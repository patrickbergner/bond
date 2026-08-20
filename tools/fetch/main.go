// Command fetch downloads the third-party tools that get embedded into the bond
// executables, one binary per target platform.
//
// They are deliberately not committed. Version stability comes from
// tools/manifest.json instead: a pinned release, pinned URLs and a pinned
// SHA-256 for every package, every extracted binary and every licence. Nothing
// lands in the source tree that does not hash to the recorded value, so a mirror
// serving something else, or a truncated download, fails the build rather than
// ending up inside a backup tool.
//
// 7-Zip is the only tool here today, but nothing below knows that: a tool is an
// entry in the manifest with its own version, its own destination directory and
// its own packages.
//
//	go run ./tools/fetch                  # fetch whatever is missing or stale
//	go run ./tools/fetch --check          # verify only, no downloads
//	go run ./tools/fetch --force          # re-download everything
//	go run ./tools/fetch --update-hashes  # re-record hashes after a version bump
package main

import (
	"crypto/sha256"
	"debug/macho"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type manifest struct {
	Tools map[string]*tool `json:"tools"`
}

type tool struct {
	Version string `json:"version"`
	// BinDir is where this tool's binaries are installed, relative to the
	// repository root. It is the package that embeds them that decides.
	BinDir   string          `json:"binDir"`
	Packages map[string]*pkg `json:"packages"`
	Binaries []*binary       `json:"binaries"`
}

type pkg struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	// Bare marks a download that is the tool itself rather than an archive:
	// it is installed by copying, and the binary's member is ignored. Common
	// for Windows tools published as a plain .exe.
	Bare bool `json:"bare,omitempty"`
}

type binary struct {
	Target     string `json:"target"`
	File       string `json:"file"`
	Package    string `json:"package"`
	Member     string `json:"member"`
	MachOSlice string `json:"machoSlice,omitempty"`
	SHA256     string `json:"sha256"`
	// License names the licence text inside this binary's own package, so a
	// binary and the terms it ships under always come out of the same
	// download. It is installed next to the others as <File>.txt.
	License       string `json:"license,omitempty"`
	LicenseSHA256 string `json:"licenseSha256,omitempty"`
}

const (
	manifestPath = "tools/manifest.json"
	licenseDir   = "tools/licenses"
	cacheDir     = "tools/download-cache"
)

func main() {
	var (
		check    bool
		force    bool
		update   bool
		rootPath string
	)
	flag.BoolVar(&check, "check", false, "verify the installed binaries and exit without downloading")
	flag.BoolVar(&force, "force", false, "download again even when the cache is valid")
	flag.BoolVar(&update, "update-hashes", false, "record the hashes actually seen, for a version bump")
	flag.StringVar(&rootPath, "root", "", "repository root (default: the directory holding go.mod)")
	flag.Parse()

	if err := run(rootPath, check, force, update); err != nil {
		fmt.Fprintf(os.Stderr, "fetch: %v\n", err)
		os.Exit(1)
	}
}

func run(rootPath string, check, force, update bool) error {
	root, err := findRoot(rootPath)
	if err != nil {
		return err
	}

	m, err := loadManifest(filepath.Join(root, manifestPath))
	if err != nil {
		return err
	}

	if check {
		return verifyInstalled(root, m)
	}
	if !force && !update {
		if err := verifyInstalled(root, m); err == nil {
			for _, name := range toolNames(m) {
				t := m.Tools[name]
				fmt.Printf("%s %s: all %d binaries present and verified\n", name, t.Version, len(t.Binaries))
			}
			return nil
		}
	}

	f := &fetcher{root: root, m: m, force: force, update: update}
	return f.fetch()
}

type fetcher struct {
	root   string
	m      *manifest
	force  bool
	update bool
}

func (f *fetcher) fetch() error {
	if err := os.MkdirAll(filepath.Join(f.root, cacheDir), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(f.root, licenseDir), 0o755); err != nil {
		return err
	}

	for _, name := range toolNames(f.m) {
		if err := f.fetchTool(name, f.m.Tools[name]); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}

	if f.update {
		if err := saveManifest(filepath.Join(f.root, manifestPath), f.m); err != nil {
			return err
		}
		fmt.Printf("recorded hashes in %s – review the diff before committing\n", manifestPath)
	}
	return nil
}

func (f *fetcher) fetchTool(name string, t *tool) error {
	if t.BinDir == "" {
		return errors.New("no binDir; the manifest must say where this tool's binaries are installed")
	}
	if err := os.MkdirAll(filepath.Join(f.root, t.BinDir), 0o755); err != nil {
		return err
	}

	// Download every package first, so a bad mirror fails before anything is
	// written into the source tree.
	for pkgName, p := range t.Packages {
		if _, err := f.packagePath(pkgName, p); err != nil {
			return err
		}
	}

	// Packages this host's tar can open come first: where it cannot (GNU tar
	// has no 7-Zip reader), the fallback in extract needs a binary this very
	// run has already installed.
	for pass := 0; pass < 2; pass++ {
		for _, b := range t.Binaries {
			p := t.Packages[b.Package]
			if p == nil {
				return fmt.Errorf("%s: no package named %q", b.File, b.Package)
			}
			if (pass == 0) == needsInstalledTool(p) {
				continue
			}
			if err := f.install(t, b, p); err != nil {
				return fmt.Errorf("%s: %w", b.File, err)
			}
		}
	}

	fmt.Printf("%s %s: %d binaries installed in %s\n", name, t.Version, len(t.Binaries), t.BinDir)
	return nil
}

// needsInstalledTool reports whether opening this package may require a binary
// the fetcher installs itself. Only .7z is in that position, and only on hosts
// whose tar is GNU tar; ordering by it costs nothing where tar copes.
func needsInstalledTool(p *pkg) bool {
	return strings.HasSuffix(p.URL, ".7z")
}

func (f *fetcher) install(t *tool, b *binary, p *pkg) error {
	data, err := f.member(t, p, b.Package, b.Member)
	if err != nil {
		return err
	}

	if b.MachOSlice != "" {
		data, err = machoSlice(data, b.MachOSlice)
		if err != nil {
			return err
		}
	}

	sum := hashOf(data)
	switch {
	case f.update:
		b.SHA256 = sum
	case b.SHA256 == "":
		return fmt.Errorf("no sha256 recorded; run with --update-hashes to pin the current release")
	case b.SHA256 != sum:
		return fmt.Errorf("sha256 mismatch\n  want %s\n  got  %s\nthe pinned release changed under us; do not install this", b.SHA256, sum)
	}

	if err := os.WriteFile(filepath.Join(f.root, t.BinDir, b.File), data, 0o755); err != nil {
		return err
	}
	fmt.Printf("  %-22s %-14s %s\n", b.File, b.Target, shortHash(sum))

	return f.installLicense(t, b, p)
}

// installLicense writes the terms this binary ships under, taken from the same
// download the binary came from and named after it, so the pairing survives a
// tool whose packages do not all carry the same licence.
func (f *fetcher) installLicense(t *tool, b *binary, p *pkg) error {
	if b.License == "" {
		return nil
	}
	data, err := f.member(t, p, b.Package, b.License)
	if err != nil {
		return fmt.Errorf("license: %w", err)
	}

	sum := hashOf(data)
	switch {
	case f.update:
		b.LicenseSHA256 = sum
	case b.LicenseSHA256 == "":
		return fmt.Errorf("license: no sha256 recorded; run with --update-hashes to pin the current release")
	case b.LicenseSHA256 != sum:
		return fmt.Errorf("license: sha256 mismatch\n  want %s\n  got  %s\nthe terms changed with the release; read them before re-pinning", b.LicenseSHA256, sum)
	}

	return os.WriteFile(licensePath(f.root, b), data, 0o644)
}

func licensePath(root string, b *binary) string {
	return filepath.Join(root, licenseDir, b.File+".txt")
}

// member pulls one file out of a package and returns its bytes.
func (f *fetcher) member(t *tool, p *pkg, pkgName, name string) ([]byte, error) {
	src, err := f.packagePath(pkgName, p)
	if err != nil {
		return nil, err
	}
	if p.Bare {
		return os.ReadFile(src)
	}

	tmp, err := os.MkdirTemp(filepath.Join(f.root, cacheDir), "unpack-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	if err := f.extract(t, src, p, name, tmp); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(tmp, filepath.FromSlash(name)))
	if err != nil {
		return nil, fmt.Errorf("%s was not in %s: %w", name, filepath.Base(src), err)
	}
	return data, nil
}

// extract pulls one member out of a package into dir, keeping its path.
//
// tar does the work for every format. The bsdtar Windows has shipped since
// Windows 10 and the one macOS ships are libarchive, which reads .7z and .zip
// as readily as .tar.xz, so a pinned tool needs no unpacker of its own – and
// bond no longer downloads 7zr just to open the Windows package.
func (f *fetcher) extract(t *tool, src string, p *pkg, member, dir string) error {
	// Every path is passed relative to the cache directory: a Windows path
	// reaching a tar built for MSYS is read as a remote host:path and then
	// mangled by its path translation. Both bsdtar and GNU tar detect the
	// compression from the stream, so no -J is needed either.
	rel, err := filepath.Rel(filepath.Dir(src), dir)
	if err != nil {
		return err
	}
	cmd := exec.Command(tarCommand(), "-xf", filepath.Base(src), "-C", filepath.ToSlash(rel), member)
	cmd.Dir = filepath.Dir(src)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	if !needsInstalledTool(p) {
		return fmt.Errorf("tar: %w\n%s\n(a tar with xz support is needed; Windows 10 and later ship one)", err, out)
	}

	// GNU tar, then: it has no 7-Zip reader. The tool that provides 7-Zip is
	// in this manifest, and pass 0 has already installed the copy that runs
	// here. A future tool in some other exotic format would add its branch
	// alongside this one.
	tool7z, err7z := f.installedForHost(t)
	if err7z != nil {
		return fmt.Errorf("tar cannot open %s: %v\n%s\n%w", filepath.Base(src), err, out, err7z)
	}
	cmd = exec.Command(tool7z, "x", "-y", "-bso0", "-bsp0", "-o"+dir, src, member)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w\n%s", filepath.Base(tool7z), err, out)
	}
	return nil
}

// installedForHost returns this tool's binary for the machine we are running
// on, which is only useful once it has been installed.
func (f *fetcher) installedForHost(t *tool) (string, error) {
	want := fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
	for _, b := range t.Binaries {
		if b.Target != want {
			continue
		}
		path := filepath.Join(f.root, t.BinDir, b.File)
		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("and %s, which could open it, is not installed yet", b.File)
		}
		return path, nil
	}
	return "", fmt.Errorf("and no binary is pinned for this host (%s) to open it with", want)
}

// tarCommand prefers the tar Windows itself ships – bsdtar with liblzma, which
// speaks native Windows paths. A tar from an MSYS environment earlier on PATH
// would rewrite them.
func tarCommand() string {
	if runtime.GOOS == "windows" {
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		if p := filepath.Join(root, "system32", "tar.exe"); fileExists(p) {
			return p
		}
	}
	return "tar"
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// packagePath returns the cached download, fetching it when needed. The cache
// is keyed by file name and validated by hash, so a partial download is never
// mistaken for a complete one.
func (f *fetcher) packagePath(name string, p *pkg) (string, error) {
	dst := filepath.Join(f.root, cacheDir, filepath.Base(p.URL))

	if !f.force {
		if data, err := os.ReadFile(dst); err == nil {
			sum := hashOf(data)
			switch {
			case f.update:
				p.SHA256 = sum
				return dst, nil
			case sum == p.SHA256:
				return dst, nil
			}
		}
	}

	fmt.Printf("downloading %s\n", p.URL)
	data, err := download(p.URL)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}

	sum := hashOf(data)
	switch {
	case f.update:
		p.SHA256 = sum
	case p.SHA256 == "":
		return "", fmt.Errorf("%s: no sha256 recorded; run with --update-hashes to pin the current release", name)
	case p.SHA256 != sum:
		return "", fmt.Errorf("%s: sha256 mismatch\n  want %s\n  got  %s\nrefusing to unpack it", name, p.SHA256, sum)
	}

	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return "", err
	}
	return dst, nil
}

func download(url string) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// machoSlice lifts one architecture out of a universal binary. Apple's
// universal 7zz is twice the size it needs to be for an arm64-only build, and
// a slice copied out verbatim is a valid executable – the same thing lipo
// -thin produces.
func machoSlice(data []byte, arch string) ([]byte, error) {
	want, ok := map[string]macho.Cpu{
		"arm64": macho.CpuArm64,
		"amd64": macho.CpuAmd64,
	}[arch]
	if !ok {
		return nil, fmt.Errorf("unknown macho slice %q", arch)
	}

	fat, err := macho.NewFatFile(readerAt(data))
	if err != nil {
		if errors.Is(err, macho.ErrNotFat) {
			return data, nil // already a single-architecture binary
		}
		return nil, fmt.Errorf("reading universal binary: %w", err)
	}
	for _, a := range fat.Arches {
		if a.Cpu != want {
			continue
		}
		end := int(a.Offset) + int(a.Size)
		if end > len(data) {
			return nil, fmt.Errorf("%s slice runs past the end of the file", arch)
		}
		return data[a.Offset:end], nil
	}
	return nil, fmt.Errorf("no %s slice in the universal binary", arch)
}

type readerAt []byte

func (r readerAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r)) {
		return 0, io.EOF
	}
	n := copy(p, r[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func verifyInstalled(root string, m *manifest) error {
	var missing []string
	for _, name := range toolNames(m) {
		t := m.Tools[name]
		for _, b := range t.Binaries {
			missing = append(missing, checkFile(filepath.Join(root, t.BinDir, b.File), b.File, b.SHA256)...)
			if b.License != "" {
				path := licensePath(root, b)
				missing = append(missing, checkFile(path, filepath.Base(path), b.LicenseSHA256)...)
			}
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("the fetched tools are not in place:\n  %s\nrun: go run ./tools/fetch", strings.Join(missing, "\n  "))
	}
	return nil
}

func checkFile(path, name, want string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{fmt.Sprintf("%s is missing", name)}
	}
	if sum := hashOf(data); sum != want {
		return []string{fmt.Sprintf("%s has sha256 %s, want %s", name, shortHash(sum), shortHash(want))}
	}
	return nil
}

// toolNames orders the manifest, so output and --update-hashes diffs do not
// depend on Go's map iteration.
func toolNames(m *manifest) []string {
	names := make([]string, 0, len(m.Tools))
	for name := range m.Tools {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func loadManifest(path string) (*manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(m.Tools) == 0 {
		return nil, fmt.Errorf("%s: no tools listed", path)
	}
	return &m, nil
}

func saveManifest(path string, m *manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func hashOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func shortHash(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}

// findRoot walks up from the working directory to the module root, so the
// command works from anywhere in the tree.
func findRoot(given string) (string, error) {
	if given != "" {
		return filepath.Abs(given)
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("no go.mod found; run this from inside the repository or pass --root")
		}
		dir = parent
	}
}
