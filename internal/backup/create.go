// Package backup joins the pieces up: enumeration, tar, compression,
// encryption and the container, in one streaming pass each way.
package backup

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/patrickbergner/bond/internal/archive"
	"github.com/patrickbergner/bond/internal/config"
	"github.com/patrickbergner/bond/internal/container"
	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/format"
	"github.com/patrickbergner/bond/internal/parity"
	"github.com/patrickbergner/bond/internal/sevenzip"
	"github.com/patrickbergner/bond/internal/source"
)

// CreateOptions describe one container to build.
type CreateOptions struct {
	Target   *config.Target
	Settings config.Resolved
	Keys     []container.KeySpec

	// Unencrypted mirrors the settings' encryptionMethod NONE, and is what
	// puts the advisory flag in the header.
	Unencrypted bool

	WorkDir    string
	OutputPath string
	Tool       *sevenzip.Tool

	OnEntry   func(archive.Entry)
	OnWarning func(path, msg string)
	OnProblem func(path string, err error) error
}

// CreateResult reports what was written.
type CreateResult struct {
	Path        string
	Stats       source.Stats
	StreamBytes int64
	Size        int64
	VolumePaths []string
	ShardSize   int64
	Shards      int64
	Elapsed     time.Duration
	Sidecars    []string
	SidecarPath string
	Manifest    *format.Manifest
}

// Volumes is how many files the container was written to.
func (r *CreateResult) Volumes() int { return len(r.VolumePaths) }

// Ratio is the compressed size against the content that went in.
func (r *CreateResult) Ratio() float64 {
	if r.Stats.Bytes == 0 {
		return 0
	}
	return float64(r.Size) / float64(r.Stats.Bytes)
}

// Create builds one container.
//
// The whole pipeline is one pass with nothing buffered to disk: files are
// walked into a tar, the tar goes through 7-Zip's xz encoder, the compressed
// bytes are sealed into shards as they arrive, and the header is patched at
// the end. A backup of a terabyte therefore needs a terabyte of destination
// and nothing else.
func Create(ctx context.Context, opts CreateOptions) (*CreateResult, error) {
	started := time.Now()

	specs, layout, err := source.Prepare(opts.Target)
	if err != nil {
		return nil, err
	}
	plan, err := parity.For(opts.Settings.RecoveryPercent)
	if err != nil {
		return nil, err
	}
	shardSize, err := shardSizeFor(opts, specs, plan)
	if err != nil {
		return nil, err
	}

	work := filepath.Join(opts.WorkDir, filepath.Base(opts.OutputPath)+".partial")
	w, err := container.Create(work, container.Options{
		ShardSize:       shardSize,
		Keys:            opts.Keys,
		Unencrypted:     opts.Unencrypted,
		RecoveryPercent: opts.Settings.RecoveryPercent,
		MaxVolumeBytes:  opts.Settings.MaxVolumeBytes,
	})
	if err != nil {
		return nil, err
	}
	// Anything that goes wrong from here leaves no trace: the partial file is
	// removed and the destination is never touched.
	finished := false
	defer func() {
		if !finished {
			w.Abort()
		}
	}()

	// The compressor is optional. At level 0 the tar goes straight into the
	// container, which is the right thing for trees of video or music where
	// LZMA2 would burn hours to save nothing.
	var (
		sink       io.Writer = w
		compressor io.WriteCloser
	)
	if opts.Settings.CompressionLevel > 0 {
		if opts.Tool == nil {
			return nil, fmt.Errorf("compression was asked for but no 7-Zip is available")
		}
		compressor, err = opts.Tool.XZWriter(ctx, w, sevenzip.Options{Level: opts.Settings.CompressionLevel})
		if err != nil {
			return nil, err
		}
		sink = compressor
	}

	tw := archive.NewWriter(sink)
	tw.OnWarning = opts.OnWarning

	walker := &source.Walker{
		FollowSymlinks: opts.Settings.FollowSymlinks,
		OnProblem:      opts.OnProblem,
	}
	stats, err := walker.Walk(specs, func(e source.Entry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		entry := archive.Entry{
			Path:    e.Archive,
			Disk:    e.Abs,
			Kind:    archiveKind(e.Kind),
			Size:    e.Size,
			Mode:    e.Mode,
			ModTime: e.ModTime,
			Link:    e.Link,
		}
		if opts.OnEntry != nil {
			opts.OnEntry(entry)
		}
		return tw.Add(entry)
	})
	if err != nil {
		return nil, err
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("finishing the archive: %w", err)
	}
	if compressor != nil {
		if err := compressor.Close(); err != nil {
			return nil, fmt.Errorf("finishing compression: %w", err)
		}
	}

	m := buildManifest(opts, layout, stats, tw)
	if err := w.Finish(m); err != nil {
		return nil, fmt.Errorf("completing the container: %w", err)
	}
	paths, err := w.Publish(opts.OutputPath)
	if err != nil {
		return nil, fmt.Errorf("publishing the container: %w", err)
	}
	finished = true

	// The published file stays where it is if this fails. It may be the only
	// copy of the data, and deleting it on the strength of a self-check would
	// be a worse bug than the one being reported.
	if err := confirmReadable(paths[0], opts.Keys); err != nil {
		return nil, err
	}

	var total int64
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		total += info.Size()
	}

	result := &CreateResult{
		Path:        opts.OutputPath,
		ShardSize:   shardSize,
		Shards:      m.DataShardCount,
		Stats:       stats,
		StreamBytes: m.StreamLength,
		Size:        total,
		VolumePaths: paths,
		Elapsed:     time.Since(started),
		Manifest:    m,
	}

	if opts.Settings.HashAlgorithm != config.HashNone {
		// Every volume gets its own checksum file: they are uploaded and
		// checked one at a time, so one digest over the set would be no use.
		for _, p := range paths {
			sidecar, err := WriteSidecar(p, opts.Settings.HashAlgorithm)
			if err != nil {
				return result, fmt.Errorf("writing the checksum file: %w", err)
			}
			result.Sidecars = append(result.Sidecars, sidecar)
		}
		result.SidecarPath = result.Sidecars[0]
	}
	return result, nil
}

// confirmReadable opens the container that was just written and unlocks it.
//
// Nothing else does. Publish renames a file into place and the run reports
// success on the strength of the writer not having returned an error, which is
// exactly how a container that no tool could open was once written, checksummed
// and reported as a finished backup. The bug that did it lived in the header
// bounds check and only ever fired for one shape of container, so no round-trip
// test caught it – but any re-open would have.
//
// This is deliberately not a full verification: it parses the headers, assembles
// the volume set, checks every volume's MAC, the key commitment, the manifest
// and the cross-check between them, and stops. The payload is not read back,
// because doubling the I/O of every backup to re-check bytes that were sealed a
// moment ago is what "bond verify" is for.
//
// A recipient-only container has no secret on this machine by design, so there
// it goes as far as opening and stops, which still exercises everything the
// header and volume set have to get right.
func confirmReadable(path string, keys []container.KeySpec) error {
	r, err := container.Open(path)
	if err != nil {
		return fmt.Errorf("the container was written but cannot be opened again; this is a bug in bond: %w", err)
	}
	defer r.Close()

	var secrets []crypto.Unlocker
	for _, k := range keys {
		if k.Secret != nil {
			secrets = append(secrets, k.Secret)
		}
	}
	if len(secrets) == 0 {
		return nil
	}
	if err := r.Unlock(secrets...); err != nil {
		return fmt.Errorf("the container was written but does not unlock with the key that made it; this is a bug in bond: %w", err)
	}
	return nil
}

// shardSizeFor picks the shard size, treating the configured value as a
// maximum rather than a fixed choice.
//
// A stripe cannot be narrower than one shard, so a payload smaller than
// k shards cannot reach the requested recovery percentage: at the extreme, a
// 3 MiB backup in 4 MiB shards is one data shard and one parity shard, which
// is 100% overhead for a container that asked for 10%. Sizing the shards to
// the payload fixes that, and costs one metadata-only pass over the tree –
// nothing next to what compressing it will take.
//
// Without parity there is no stripe to fill and the configured size stands.
func shardSizeFor(opts CreateOptions, specs []source.Spec, plan parity.Plan) (int64, error) {
	configured := opts.Settings.ShardBytes
	if !plan.Enabled() {
		return configured, nil
	}

	// Errors are ignored here: this walk only estimates, and the real one
	// still applies the caller's policy about what an unreadable path means.
	var estimate int64
	walker := &source.Walker{
		FollowSymlinks: opts.Settings.FollowSymlinks,
		OnProblem:      func(string, error) error { return nil },
	}
	stats, err := walker.Walk(specs, func(source.Entry) error { return nil })
	if err == nil {
		estimate = stats.Bytes
	}

	const minShard = 64 << 10
	want := (estimate/int64(plan.Data) + 4095) / 4096 * 4096
	return max(minShard, min(configured, want)), nil
}

// archiveKind translates between the two packages' entry kinds. They happen to
// use the same order, but writing it out means a new kind in one of them
// cannot silently become the wrong kind in the other.
func archiveKind(k source.Kind) archive.Kind {
	switch k {
	case source.KindDir:
		return archive.KindDir
	case source.KindSymlink:
		return archive.KindSymlink
	default:
		return archive.KindFile
	}
}

func buildManifest(opts CreateOptions, layout *source.Layout, stats source.Stats, tw *archive.Writer) *format.Manifest {
	m := &format.Manifest{
		TargetID:       opts.Target.ID,
		Tool:           "bond",
		ArchiveRoot:    layout.Root,
		SyntheticRoots: layout.Synthetic,
		FollowSymlinks: opts.Settings.FollowSymlinks,
		Files:          stats.Files,
		Dirs:           stats.Dirs,
		Symlinks:       stats.Symlinks,
		Bytes:          stats.Bytes,
		Compression: format.Compression{
			Format: "none",
			Level:  opts.Settings.CompressionLevel,
			Solid:  true,
		},
	}
	if opts.Settings.CompressionLevel > 0 {
		m.Compression.Format = "xz"
	}
	if opts.Settings.StoreFileIndex {
		m.Index = tw.Index()
	}
	return m
}

// WriteSidecar writes a checksum next to the container in the format the
// standard sha256sum and sha384sum tools read, so a copy in cloud storage can
// be checked with nothing but a shell.
func WriteSidecar(path, algorithm string) (string, error) {
	var (
		h   hash.Hash
		ext string
	)
	switch algorithm {
	case config.HashSHA256:
		h, ext = sha256.New(), ".sha256"
	case config.HashSHA384:
		h, ext = sha512.New384(), ".sha384"
	case config.HashSHA512:
		h, ext = sha512.New(), ".sha512"
	default:
		return "", fmt.Errorf("unknown hash algorithm %q", algorithm)
	}

	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	sidecar := path + ext
	line := fmt.Sprintf("%s  %s\n", hex.EncodeToString(h.Sum(nil)), filepath.Base(path))
	if err := os.WriteFile(sidecar, []byte(line), 0o644); err != nil {
		return "", err
	}
	return sidecar, nil
}

// CheckSidecar re-hashes a container and compares it with its checksum file.
// It needs no key, which makes it the check to run straight after an upload or
// a download.
func CheckSidecar(path string) (string, error) {
	for _, c := range []struct {
		ext string
		alg string
	}{
		{".sha256", config.HashSHA256},
		{".sha384", config.HashSHA384},
		{".sha512", config.HashSHA512},
	} {
		data, err := os.ReadFile(path + c.ext)
		if err != nil {
			continue
		}
		want, _, _ := strings.Cut(strings.TrimSpace(string(data)), " ")

		got, err := hashFile(path, c.alg)
		if err != nil {
			return "", err
		}
		if got != want {
			return "", fmt.Errorf("%s does not match %s\n  recorded %s\n  actual   %s",
				filepath.Base(path), filepath.Base(path+c.ext), want, got)
		}
		return c.alg, nil
	}
	return "", fmt.Errorf("no checksum file next to %s", filepath.Base(path))
}

func hashFile(path, algorithm string) (string, error) {
	var h hash.Hash
	switch algorithm {
	case config.HashSHA256:
		h = sha256.New()
	case config.HashSHA384:
		h = sha512.New384()
	case config.HashSHA512:
		h = sha512.New()
	default:
		return "", fmt.Errorf("unknown hash algorithm %q", algorithm)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
