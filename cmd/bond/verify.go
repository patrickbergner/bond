package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/patrickbergner/bond/internal/backup"
	"github.com/patrickbergner/bond/internal/container"
	"github.com/patrickbergner/bond/internal/crypto"
	"github.com/patrickbergner/bond/internal/format"
	"github.com/patrickbergner/bond/internal/ui"
)

func runVerify(args []string) error {
	fs := newFlagSet("verify")
	var (
		quick bool
		keys  keyFlags
	)
	fs.BoolVar(&quick, "quick", false, "")
	keys.register(fs)
	keys.registerShorthand(fs)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `usage: bond verify <container.bond>

Checks a container for damage. Every shard is authenticated and the compressed
stream is re-hashed against what the manifest recorded.

Exits 1 unless the container is fully healthy. That includes a payload that
is whole in a container that has lost one of its two copies of a header, a
key-slot table or the manifest: "bond repair" puts the copy back.

options:
      --quick   check only the checksum file next to the container.
                Needs no key, so it is the check to run right after an upload
                or a download. With --expect-writer it checks the writer's
                signature and every volume's signed payload digest instead,
                which a substituted container cannot pass.
%s
`, keyFlagHelp)
	}
	operands, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return badUsage("verify needs exactly one container to check")
	}
	path := operands[0]

	if quick {
		if keys.expectWriter != "" {
			return signedQuickVerify(path, keys.expectWriter)
		}
		return quickVerify(path)
	}

	r, err := openContainer(path, &keys)
	if err != nil {
		return err
	}
	defer r.Close()

	sb := r.Superblock()
	fmt.Printf("%s\n", path)
	fmt.Printf("  header      %s\n", r.HeaderSource())
	fmt.Printf("  shards      %s of %s\n", ui.Count(int(sb.DataShardCount)), ui.Bytes(int64(sb.ShardSize)))
	fmt.Printf("  recovery    %s\n", sb.Plan())
	for _, notice := range r.Notices() {
		fmt.Printf("  damaged     %s\n", notice)
	}

	progress := ui.NewProgress(os.Stderr)
	started := time.Now()
	report, err := r.Verify(func(shard, total uint64) { progress.Add(int64(sb.ShardSize)) })
	progress.Clear()
	if err != nil {
		return err
	}

	if report.Damaged() {
		if len(report.DamagedShards) > 0 {
			fmt.Printf("  damaged     %s: %v\n",
				ui.Items(len(report.DamagedShards), "data shard", "data shards"), summarise(report.DamagedShards))
		}
		if len(report.DamagedParity) > 0 {
			fmt.Printf("  damaged     %s\n", ui.Items(len(report.DamagedParity), "parity shard", "parity shards"))
		}
		switch {
		case sb.Parity == format.ParityNone:
			return fmt.Errorf("this container carries no recovery data, so the damage cannot be repaired; restore from another copy")
		case report.Repairable:
			fmt.Printf("  repairable  yes – run: bond repair %s\n", path)
			return fmt.Errorf("the container is damaged but can be rebuilt from its recovery data")
		default:
			fmt.Printf("  repairable  no – %s lost more shards than the parity covers\n",
				ui.Items(len(report.Unrepairable), "stripe", "stripes"))
			return fmt.Errorf("the damage is beyond what this container's recovery data covers; restore from another copy")
		}
	}
	if !report.StreamMatches {
		return fmt.Errorf("every shard authenticates, but the compressed stream hashes to %s and the manifest says %s",
			short(report.StreamSHA256), short(r.Manifest().StreamSHA256))
	}

	fmt.Printf("  checked     %s in %s\n", ui.Bytes(int64(sb.PayloadBytes())), time.Since(started).Round(time.Millisecond))

	// A container that opened on its last copy of something has not passed. The
	// payload is whole, but the next flip in that region is the one that loses
	// it, and a scheduled check that exits 0 here is a check nobody hears from
	// until then.
	if len(r.Notices()) > 0 {
		fmt.Printf("  payload     every shard authenticates and the stream matches its digest\n")
		fmt.Printf("  repairable  yes – run: bond repair %s\n", path)
		return fmt.Errorf("the payload is intact, but the container has lost a copy of its metadata and is one more fault from being unreadable")
	}
	fmt.Printf("  OK          every shard authenticates and the stream matches its digest\n")
	return nil
}

// quickVerify checks every volume of a container against its checksum file.
//
// The set is found by name rather than by reading any header, so this still
// works on a container too damaged to open – which is the case it exists for.
// A split set is checked file by file because that is how it is stored and
// uploaded: one digest over the whole thing would name no volume when it failed.
func quickVerify(path string) error {
	volumes, err := volumeFiles(path)
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", path)
	for _, p := range volumes {
		algorithm, err := backup.CheckSidecar(p)
		if err != nil {
			return err
		}
		name := filepath.Base(p)
		if len(volumes) == 1 {
			name = "the container"
		}
		fmt.Printf("  %-24s %s matches its %s checksum file\n", name, ui.Bytes(fileSize(p)), algorithm)
	}
	return nil
}

// signedQuickVerify checks a container against its writer's public key, and
// against the checksum files when they are there. It needs no decryption key.
func signedQuickVerify(path, expect string) error {
	pub, err := loadWriterPublic(expect)
	if err != nil {
		return badUsage("--expect-writer: %v", err)
	}
	rep, err := container.VerifySigned(path, pub)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", path)
	fmt.Printf("  writer      %s – every volume header is signed by it\n", shortID(pub.Fingerprint()))
	for _, notice := range rep.Notices {
		fmt.Printf("  damaged     %s\n", notice)
	}
	var total int64
	for _, p := range rep.Paths {
		total += fileSize(p)
		if backup.SidecarAlgorithm(p) != "" {
			if _, err := backup.CheckSidecar(p); err != nil {
				return err
			}
		}
	}
	fmt.Printf("  payload     %s in %s matches what the writer signed\n", ui.Bytes(total), ui.Items(len(rep.Paths), "file", "files"))
	if len(rep.Notices) > 0 {
		fmt.Printf("  repairable  yes – run: bond repair %s\n", path)
		return fmt.Errorf("the container is what its writer signed, but has lost a copy of its metadata")
	}
	fmt.Printf("  OK          signed by the expected writer and unchanged since\n")
	return nil
}

// volumeFiles lists the files a container is stored in, without opening any of
// them as a container.
func volumeFiles(path string) ([]string, error) {
	return container.VolumeFiles(path)
}

func runInspect(args []string) error {
	fs := newFlagSet("inspect")
	var keys keyFlags
	keys.register(fs)
	keys.registerShorthand(fs)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `usage: bond inspect <container.bond>

Shows a container's format and settings. What can be read without a key is
shown first and marked as unverified; the rest needs one.

options:
%s
`, keyFlagHelp)
	}
	operands, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 {
		return badUsage("inspect needs exactly one container to read")
	}

	r, err := container.Open(operands[0])
	if err != nil {
		return err
	}
	defer r.Close()

	sb := r.Superblock()
	fmt.Printf("%s\n\n", operands[0])
	fmt.Printf("without a key – read from the header, not yet authenticated\n")
	fmt.Printf("  format            BOND %d.%d\n", sb.VersionMajor, sb.VersionMinor)
	fmt.Printf("  container         %x\n", sb.ContainerUUID)
	fmt.Printf("  created           %s\n", sb.Created.Format(time.RFC3339))
	fmt.Printf("  cipher            %s\n", sb.Cipher)
	fmt.Printf("  header copy       %s\n", r.HeaderSource())
	fmt.Printf("  shard size        %s\n", ui.Bytes(int64(sb.ShardSize)))
	fmt.Printf("  shards            %s\n", ui.Count(int(sb.DataShardCount)))
	fmt.Printf("  payload           %s\n", ui.Bytes(int64(sb.PayloadBytes())))
	fmt.Printf("  recovery data     %s\n", sb.Plan())
	fmt.Printf("  volumes           %s\n", ui.Items(r.Volumes(), "file", "files"))
	if id := r.Signer(); id != nil {
		fmt.Printf("  signed by         writer %s (Ed25519 + ML-DSA-65; check with --expect-writer)\n", shortID(id))
	} else {
		fmt.Printf("  signed by         nobody\n")
	}

	fmt.Printf("  key slots         %d\n", len(r.Slots()))
	for _, s := range r.Slots() {
		label := s.DisplayLabel()
		if label != "" {
			label = "  " + label
		}
		switch s.Type {
		case crypto.SlotPassphrase:
			fmt.Printf("    passphrase      argon2id, %s memory, %d passes, %d lanes%s\n",
				ui.Bytes(int64(s.KDF.MemoryKiB)*1024), s.KDF.Iterations, s.KDF.Parallelism, label)
		default:
			fmt.Printf("    %-15s%s\n", s.Type, label)
		}
	}
	// The slots decide this, not the header flag. A NONE container whose
	// plaintext slot was later removed still carries the flag – the header is
	// never rewritten by a key change – and saying "the key is stored in this
	// container" about one that no longer stores it is the worst direction to
	// be wrong in. The flag is reported only where it contradicts the slots.
	plaintext := r.HasPlaintextSlot()
	if plaintext {
		fmt.Printf("\n  encryption        NONE – the key is stored in this container.\n")
		fmt.Printf("                    Tags detect corruption, but provide no authenticity against an attacker.\n")
	}
	switch flagged := sb.Flags&format.FlagUnencrypted != 0; {
	case flagged && !plaintext:
		fmt.Printf("\n  encryption        the header still carries the unencrypted flag from when this\n")
		fmt.Printf("                    container was written; its plaintext slot has since been removed,\n")
		fmt.Printf("                    so the slots above are what actually opens it. \"bond rekey\" writes\n")
		fmt.Printf("                    a fresh container whose header matches its keys.\n")
	case !flagged && plaintext:
		fmt.Printf("                    The header does not carry the unencrypted flag. Believe the slot.\n")
	}

	secrets, err := keys.unlockersFor(r.Slots())
	if err != nil {
		fmt.Printf("\nwith a key\n  not shown: %v\n", err)
		return nil
	}
	defer wipeUnlockers(secrets)
	if keys.allowExpensiveKDF {
		fmt.Fprintln(os.Stderr, "warning: --allow-expensive-kdf permits unauthenticated container data to request extreme memory or CPU")
	}
	opts, err := keys.unlockOptions()
	if err != nil {
		return err
	}
	if err := r.UnlockWithOptions(opts, secrets...); err != nil {
		return err
	}
	if r.WriterChecked() {
		fmt.Printf("  writer            %s – the signature verifies\n", shortID(r.Signer()))
	}

	m := r.Manifest()
	fmt.Printf("\nwith the key – authenticated\n")
	for _, notice := range r.Notices() {
		fmt.Printf("  damage            %s\n", notice)
	}
	if m.TargetID != "" {
		fmt.Printf("  target            %s\n", m.TargetID)
	}
	fmt.Printf("  compression       %s", m.Compression.Format)
	if m.Compression.Format != "none" {
		fmt.Printf(", level %d", m.Compression.Level)
	}
	fmt.Println()
	fmt.Printf("  contents          %s, %s, %s\n",
		ui.Items(m.Files, "file", "files"), ui.Items(m.Dirs, "directory", "directories"), ui.Bytes(m.Bytes))
	if m.SkippedSymlinks > 0 {
		fmt.Printf("  symlinks skipped  %s\n", ui.Items(m.SkippedSymlinks, "symlink", "symlinks"))
	}
	fmt.Printf("  compressed to     %s\n", ui.Bytes(m.StreamLength))
	fmt.Printf("  file index        %s\n", indexState(m))
	return nil
}

func indexState(m *format.Manifest) string {
	if len(m.Index) == 0 {
		return "not stored"
	}
	return fmt.Sprintf("%s recorded", ui.Items(len(m.Index), "entry", "entries"))
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func short(hash string) string {
	if len(hash) > 16 {
		return hash[:16] + "…"
	}
	return hash
}

// summarise keeps a long list of damaged shards readable.
func summarise(shards []uint64) string {
	const show = 8
	if len(shards) <= show {
		return fmt.Sprint(shards)
	}
	return fmt.Sprintf("%v and %d more", shards[:show], len(shards)-show)
}
