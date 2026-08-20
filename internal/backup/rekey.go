package backup

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/patrickbergner/bond/internal/container"
	"github.com/patrickbergner/bond/internal/format"
)

// RekeyResult reports a completed re-encryption.
type RekeyResult struct {
	Path    string
	Size    int64
	Volumes int
	Elapsed time.Duration
}

// Rekey writes a copy of a container under a brand new master key.
//
// This is the expensive one, and the distinction matters. Adding, removing or
// changing a *key slot* rewrites 64 KiB, because every slot wraps the same
// master key. Replacing the master key itself means every shard is sealed
// again under a different key, so the whole container is written from scratch
// – hours for a large backup rather than milliseconds.
//
// It is worth doing when the master key may have been exposed, and not
// otherwise: a compromised passphrase is answered by rotating that slot.
func Rekey(ctx context.Context, r *container.Reader, dst string, keys []container.KeySpec, unencrypted bool, workDir string, maxVolumeBytes int64) (*RekeyResult, error) {
	if !r.Unlocked() {
		return nil, fmt.Errorf("the container is locked")
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("the new container needs at least one key slot")
	}

	started := time.Now()
	old := r.Manifest()
	sb := r.Superblock()

	stream, err := r.Stream()
	if err != nil {
		return nil, err
	}

	work := filepath.Join(workDir, filepath.Base(dst)+".partial")
	w, err := container.Create(work, container.Options{
		ShardSize:       int64(sb.ShardSize),
		Keys:            keys,
		Unencrypted:     unencrypted,
		RecoveryPercent: old.RecoveryPercent,
		MaxVolumeBytes:  maxVolumeBytes,
	})
	if err != nil {
		return nil, err
	}
	finished := false
	defer func() {
		if !finished {
			w.Abort()
		}
	}()

	// The payload is copied as the compressed stream it already is: nothing is
	// decompressed, re-compressed or re-archived, so the contents cannot
	// change in the process.
	if _, err := io.Copy(w, stream); err != nil {
		return nil, fmt.Errorf("copying the payload: %w", err)
	}

	// The manifest carries over unchanged apart from what the new container
	// decides for itself.
	m := *old
	m.Index = old.Index
	if err := w.Finish(&m); err != nil {
		return nil, err
	}
	paths, err := w.Publish(dst)
	if err != nil {
		return nil, err
	}
	finished = true

	if err := confirmReadable(paths[0], keys); err != nil {
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
	return &RekeyResult{Path: dst, Size: total, Volumes: len(paths), Elapsed: time.Since(started)}, nil
}

// ManifestOf exposes a container's manifest for commands that report on it.
func ManifestOf(r *container.Reader) *format.Manifest { return r.Manifest() }
