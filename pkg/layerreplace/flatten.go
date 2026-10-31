package layerreplace

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/project-copacetic/copacetic/pkg/layersplit"
)

const (
	whiteoutPrefix = ".wh."
	whiteoutOpaque = ".wh..wh..opq"

	maxReportedDiffs = 20
)

// flattener applies image layers in order with overlay semantics and keeps
// the resulting tree of comparison entries.
type flattener struct {
	tree map[string]layersplit.Entry
}

func newFlattener() *flattener {
	return &flattener{tree: make(map[string]layersplit.Entry)}
}

func (f *flattener) removeTree(p string, keep map[string]bool) {
	prefix := p + "/"
	for q := range f.tree {
		if (q == p || strings.HasPrefix(q, prefix)) && !keep[q] {
			delete(f.tree, q)
		}
	}
}

// apply applies one uncompressed layer tar stream.
func (f *flattener) apply(r io.Reader) error {
	tr := tar.NewReader(r)
	added := make(map[string]bool)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		p := cleanTarPath(h.Name)
		if p == "/" {
			continue
		}

		dir, base := path.Split(p)
		dir = path.Clean(dir)
		switch {
		case base == whiteoutOpaque:
			for q := range f.tree {
				if strings.HasPrefix(q, strings.TrimSuffix(dir, "/")+"/") && !added[q] {
					delete(f.tree, q)
				}
			}
			continue
		case strings.HasPrefix(base, whiteoutPrefix):
			f.removeTree(path.Join(dir, strings.TrimPrefix(base, whiteoutPrefix)), added)
			continue
		}

		var e layersplit.Entry
		switch h.Typeflag {
		case tar.TypeLink:
			target := cleanTarPath(h.Linkname)
			te, ok := f.tree[target]
			if !ok {
				return fmt.Errorf("hardlink %s points to missing %s", p, target)
			}
			e = te
		case tar.TypeReg:
			sum := sha256.New()
			//nolint:gosec // G110: hashing streams the layer; nothing is held in memory or written to disk.
			if _, err := io.Copy(sum, tr); err != nil {
				return fmt.Errorf("reading %s: %w", p, err)
			}
			if e, err = layersplit.EntryFromTar(h, hex.EncodeToString(sum.Sum(nil))); err != nil {
				return err
			}
		default:
			if e, err = layersplit.EntryFromTar(h, ""); err != nil {
				return err
			}
		}

		// A non-directory replaces a directory and everything below it.
		if old, ok := f.tree[p]; ok && old.Type != e.Type {
			f.removeTree(p, added)
		}
		f.tree[p] = e
		added[p] = true
	}
}

// verifyTree compares the flattened image with the expected root filesystem.
func verifyTree(expected, actual map[string]layersplit.Entry) error {
	diffs := layersplit.Compare(expected, actual)
	if len(diffs) == 0 {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "verification failed: the flattened patched image differs from the upgraded root filesystem in %d paths:", len(diffs))
	for i, d := range diffs {
		if i == maxReportedDiffs {
			fmt.Fprintf(&b, "\n  ... and %d more", len(diffs)-maxReportedDiffs)
			break
		}
		b.WriteString("\n  " + d.String())
	}
	return errors.New(b.String())
}
