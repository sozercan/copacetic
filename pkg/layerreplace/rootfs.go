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
	"time"

	"github.com/project-copacetic/copacetic/pkg/layersplit"
)

// rootEntry is one entry of a root filesystem tar archive.
type rootEntry struct {
	path string
	hdr  *tar.Header
	// offset is the position of a regular file's content in the archive.
	offset int64
	// link is the target path of a hardlink.
	link string
	// entry is the comparison entry; for hardlinks it is the target's entry.
	entry layersplit.Entry
}

// rootFS indexes a tar archive of a root filesystem, such as one written by
// `tar --format=posix --xattrs -C ROOT .`. File contents are read back from
// the archive on demand.
type rootFS struct {
	r       io.ReaderAt
	entries []*rootEntry
	byPath  map[string]*rootEntry
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// cleanTarPath turns a tar entry name into an absolute clean path. It returns
// "/" for the root directory.
func cleanTarPath(name string) string {
	return path.Clean("/" + strings.TrimPrefix(name, "./"))
}

// indexRootFS reads the archive in r, hashing every regular file.
func indexRootFS(r io.ReaderAt, size int64) (*rootFS, error) {
	cr := &countingReader{r: io.NewSectionReader(r, 0, size)}
	tr := tar.NewReader(cr)
	fs := &rootFS{r: r, byPath: make(map[string]*rootEntry)}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading root filesystem archive: %w", err)
		}
		p := cleanTarPath(h.Name)
		if p == "/" {
			continue
		}
		if _, dup := fs.byPath[p]; dup {
			return nil, fmt.Errorf("root filesystem archive has duplicate entry %s", p)
		}
		e := &rootEntry{path: p, hdr: h, offset: cr.n}

		switch h.Typeflag {
		case tar.TypeLink:
			e.link = cleanTarPath(h.Linkname)
			target, ok := fs.byPath[e.link]
			if !ok || target.hdr.Typeflag != tar.TypeReg {
				return nil, fmt.Errorf("hardlink %s points to %s, which is not a preceding regular file", p, e.link)
			}
			e.entry = target.entry
		case tar.TypeReg:
			sum := sha256.New()
			//nolint:gosec // G110: the archive is the uncompressed root filesystem copa just built.
			if _, err := io.Copy(sum, tr); err != nil {
				return nil, fmt.Errorf("reading %s: %w", p, err)
			}
			if e.entry, err = layersplit.EntryFromTar(h, hex.EncodeToString(sum.Sum(nil))); err != nil {
				return nil, err
			}
		default:
			if e.entry, err = layersplit.EntryFromTar(h, ""); err != nil {
				return nil, err
			}
		}
		fs.entries = append(fs.entries, e)
		fs.byPath[p] = e
	}
	return fs, nil
}

// Root returns the classification view of the root filesystem.
func (fs *rootFS) Root() layersplit.Root {
	root := make(layersplit.Root, len(fs.entries))
	for _, e := range fs.entries {
		h := e.hdr
		if e.link != "" {
			h = fs.byPath[e.link].hdr
		}
		n := layersplit.Node{Type: layersplit.TypeOther}
		switch h.Typeflag {
		case tar.TypeDir:
			n.Type = layersplit.TypeDir
		case tar.TypeReg:
			n.Type = layersplit.TypeReg
			n.Size = h.Size
		case tar.TypeSymlink:
			n.Type = layersplit.TypeSymlink
			n.Link = h.Linkname
		}
		root[e.path] = n
	}
	return root
}

// Tree returns the comparison entries of the root filesystem.
func (fs *rootFS) Tree() map[string]layersplit.Entry {
	out := make(map[string]layersplit.Entry, len(fs.entries))
	for _, e := range fs.entries {
		out[e.path] = e.entry
	}
	return out
}

// layerHeader returns the header of p in a layer, copying the metadata Dalec
// keeps (type, mode, ownership, xattrs, timestamps) from src.
func layerHeader(src *tar.Header, p string) *tar.Header {
	name := strings.TrimPrefix(p, "/")
	h := &tar.Header{
		Typeflag: src.Typeflag,
		Name:     name,
		Mode:     src.Mode & 0o7777,
		Uid:      src.Uid,
		Gid:      src.Gid,
		ModTime:  src.ModTime,
		Linkname: src.Linkname,
		Devmajor: src.Devmajor,
		Devminor: src.Devminor,
		Format:   tar.FormatPAX,
	}
	switch src.Typeflag {
	case tar.TypeReg:
		h.Size = src.Size
	case tar.TypeDir:
		h.Name += "/"
	}
	for k, v := range layersplit.Xattrs(src) {
		if h.PAXRecords == nil {
			h.PAXRecords = make(map[string]string)
		}
		h.PAXRecords[layersplit.XattrPAXRecord(k)] = v
	}
	return h
}

// writeLayer writes a layer holding the entries of the root filesystem for
// which include returns true, following Dalec's Copy: parent directories are
// recreated with their metadata from the root filesystem, directory
// timestamps are set to dirMtime, and hardlinks are kept within the layer.
func (fs *rootFS) writeLayer(w io.Writer, include func(p string) bool, dirMtime time.Time) error {
	tw := tar.NewWriter(w)
	written := make(map[string]bool)
	// links maps the first archive path of a file with several hardlinks to
	// the path it was written under in this layer.
	links := make(map[string]string)

	writeDir := func(e *rootEntry) error {
		if written[e.path] {
			return nil
		}
		h := layerHeader(e.hdr, e.path)
		h.ModTime = dirMtime
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		written[e.path] = true
		return nil
	}
	ensureParents := func(p string) error {
		var chain []string
		for d := path.Dir(p); d != "/" && !written[d]; d = path.Dir(d) {
			chain = append(chain, d)
		}
		for i := len(chain) - 1; i >= 0; i-- {
			parent, ok := fs.byPath[chain[i]]
			if !ok || parent.hdr.Typeflag != tar.TypeDir {
				return fmt.Errorf("parent %s of %s is not a directory in the root filesystem", chain[i], p)
			}
			if err := writeDir(parent); err != nil {
				return err
			}
		}
		return nil
	}
	writeFile := func(src *rootEntry, p string) error {
		if err := tw.WriteHeader(layerHeader(src.hdr, p)); err != nil {
			return err
		}
		if _, err := io.Copy(tw, io.NewSectionReader(fs.r, src.offset, src.hdr.Size)); err != nil {
			return fmt.Errorf("copying %s: %w", p, err)
		}
		written[p] = true
		return nil
	}

	for _, e := range fs.entries {
		if !include(e.path) {
			continue
		}
		if err := ensureParents(e.path); err != nil {
			return err
		}

		switch e.hdr.Typeflag {
		case tar.TypeDir:
			if err := writeDir(e); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := writeFile(e, e.path); err != nil {
				return err
			}
			links[e.path] = e.path
		case tar.TypeLink:
			if first, ok := links[e.link]; ok {
				h := layerHeader(fs.byPath[e.link].hdr, e.path)
				h.Typeflag = tar.TypeLink
				h.Size = 0
				h.Linkname = strings.TrimPrefix(first, "/")
				if err := tw.WriteHeader(h); err != nil {
					return err
				}
				written[e.path] = true
				continue
			}
			// The file this links to is in another layer: store a copy.
			if err := writeFile(fs.byPath[e.link], e.path); err != nil {
				return err
			}
			links[e.link] = e.path
		default:
			if err := tw.WriteHeader(layerHeader(e.hdr, e.path)); err != nil {
				return err
			}
			written[e.path] = true
		}
	}
	return tw.Close()
}
