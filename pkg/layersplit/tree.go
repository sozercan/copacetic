package layersplit

import (
	"archive/tar"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Unix file type bits, as reported by lstat(2). They are spelled out so the
// comparison does not depend on the host OS.
const (
	modeFifo    = 0o010000
	modeChar    = 0o020000
	modeDir     = 0o040000
	modeBlock   = 0o060000
	modeRegular = 0o100000
	modeSymlink = 0o120000

	xattrPAXPrefix = "SCHILY.xattr."
)

// Entry describes one filesystem entry for comparison. It mirrors the Entry
// type of Dalec's layersplit.Tree so a flattened image can be compared to a
// root filesystem with the same semantics: directory timestamps are ignored,
// symlink permission bits are ignored, and everything else must match.
type Entry struct {
	Type   uint32
	Mode   uint32
	UID    uint32
	GID    uint32
	Size   int64
	SHA256 string
	Link   string
	Rdev   uint64
	Mtime  int64
	Xattrs string
}

func (e Entry) String() string {
	return fmt.Sprintf("type=%o mode=%o uid=%d gid=%d size=%d sha256=%s link=%q rdev=%d mtime=%d xattrs=%s",
		e.Type, e.Mode, e.UID, e.GID, e.Size, e.SHA256, e.Link, e.Rdev, e.Mtime, e.Xattrs)
}

// EntryFromTar returns the [Entry] for a tar header. sha256 is the hex digest
// of the content of a regular file and is ignored for other types. Hardlinks
// must be resolved by the caller to the entry of their target.
func EntryFromTar(h *tar.Header, sha256 string) (Entry, error) {
	e := Entry{
		Mode: uint32(h.Mode & 0o7777), //nolint:gosec // Masked to permission bits.
		UID:  uint32(h.Uid),           //nolint:gosec // Tar ids are non-negative.
		GID:  uint32(h.Gid),           //nolint:gosec // Tar ids are non-negative.
	}

	switch h.Typeflag {
	case tar.TypeDir:
		e.Type = modeDir
	case tar.TypeReg, tar.TypeRegA: //nolint:staticcheck // TypeRegA may still appear in old archives.
		e.Type = modeRegular
		e.Size = h.Size
		e.Mtime = h.ModTime.UnixNano()
		e.SHA256 = sha256
	case tar.TypeSymlink:
		e.Type = modeSymlink
		e.Mtime = h.ModTime.UnixNano()
		e.Link = h.Linkname
		// Symlink permission bits are not meaningful on Linux.
		e.Mode = 0
	case tar.TypeChar, tar.TypeBlock:
		e.Type = modeChar
		if h.Typeflag == tar.TypeBlock {
			e.Type = modeBlock
		}
		e.Rdev = uint64(h.Devmajor)<<32 | uint64(h.Devminor)&0xffffffff //nolint:gosec // Device numbers are non-negative.
		e.Mtime = h.ModTime.UnixNano()
	case tar.TypeFifo:
		e.Type = modeFifo
		e.Mtime = h.ModTime.UnixNano()
	default:
		return Entry{}, fmt.Errorf("unsupported tar entry type %q for %s", h.Typeflag, h.Name)
	}

	e.Xattrs = formatXattrs(h)
	return e, nil
}

// Xattrs returns the extended attributes recorded in a tar header.
func Xattrs(h *tar.Header) map[string]string {
	out := make(map[string]string)
	for k, v := range h.PAXRecords {
		if name, ok := strings.CutPrefix(k, xattrPAXPrefix); ok {
			out[name] = v
		}
	}
	return out
}

// XattrPAXRecord returns the PAX record key used to store the extended attribute name.
func XattrPAXRecord(name string) string {
	return xattrPAXPrefix + name
}

func formatXattrs(h *tar.Header) string {
	xs := Xattrs(h)
	names := make([]string, 0, len(xs))
	for name := range xs {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+"="+hex.EncodeToString([]byte(xs[name])))
	}
	return strings.Join(parts, ",")
}

// Diff describes a difference between two trees.
type Diff struct {
	Path     string
	Expected *Entry
	Actual   *Entry
}

func (d Diff) String() string {
	switch {
	case d.Expected == nil:
		return fmt.Sprintf("%s: unexpected entry %s", d.Path, d.Actual)
	case d.Actual == nil:
		return fmt.Sprintf("%s: missing (expected %s)", d.Path, d.Expected)
	default:
		return fmt.Sprintf("%s: expected %s, got %s", d.Path, d.Expected, d.Actual)
	}
}

// Compare returns the differences between the expected and actual trees,
// sorted by path.
func Compare(expected, actual map[string]Entry) []Diff {
	var diffs []Diff
	for p, e := range expected {
		a, ok := actual[p]
		if !ok {
			diffs = append(diffs, Diff{Path: p, Expected: &e})
			continue
		}
		if a != e {
			diffs = append(diffs, Diff{Path: p, Expected: &e, Actual: &a})
		}
	}
	for p, a := range actual {
		if _, ok := expected[p]; !ok {
			diffs = append(diffs, Diff{Path: p, Actual: &a})
		}
	}
	sort.Slice(diffs, func(i, j int) bool { return diffs[i].Path < diffs[j].Path })
	return diffs
}
