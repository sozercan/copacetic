package layerreplace

import (
	"archive/tar"
	"bytes"
	"io"
	"sort"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/layersplit"
)

type fsEntry struct {
	path    string
	typ     byte
	mode    int64
	content string
	link    string
	xattrs  map[string]string
	uid     int
}

var testMtime = time.Unix(1700000000, 500)

// rootTar writes entries like `tar --format=posix -C ROOT .`: names start with
// "./", directories end with "/", and parents come first.
func rootTar(t *testing.T, entries []fsEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: "./", Mode: 0o755, ModTime: testMtime, Format: tar.FormatPAX}))
	for _, e := range entries {
		h := &tar.Header{
			Typeflag: e.typ, Name: "." + e.path, Mode: e.mode, Uid: e.uid, ModTime: testMtime,
			Format: tar.FormatPAX, AccessTime: testMtime.Add(time.Hour),
		}
		switch e.typ {
		case tar.TypeDir:
			h.Name += "/"
		case tar.TypeReg:
			h.Size = int64(len(e.content))
		case tar.TypeSymlink:
			h.Linkname = e.link
		case tar.TypeLink:
			h.Linkname = "." + e.link
		case tar.TypeChar:
			h.Devmajor, h.Devminor = 1, 3
		}
		for k, v := range e.xattrs {
			if h.PAXRecords == nil {
				h.PAXRecords = map[string]string{}
			}
			h.PAXRecords[layersplit.XattrPAXRecord(k)] = v
		}
		require.NoError(t, tw.WriteHeader(h))
		if e.typ == tar.TypeReg {
			_, err := tw.Write([]byte(e.content))
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	return buf.Bytes()
}

func dir(p string) fsEntry { return fsEntry{path: p, typ: tar.TypeDir, mode: 0o755} }
func file(p, content string) fsEntry {
	return fsEntry{path: p, typ: tar.TypeReg, mode: 0o644, content: content}
}

// testRootEntries is a small Azure Linux like root filesystem. opensslVersion
// changes the content of the openssl package files.
func testRootEntries(opensslVersion string) []fsEntry {
	return []fsEntry{
		dir("/dev"),
		{path: "/dev/null", typ: tar.TypeChar, mode: 0o666},
		dir("/etc"),
		file("/etc/group", "root:x:0:"),
		// Unowned, so in the state layer. The glibc files below are
		// hardlinks to it, as tar records later links to the first path.
		file("/etc/libc-copy", "libc"),
		file("/etc/ld.so.cache", "cache"),
		file("/etc/passwd", "root:x:0:0"),
		file("/etc/unowned.conf", "x"),
		{path: "/lib", typ: tar.TypeSymlink, mode: 0o777, link: "usr/lib"},
		dir("/run"),
		{path: "/run/fifo", typ: tar.TypeFifo, mode: 0o600},
		dir("/usr"),
		dir("/usr/bin"),
		{path: "/usr/bin/myapp", typ: tar.TypeReg, mode: 0o4755, content: "myapp", xattrs: map[string]string{"security.capability": "\x01\x00"}},
		file("/usr/bin/myapp-debug", "myapp-debug"),
		{path: "/usr/bin/openssl", typ: tar.TypeReg, mode: 0o755, content: "openssl " + opensslVersion, uid: 0},
		// Hardlink within the openssl group.
		{path: "/usr/bin/openssl-link", typ: tar.TypeLink, link: "/usr/bin/openssl"},
		dir("/usr/lib"),
		{path: "/usr/lib/libc-link", typ: tar.TypeLink, link: "/etc/libc-copy"},
		{path: "/usr/lib/libc.so.6", typ: tar.TypeLink, link: "/etc/libc-copy"},
		file("/usr/lib/libssl.so.3", "libssl "+opensslVersion),
		dir("/usr/share"),
		dir("/usr/share/doc"),
		dir("/usr/share/doc/glibc"),
		file("/usr/share/doc/glibc/NEWS", "news"),
		dir("/var"),
		dir("/var/lib"),
		dir("/var/lib/rpm"),
		file("/var/lib/rpm/rpmdb.sqlite", "db "+opensslVersion),
	}
}

func testInputs() layersplit.Inputs {
	return layersplit.Inputs{
		Packages: map[string]string{
			"glibc": "glibc", "openssl": "openssl", "openssl-libs": "openssl", "setup": "setup",
			"myapp": "myapp", "myapp-debug": "myapp",
		},
		Files: []layersplit.OwnedFile{
			{Package: "glibc", Path: "/lib/libc.so.6"},
			{Package: "glibc", Path: "/usr/lib/libc-link"},
			{Package: "glibc", Path: "/etc/ld.so.cache", Ghost: true},
			{Package: "glibc", Path: "/usr/share/doc/glibc/NEWS"},
			{Package: "glibc", Path: "/usr/share/doc/glibc"},
			{Package: "openssl-libs", Path: "/usr/lib/libssl.so.3"},
			{Package: "openssl", Path: "/usr/bin/openssl"},
			{Package: "openssl", Path: "/usr/bin/openssl-link"},
			{Package: "setup", Path: "/etc/passwd"},
			{Package: "setup", Path: "/etc/group"},
			{Package: "myapp", Path: "/usr/bin/myapp"},
			{Package: "myapp-debug", Path: "/usr/bin/myapp-debug"},
		},
		Modified: []string{"/etc/passwd"},
		App:      map[string]bool{"myapp": true, "myapp-debug": true},
	}
}

func testLayout(t *testing.T) *Layout {
	t.Helper()
	l, err := ParseLayout(perPackageConfig(historyEntries{
		"dalec.layer.v1 kind=os name=glibc packages=glibc",
		"dalec.layer.v1 kind=os name=openssl packages=openssl,openssl-libs",
		"dalec.layer.v1 kind=os name=setup packages=setup",
		"dalec.layer.v1 kind=app name=myapp packages=myapp",
		"dalec.layer.v1 kind=app name=myapp-debug packages=myapp-debug",
		"dalec.layer.v1 kind=state name=state",
		"buildkit.exporter.image.v0",
	}.history(), 7))
	require.NoError(t, err)
	return l
}

type historyEntries []string

func (h historyEntries) history() []v1.History {
	out := make([]v1.History, 0, len(h))
	for _, c := range h {
		out = append(out, v1.History{Comment: c})
	}
	return out
}

func indexTar(t *testing.T, b []byte) *rootFS {
	t.Helper()
	fs, err := indexRootFS(bytes.NewReader(b), int64(len(b)))
	require.NoError(t, err)
	return fs
}

// splitAll writes one layer per layout position, like Dalec does.
func splitAll(t *testing.T, fs *rootFS, asg *assignment, layout *Layout) [][]byte {
	t.Helper()
	out := make([][]byte, layout.NumLayers)
	for i := range out {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		require.NoError(t, tw.Close())
		out[i] = buf.Bytes()
	}
	for pos, li := range layout.Layers {
		var buf bytes.Buffer
		require.NoError(t, fs.writeLayer(&buf, func(p string) bool { return asg.layer[p] == pos }, time.Unix(0, 0)))
		out[li.Index] = buf.Bytes()
	}
	return out
}

func flattenLayers(t *testing.T, layers [][]byte) map[string]layersplit.Entry {
	t.Helper()
	f := newFlattener()
	for _, l := range layers {
		require.NoError(t, f.apply(bytes.NewReader(l)))
	}
	return f.tree
}

func layerPaths(t *testing.T, b []byte) map[string]tar.Header {
	t.Helper()
	out := map[string]tar.Header{}
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		require.NoError(t, err)
		out[cleanTarPath(h.Name)] = *h
	}
}

func TestIndexRootFS(t *testing.T) {
	fs := indexTar(t, rootTar(t, testRootEntries("1")))
	tree := fs.Tree()
	assert.Len(t, tree, len(testRootEntries("1")))
	assert.NotContains(t, tree, "/")

	// File contents are read back from the recorded offsets.
	e := fs.byPath["/usr/lib/libssl.so.3"]
	got, err := io.ReadAll(io.NewSectionReader(fs.r, e.offset, e.hdr.Size))
	require.NoError(t, err)
	assert.Equal(t, "libssl 1", string(got))

	// Hardlinks compare like their target.
	assert.Equal(t, tree["/usr/bin/openssl"], tree["/usr/bin/openssl-link"])
	assert.Equal(t, "security.capability=0100", tree["/usr/bin/myapp"].Xattrs)
	assert.Equal(t, uint32(0o4755), tree["/usr/bin/myapp"].Mode)

	root := fs.Root()
	assert.Equal(t, layersplit.Node{Type: layersplit.TypeSymlink, Link: "usr/lib"}, root["/lib"])
	assert.Equal(t, layersplit.TypeReg, root["/usr/bin/openssl-link"].Type)
}

func TestSplitAndFlattenRoundTrip(t *testing.T) {
	fs := indexTar(t, rootTar(t, testRootEntries("1")))
	layout := testLayout(t)
	asg, err := classify(fs.Root(), testInputs(), layout)
	require.NoError(t, err)

	group := func(p string) string { return layout.Layers[asg.layer[p]].Group.Name }
	assert.Equal(t, "glibc", group("/usr/lib/libc.so.6"))
	assert.Equal(t, "openssl", group("/usr/lib/libssl.so.3"))
	assert.Equal(t, "state", group("/etc/passwd"))
	assert.Equal(t, "state", group("/lib"))
	assert.Equal(t, "myapp-debug", group("/usr/bin/myapp-debug"))
	assert.Equal(t, []string{"openssl", "openssl-libs"}, asg.packages[1])

	layers := splitAll(t, fs, asg, layout)
	require.NoError(t, verifyTree(fs.Tree(), flattenLayers(t, layers)))

	openssl := layerPaths(t, layers[1])
	// Parents are recreated with normalized directory timestamps.
	assert.Equal(t, time.Unix(0, 0), openssl["/usr/bin"].ModTime)
	assert.Equal(t, byte(tar.TypeDir), openssl["/usr"].Typeflag)
	// Hardlinks within a layer stay hardlinks; file times are kept.
	assert.Equal(t, byte(tar.TypeLink), openssl["/usr/bin/openssl-link"].Typeflag)
	assert.Equal(t, "usr/bin/openssl", openssl["/usr/bin/openssl-link"].Linkname)
	assert.Equal(t, testMtime, openssl["/usr/bin/openssl"].ModTime)
	assert.True(t, openssl["/usr/bin/openssl"].AccessTime.IsZero())
	assert.NotContains(t, openssl, "/usr/lib/libc.so.6")

	// A hardlink to a file in another layer becomes a copy, and later links
	// to the same file in the layer link to that copy.
	glibc := layerPaths(t, layers[0])
	assert.Equal(t, byte(tar.TypeReg), glibc["/usr/lib/libc-link"].Typeflag)
	assert.Equal(t, int64(4), glibc["/usr/lib/libc-link"].Size)
	assert.Equal(t, byte(tar.TypeLink), glibc["/usr/lib/libc.so.6"].Typeflag)
	assert.Equal(t, "usr/lib/libc-link", glibc["/usr/lib/libc.so.6"].Linkname)
	assert.Equal(t, byte(tar.TypeReg), layerPaths(t, layers[layout.StateLayer().Index])["/etc/libc-copy"].Typeflag)
}

func TestReplaceAffectedLayers(t *testing.T) {
	layout := testLayout(t)
	oldFS := indexTar(t, rootTar(t, testRootEntries("1")))
	oldAsg, err := classify(oldFS.Root(), testInputs(), layout)
	require.NoError(t, err)
	oldLayers := splitAll(t, oldFS, oldAsg, layout)

	newFS := indexTar(t, rootTar(t, testRootEntries("2")))
	asg, err := classify(newFS.Root(), testInputs(), layout)
	require.NoError(t, err)

	affected := affectedLayers([]string{"openssl", "openssl-libs"}, layout, asg)
	assert.Equal(t, []int{1, layout.State}, affected)

	replaced := make([][]byte, len(oldLayers))
	copy(replaced, oldLayers)
	for _, pos := range affected {
		var buf bytes.Buffer
		require.NoError(t, newFS.writeLayer(&buf, func(p string) bool { return asg.layer[p] == pos }, time.Unix(0, 0)))
		replaced[layout.Layers[pos].Index] = buf.Bytes()
	}
	require.NoError(t, verifyTree(newFS.Tree(), flattenLayers(t, replaced)))

	// Replacing too few layers is caught by the verification.
	stale := make([][]byte, len(oldLayers))
	copy(stale, oldLayers)
	var buf bytes.Buffer
	require.NoError(t, newFS.writeLayer(&buf, func(p string) bool { return asg.layer[p] == layout.State }, time.Unix(0, 0)))
	stale[layout.StateLayer().Index] = buf.Bytes()
	err = verifyTree(newFS.Tree(), flattenLayers(t, stale))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "/usr/bin/openssl: expected")
	assert.Contains(t, err.Error(), "/usr/lib/libssl.so.3: expected")
}

func TestClassifyGroupMapping(t *testing.T) {
	fs := indexTar(t, rootTar(t, testRootEntries("1")))

	// Groups folded into Dalec's misc layer are found through their packages.
	misc, err := ParseLayout(perPackageConfig(historyEntries{
		"dalec.layer.v1 kind=os name=misc packages=glibc,setup",
		"dalec.layer.v1 kind=os name=openssl packages=openssl,openssl-libs",
		"dalec.layer.v1 kind=app name=myapp packages=myapp",
		"dalec.layer.v1 kind=app name=myapp-debug packages=myapp-debug",
		"dalec.layer.v1 kind=state name=state",
	}.history(), 5))
	require.NoError(t, err)
	asg, err := classify(fs.Root(), testInputs(), misc)
	require.NoError(t, err)
	assert.Equal(t, 0, asg.layer["/usr/lib/libc.so.6"])
	assert.Equal(t, 0, asg.layer["/etc/group"])
	assert.Equal(t, []string{"glibc", "setup"}, asg.packages[0])
	assert.Equal(t, []int{0, 4}, affectedLayers([]string{"glibc"}, misc, asg))

	// A package group without a layer cannot be placed.
	noSetup, err := ParseLayout(perPackageConfig(historyEntries{
		"dalec.layer.v1 kind=os name=glibc packages=glibc",
		"dalec.layer.v1 kind=os name=openssl packages=openssl,openssl-libs",
		"dalec.layer.v1 kind=app name=myapp packages=myapp",
		"dalec.layer.v1 kind=app name=myapp-debug packages=myapp-debug",
		"dalec.layer.v1 kind=state name=state",
	}.history(), 5))
	require.NoError(t, err)
	_, err = classify(fs.Root(), testInputs(), noSetup)
	assert.ErrorContains(t, err, "files of package group os:setup")
}

func TestFlattenWhiteouts(t *testing.T) {
	lower := rootTar(t, []fsEntry{dir("/a"), file("/a/x", "x"), file("/a/y", "y"), dir("/b"), file("/b/z", "z"), file("/c", "c")})
	upper := rootTar(t, []fsEntry{
		file("/a/.wh.x", ""),
		dir("/b"), file("/b/.wh..wh..opq", ""), file("/b/new", "n"),
		dir("/c"),
	})
	tree := flattenLayers(t, [][]byte{lower, upper})
	paths := make([]string, 0, len(tree))
	for p := range tree {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	assert.Equal(t, []string{"/a", "/a/y", "/b", "/b/new", "/c"}, paths)
	assert.Equal(t, uint32(0o040000), tree["/c"].Type)
}

func TestVerifyTreeReportsDiffs(t *testing.T) {
	want := map[string]layersplit.Entry{}
	for i := range 30 {
		want["/f"+strings.Repeat("x", i)] = layersplit.Entry{Type: 0o100000}
	}
	err := verifyTree(want, map[string]layersplit.Entry{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "differs from the upgraded root filesystem in 30 paths")
	assert.Contains(t, err.Error(), "... and 10 more")
}
