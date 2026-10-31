package layersplit

import (
	"archive/tar"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTree builds a Root like Dalec's writeTree test helper: every file and
// symlink gets its parent directories created implicitly.
func testTree(files, links map[string]string) Root {
	root := make(Root)
	addParents := func(p string) {
		for d := path.Dir(p); d != "/"; d = path.Dir(d) {
			root[d] = Node{Type: TypeDir}
		}
	}
	for p, content := range files {
		addParents(p)
		root[p] = Node{Type: TypeReg, Size: int64(len(content))}
	}
	for p, target := range links {
		addParents(p)
		root[p] = Node{Type: TypeSymlink, Link: target}
	}
	return root
}

// The fixture and expectations below are the same as Dalec's
// internal/layersplit/plan_test.go so the port keeps classification parity.
func testRoot() Root {
	//nolint:gosec // G101: file paths and contents of a test fixture, not credentials.
	return testTree(map[string]string{
		"/usr/lib/libc.so.6":        "libc",
		"/usr/lib/libssl.so.3":      "libssl",
		"/usr/bin/openssl":          "openssl",
		"/usr/bin/myapp":            "myapp",
		"/usr/bin/myapp-debug":      "myapp-debug",
		"/etc/passwd":               "root:x:0:0",
		"/etc/group":                "root:x:0:",
		"/etc/ld.so.cache":          "cache",
		"/etc/unowned.conf":         "x",
		"/var/lib/rpm/rpmdb.sqlite": "db",
		"/usr/share/doc/glibc/NEWS": "news",
	}, map[string]string{
		"/lib": "usr/lib",
	})
}

func testInputs() Inputs {
	return Inputs{
		Packages: map[string]string{
			"glibc":        "glibc",
			"openssl":      "openssl",
			"openssl-libs": "openssl",
			"setup":        "setup",
			"myapp":        "myapp",
			"myapp-debug":  "myapp",
		},
		Files: []OwnedFile{
			// Owned through the /lib -> usr/lib symlink.
			{Package: "glibc", Path: "/lib/libc.so.6"},
			{Package: "glibc", Path: "/etc/ld.so.cache", Ghost: true},
			{Package: "glibc", Path: "/usr/share/doc/glibc/NEWS"},
			{Package: "glibc", Path: "/usr/share/doc/glibc"},
			{Package: "openssl-libs", Path: "/usr/lib/libssl.so.3"},
			{Package: "openssl", Path: "/usr/bin/openssl"},
			{Package: "setup", Path: "/etc/passwd"},
			{Package: "setup", Path: "/etc/group"},
			{Package: "myapp", Path: "/usr/bin/myapp"},
			{Package: "myapp-debug", Path: "/usr/bin/myapp-debug"},
		},
		Modified: []string{"/etc/passwd"},
		App:      map[string]bool{"myapp": true, "myapp-debug": true},
	}
}

func groupNames(p *Plan) []string {
	var out []string
	for _, g := range p.Groups {
		out = append(out, g.Kind+":"+g.Name)
	}
	return out
}

func groupOf(t *testing.T, p *Plan, pth string) string {
	t.Helper()
	idx, ok := p.Assign[pth]
	require.True(t, ok, "path %s not assigned", pth)
	g := p.Groups[idx]
	return g.Kind + ":" + g.Name
}

func TestBuildPlan(t *testing.T) {
	plan, err := BuildPlan(testRoot(), testInputs(), Options{})
	require.NoError(t, err)

	assert.Equal(t, []string{
		"os:glibc", "os:openssl", "os:setup",
		"app:myapp", "app:myapp-debug",
		"state:state",
	}, groupNames(plan))
	assert.Equal(t, []string{"openssl", "openssl-libs"}, plan.Groups[1].Packages)

	cases := map[string]string{
		"/usr/lib/libc.so.6":        "os:glibc",
		"/usr/lib/libssl.so.3":      "os:openssl",
		"/usr/bin/openssl":          "os:openssl",
		"/usr/bin/myapp":            "app:myapp",
		"/usr/bin/myapp-debug":      "app:myapp-debug",
		"/usr/share/doc/glibc":      "os:glibc",
		"/usr/share/doc/glibc/NEWS": "os:glibc",
		"/etc/group":                "os:setup",
		// Modified after install.
		"/etc/passwd": "state:state",
		// %ghost file.
		"/etc/ld.so.cache": "state:state",
		// Not owned by any package.
		"/etc/unowned.conf": "state:state",
		"/lib":              "state:state",
		"/usr":              "state:state",
		// Package database.
		"/var/lib/rpm/rpmdb.sqlite": "state:state",
	}
	for p, want := range cases {
		assert.Equal(t, want, groupOf(t, plan, p), p)
	}
	assert.Len(t, plan.Assign, len(testRoot()))
}

func TestBuildPlanMultipleOwners(t *testing.T) {
	root := testTree(map[string]string{"/usr/share/licenses/shared": "x"}, nil)
	in := Inputs{
		Packages: map[string]string{"zlib": "zlib", "bash": "bash"},
		Files: []OwnedFile{
			{Package: "zlib", Path: "/usr/share/licenses/shared"},
			{Package: "bash", Path: "/usr/share/licenses/shared"},
		},
	}
	plan, err := BuildPlan(root, in, Options{})
	require.NoError(t, err)
	// The lexicographically first group key wins.
	assert.Equal(t, "os:bash", groupOf(t, plan, "/usr/share/licenses/shared"))
}

func TestBuildPlanBudget(t *testing.T) {
	plan, err := BuildPlan(testRoot(), testInputs(), Options{MaxLayers: 5})
	require.NoError(t, err)

	// 5 layers: 2 app + state leaves 2 for OS packages: the largest one
	// keeps its own layer and the rest are folded into misc.
	assert.Equal(t, []string{
		"os:misc", "os:openssl", "app:myapp", "app:myapp-debug", "state:state",
	}, groupNames(plan))
	assert.Equal(t, []string{"glibc", "setup"}, plan.Groups[0].Packages)
	assert.Equal(t, "os:misc", groupOf(t, plan, "/usr/lib/libc.so.6"))
	assert.Equal(t, "os:openssl", groupOf(t, plan, "/usr/bin/openssl"))

	_, err = BuildPlan(testRoot(), testInputs(), Options{MaxLayers: 3})
	assert.ErrorContains(t, err, "too small")
}

func TestBuildPlanDeterministic(t *testing.T) {
	want, err := BuildPlan(testRoot(), testInputs(), Options{})
	require.NoError(t, err)
	for range 10 {
		got, err := BuildPlan(testRoot(), testInputs(), Options{})
		require.NoError(t, err)
		assert.Equal(t, want.Groups, got.Groups)
		assert.Equal(t, want.Assign, got.Assign)
	}
}

func TestResolveInRoot(t *testing.T) {
	root := testTree(map[string]string{"/usr/lib/x": ""}, map[string]string{
		"/lib":      "usr/lib",
		"/abs":      "/usr/lib",
		"/loop/a":   "../loop/b",
		"/loop/b":   "a",
		"/usr/link": "../lib",
	})

	cases := map[string]string{
		"/lib/x":         "/usr/lib/x",
		"/abs/x":         "/usr/lib/x",
		"/usr/link/x":    "/usr/lib/x",
		"/lib":           "/lib",
		"/missing/a/b":   "/missing/a/b",
		"/lib/missing/b": "/usr/lib/missing/b",
		"/usr/../lib/x":  "/usr/lib/x",
	}
	for in, want := range cases {
		got, err := ResolveInRoot(root, in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}

	_, err := ResolveInRoot(root, "/loop/a/x")
	assert.ErrorContains(t, err, "too many levels")
}

func TestHistoryComment(t *testing.T) {
	g := Group{Name: "openssl", Kind: KindOS, Packages: []string{"openssl", "openssl-libs"}}
	c := g.HistoryComment()
	assert.Equal(t, "dalec.layer.v1 kind=os name=openssl packages=openssl,openssl-libs", c)
	assert.Equal(t, "dalec: files from openssl, openssl-libs", g.HistoryCreatedBy())

	parsed, ok := ParseHistoryComment(c)
	require.True(t, ok)
	assert.Equal(t, Group{Name: g.Name, Kind: g.Kind, Packages: g.Packages}, parsed)

	parsed, ok = ParseHistoryComment(Group{Name: KindState, Kind: KindState}.HistoryComment())
	require.True(t, ok)
	assert.Equal(t, KindState, parsed.Kind)
	assert.Empty(t, parsed.Packages)

	for _, s := range []string{"buildkit.exporter.image.v0", "", "dalec.layer.v1 kind=os", "dalec.layer.v2 kind=os name=x"} {
		_, ok = ParseHistoryComment(s)
		assert.False(t, ok, s)
	}
}

func TestParsers(t *testing.T) {
	t.Run("source package name", func(t *testing.T) {
		assert.Equal(t, "openssl", SourcePackageName("openssl-3.3.2-1.azl3.src.rpm"))
		assert.Equal(t, "ca-certificates", SourcePackageName("ca-certificates-3.0.0-8.azl3.src.rpm"))
		assert.Equal(t, "", SourcePackageName("(none)"))
	})

	t.Run("packages", func(t *testing.T) {
		pkgs, err := ParseRPMPackages(strings.NewReader("openssl-libs\topenssl-3.3.2-1.azl3.src.rpm\ngpg-pubkey\t(none)\n"))
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"openssl-libs": "openssl", "gpg-pubkey": "gpg-pubkey"}, pkgs)
	})

	t.Run("files", func(t *testing.T) {
		in := "glibc\tnormal\t\t/usr/lib/libc.so.6\n" +
			"glibc\tnormal\tg\t/etc/ld.so.cache\n" +
			"glibc\tnot installed\td\t/usr/share/doc/glibc/NEWS\n" +
			"setup\treplaced\tc\t/etc/passwd\n"
		files, err := ParseRPMFiles(strings.NewReader(in))
		require.NoError(t, err)
		assert.Equal(t, []OwnedFile{
			{Package: "glibc", Path: "/usr/lib/libc.so.6"},
			{Package: "glibc", Path: "/etc/ld.so.cache", Ghost: true},
			{Package: "setup", Path: "/etc/passwd"},
		}, files)

		_, err = ParseRPMFiles(strings.NewReader("bad line\n"))
		assert.ErrorContains(t, err, "malformed")
	})

	t.Run("verify", func(t *testing.T) {
		in := "S.5....T.  c /etc/passwd\n" +
			"missing   c /etc/removed\n" +
			".M.......    /usr/bin/with space\n"
		paths, err := ParseRPMVerify(strings.NewReader(in))
		require.NoError(t, err)
		assert.Equal(t, []string{"/etc/passwd", "/usr/bin/with space"}, paths)
	})
}

func TestEntryFromTar(t *testing.T) {
	mtime := time.Unix(1700000000, 123456789)
	reg := &tar.Header{
		Typeflag: tar.TypeReg, Name: "usr/bin/x", Mode: 0o104755, Uid: 1, Gid: 2, Size: 3, ModTime: mtime,
		PAXRecords: map[string]string{
			"SCHILY.xattr.security.capability": "\x01\x02",
			"SCHILY.xattr.user.a":              "b",
			"mtime":                            "ignored",
		},
	}
	e, err := EntryFromTar(reg, "abc")
	require.NoError(t, err)
	assert.Equal(t, Entry{
		Type: modeRegular, Mode: 0o4755, UID: 1, GID: 2, Size: 3, SHA256: "abc",
		Mtime: mtime.UnixNano(), Xattrs: "security.capability=0102,user.a=62",
	}, e)

	dir, err := EntryFromTar(&tar.Header{Typeflag: tar.TypeDir, Mode: 0o755, ModTime: mtime}, "")
	require.NoError(t, err)
	assert.Equal(t, Entry{Type: modeDir, Mode: 0o755}, dir, "directory timestamps are ignored")

	link, err := EntryFromTar(&tar.Header{Typeflag: tar.TypeSymlink, Mode: 0o777, Linkname: "../lib", ModTime: mtime}, "")
	require.NoError(t, err)
	assert.Equal(t, Entry{Type: modeSymlink, Link: "../lib", Mtime: mtime.UnixNano()}, link)

	dev, err := EntryFromTar(&tar.Header{Typeflag: tar.TypeChar, Mode: 0o666, Devmajor: 1, Devminor: 3, ModTime: mtime}, "")
	require.NoError(t, err)
	assert.Equal(t, uint64(1)<<32|3, dev.Rdev)

	_, err = EntryFromTar(&tar.Header{Typeflag: tar.TypeLink, Name: "x"}, "")
	assert.Error(t, err)
}

func TestCompare(t *testing.T) {
	a := Entry{Type: modeRegular, Mode: 0o644, SHA256: "a"}
	b := Entry{Type: modeRegular, Mode: 0o644, SHA256: "b"}
	diffs := Compare(
		map[string]Entry{"/same": a, "/changed": a, "/missing": a},
		map[string]Entry{"/same": a, "/changed": b, "/extra": b},
	)
	require.Len(t, diffs, 3)
	assert.Equal(t, "/changed", diffs[0].Path)
	assert.Contains(t, diffs[0].String(), "expected")
	assert.Equal(t, "/extra", diffs[1].Path)
	assert.Contains(t, diffs[1].String(), "unexpected entry")
	assert.Equal(t, "/missing", diffs[2].Path)
	assert.Contains(t, diffs[2].String(), "missing")
}
