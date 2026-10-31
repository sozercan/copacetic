// Package layersplit classifies the files of an RPM-based root filesystem into
// per-package layer groups plus a final "state" group, following the layout
// that Dalec writes for images built with `image.layers: per-package`.
//
// The grouping rules are ported from Dalec's internal/layersplit package
// (https://github.com/project-dalec/dalec, internal/layersplit/plan.go and
// tree_linux.go) and must stay in sync with it: a file goes to the state group
// when it is under the package database, is a %ghost file, was reported as
// modified by `rpm -Va`, or is not owned by any package. Every other file goes
// to the group of the package that owns it. Unlike Dalec, this port works on an
// in-memory view of the root filesystem so it can classify a tar stream.
package layersplit

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

const (
	// KindOS is a layer holding files of packages from the distro repositories.
	KindOS = "os"
	// KindApp is a layer holding files of a package built from the Dalec spec.
	KindApp = "app"
	// KindState is the final layer holding the package database and files
	// that are generated or modified during install.
	KindState = "state"

	// MiscGroupName is the name of the group Dalec uses for packages that did
	// not fit in its layer budget.
	MiscGroupName = "misc"

	// DefaultMaxLayers is Dalec's default maximum number of layers, including
	// the state layer.
	DefaultMaxLayers = 64

	// HistoryCommentPrefix prefixes the image history comment of every layer
	// Dalec writes in per-package mode.
	HistoryCommentPrefix = "dalec.layer.v1"

	// LabelImageLayers is the image label set on images using per-package layers.
	LabelImageLayers = "dev.dalec.image.layers"
	// ImageLayersPerPackage is the value of [LabelImageLayers] for per-package images.
	ImageLayersPerPackage = "per-package"
)

// stateDirs are directories whose whole contents always go to the state layer
// because they hold the package database.
var stateDirs = []string{
	"/var/lib/rpm",
	"/usr/lib/sysimage/rpm",
	"/var/lib/dpkg",
}

// Group is one layer of the split.
type Group struct {
	Name     string   `json:"name"`
	Kind     string   `json:"kind"`
	Packages []string `json:"packages,omitempty"`
	// Size is the total size in bytes of regular files in the group.
	Size int64 `json:"size"`
	// Paths is the number of filesystem entries in the group.
	Paths int `json:"paths"`
}

// HistoryComment returns the image history comment for the layer of g.
func (g Group) HistoryComment() string {
	s := HistoryCommentPrefix + " kind=" + g.Kind + " name=" + g.Name
	if len(g.Packages) > 0 {
		s += " packages=" + strings.Join(g.Packages, ",")
	}
	return s
}

// HistoryCreatedBy returns a human readable description of the layer of g.
func (g Group) HistoryCreatedBy() string {
	if g.Kind == KindState {
		return "dalec: package database and generated files"
	}
	return "dalec: files from " + strings.Join(g.Packages, ", ")
}

// ParseHistoryComment parses a history comment written by [Group.HistoryComment].
func ParseHistoryComment(s string) (Group, bool) {
	fields := strings.Fields(s)
	if len(fields) == 0 || fields[0] != HistoryCommentPrefix {
		return Group{}, false
	}

	var g Group
	for _, f := range fields[1:] {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		switch k {
		case "kind":
			g.Kind = v
		case "name":
			g.Name = v
		case "packages":
			if v != "" {
				g.Packages = strings.Split(v, ",")
			}
		}
	}
	if g.Kind == "" || g.Name == "" {
		return Group{}, false
	}
	return g, true
}

// Plan is the result of classifying a root filesystem.
type Plan struct {
	Groups []Group
	// Assign maps each path (absolute, relative to the root) to the index of
	// its group in Groups.
	Assign map[string]int
}

// Inputs holds the package manager data used to classify files.
type Inputs struct {
	// Packages maps an installed package name to its group key, for example
	// the source package name.
	Packages map[string]string
	// Files lists files owned by installed packages.
	Files []OwnedFile
	// Modified lists paths reported as changed since install by the package
	// manager's verify command.
	Modified []string
	// App is the set of package names built from the spec.
	App map[string]bool
}

// OwnedFile is a file owned by a package.
type OwnedFile struct {
	Package string
	Path    string
	Ghost   bool
}

// Options configures [BuildPlan].
type Options struct {
	// MaxLayers is the maximum number of layers, including the state layer.
	// Zero means [DefaultMaxLayers].
	MaxLayers int
}

// NodeType is the type of a [Node].
type NodeType int

const (
	// TypeOther is any entry that is not a directory, regular file or symlink.
	TypeOther NodeType = iota
	// TypeDir is a directory.
	TypeDir
	// TypeReg is a regular file.
	TypeReg
	// TypeSymlink is a symbolic link.
	TypeSymlink
)

// Node is the subset of filesystem metadata needed to classify a path.
type Node struct {
	Type NodeType
	// Size is the size of a regular file.
	Size int64
	// Link is the target of a symlink.
	Link string
}

// Root is an in-memory view of a root filesystem. Keys are absolute, clean
// paths; the root directory itself is not included.
type Root map[string]Node

// BuildPlan assigns every entry of root to a group. It mirrors Dalec's
// BuildPlan, including the layer budget, so the classification of a root
// filesystem matches the layout Dalec produced for it.
func BuildPlan(root Root, in Inputs, opts Options) (*Plan, error) {
	maxLayers := opts.MaxLayers
	if maxLayers == 0 {
		maxLayers = DefaultMaxLayers
	}

	owners := make(map[string][]string)
	ghost := make(map[string]bool)
	for _, f := range in.Files {
		p, err := ResolveInRoot(root, f.Path)
		if err != nil {
			return nil, fmt.Errorf("resolving %s: %w", f.Path, err)
		}
		if f.Ghost {
			ghost[p] = true
			continue
		}
		owners[p] = append(owners[p], f.Package)
	}

	modified := make(map[string]bool, len(in.Modified))
	for _, m := range in.Modified {
		p, err := ResolveInRoot(root, m)
		if err != nil {
			return nil, fmt.Errorf("resolving %s: %w", m, err)
		}
		modified[p] = true
	}

	groupKey := func(pkg string) string {
		if in.App[pkg] {
			return KindApp + ":" + pkg
		}
		if k := in.Packages[pkg]; k != "" {
			return KindOS + ":" + k
		}
		return KindOS + ":" + pkg
	}

	type acc struct {
		Group
		pkgs map[string]bool
	}
	groups := make(map[string]*acc)
	getGroup := func(key, kind, name string) *acc {
		g, ok := groups[key]
		if !ok {
			g = &acc{Group: Group{Name: name, Kind: kind}, pkgs: make(map[string]bool)}
			groups[key] = g
		}
		return g
	}
	stateKey := KindState + ":"
	getGroup(stateKey, KindState, KindState)

	for pkg := range in.Packages {
		key := groupKey(pkg)
		kind, name, _ := strings.Cut(key, ":")
		getGroup(key, kind, name).pkgs[pkg] = true
	}
	for pkg := range in.App {
		key := groupKey(pkg)
		kind, name, _ := strings.Cut(key, ":")
		getGroup(key, kind, name).pkgs[pkg] = true
	}

	paths := make([]string, 0, len(root))
	for p := range root {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	assignKey := make(map[string]string, len(paths))
	for _, p := range paths {
		key := stateKey
		if !inStateDir(p) && !ghost[p] && !modified[p] {
			if pkgs := owners[p]; len(pkgs) > 0 {
				keys := make([]string, 0, len(pkgs))
				for _, pkg := range pkgs {
					keys = append(keys, groupKey(pkg))
				}
				sort.Strings(keys)
				key = keys[0]
			}
		}

		kind, name, _ := strings.Cut(key, ":")
		if kind == KindState {
			name = KindState
		}
		g := getGroup(key, kind, name)
		g.Paths++
		if n := root[p]; n.Type == TypeReg {
			g.Size += n.Size
		}
		assignKey[p] = key
	}

	var osKeys, appKeys []string
	for key, g := range groups {
		if key == stateKey || g.Paths == 0 {
			continue
		}
		if g.Kind == KindApp {
			appKeys = append(appKeys, key)
		} else {
			osKeys = append(osKeys, key)
		}
	}
	sort.Strings(appKeys)

	// Keep the layer count within budget by folding the smallest OS groups
	// into a single misc group. App groups always get their own layer.
	budget := maxLayers - 1 - len(appKeys)
	if budget < 1 {
		return nil, fmt.Errorf("layer budget of %d is too small for %d spec packages", maxLayers, len(appKeys))
	}
	if len(osKeys) > budget {
		sort.Slice(osKeys, func(i, j int) bool {
			gi, gj := groups[osKeys[i]], groups[osKeys[j]]
			if gi.Size != gj.Size {
				return gi.Size > gj.Size
			}
			return osKeys[i] < osKeys[j]
		})
		miscKey := KindOS + ":" + MiscGroupName + "\x00"
		misc := getGroup(miscKey, KindOS, MiscGroupName)
		for _, key := range osKeys[budget-1:] {
			g := groups[key]
			misc.Paths += g.Paths
			misc.Size += g.Size
			for pkg := range g.pkgs {
				misc.pkgs[pkg] = true
			}
			for p, k := range assignKey {
				if k == key {
					assignKey[p] = miscKey
				}
			}
			delete(groups, key)
		}
		osKeys = append(osKeys[:budget-1:budget-1], miscKey)
	}
	sort.Strings(osKeys)

	ordered := append(append(osKeys, appKeys...), stateKey) //nolint:gocritic // Same construction as Dalec.
	plan := &Plan{Assign: make(map[string]int, len(assignKey))}
	index := make(map[string]int, len(ordered))
	for i, key := range ordered {
		g := groups[key]
		g.Packages = sortedKeys(g.pkgs)
		plan.Groups = append(plan.Groups, g.Group)
		index[key] = i
	}
	for p, key := range assignKey {
		plan.Assign[p] = index[key]
	}
	return plan, nil
}

func inStateDir(p string) bool {
	for _, d := range stateDirs {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ResolveInRoot returns the canonical form of the absolute path p inside root:
// every symlink in a parent directory is resolved (scoped to root), while the
// final path component is left as is. Missing components are kept literally.
func ResolveInRoot(root Root, p string) (string, error) {
	const maxLinks = 255

	pending := splitPath(p)
	cur := "/"
	links := 0
	for len(pending) > 0 {
		part := pending[0]
		pending = pending[1:]
		next := path.Join(cur, part)
		if len(pending) == 0 {
			return next, nil
		}

		n, ok := root[next]
		if !ok {
			return path.Join(append([]string{next}, pending...)...), nil
		}
		if n.Type != TypeSymlink {
			cur = next
			continue
		}

		links++
		if links > maxLinks {
			return "", fmt.Errorf("too many levels of symbolic links in %s", p)
		}
		target := n.Link
		if !path.IsAbs(target) {
			target = path.Join(cur, target)
		}
		pending = append(splitPath(target), pending...)
		cur = "/"
	}
	return cur, nil
}

func splitPath(p string) []string {
	var out []string
	for _, part := range strings.Split(path.Clean("/"+p), "/") {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// SourcePackageName returns the source package name from an RPM SOURCERPM
// value such as "openssl-3.3.2-1.azl3.src.rpm".
func SourcePackageName(srpm string) string {
	s := strings.TrimSuffix(srpm, ".src.rpm")
	s = strings.TrimSuffix(s, ".nosrc.rpm")
	for range 2 {
		i := strings.LastIndex(s, "-")
		if i <= 0 {
			return ""
		}
		s = s[:i]
	}
	return s
}

func newScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	return sc
}

// ParseRPMPackages parses lines of `rpm -qa --qf '%{NAME}\t%{SOURCERPM}\n'`
// and returns a map of package name to source package name.
func ParseRPMPackages(r io.Reader) (map[string]string, error) {
	out := make(map[string]string)
	sc := newScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		name, srpm, _ := strings.Cut(line, "\t")
		src := SourcePackageName(srpm)
		if src == "" {
			src = name
		}
		out[name] = src
	}
	return out, sc.Err()
}

// ParseRPMFiles parses lines of
// `rpm -qa --qf '[%{=NAME}\t%{FILESTATES:fstate}\t%{FILEFLAGS:fflags}\t%{FILENAMES}\n]'`.
// Files that are not installed on disk are skipped.
func ParseRPMFiles(r io.Reader) ([]OwnedFile, error) {
	var out []OwnedFile
	sc := newScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 4)
		if len(parts) != 4 {
			return nil, fmt.Errorf("malformed rpm file line: %q", line)
		}
		switch parts[1] {
		case "normal", "replaced":
		default:
			// "not installed" (for example docs excluded with --nodocs),
			// "net shared", "wrong color" or "missing": not on disk.
			continue
		}
		out = append(out, OwnedFile{
			Package: parts[0],
			Path:    parts[3],
			Ghost:   strings.Contains(parts[2], "g"),
		})
	}
	return out, sc.Err()
}

// ParseRPMVerify parses the output of `rpm -Va` and returns paths that differ
// from the installed package. Missing files are skipped.
func ParseRPMVerify(r io.Reader) ([]string, error) {
	var out []string
	sc := newScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "missing") {
			continue
		}
		i := strings.Index(line, " /")
		if i < 0 {
			continue
		}
		out = append(out, line[i+1:])
	}
	return out, sc.Err()
}
