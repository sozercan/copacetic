package layerreplace

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	rpmver "github.com/knqyf263/go-rpm-version"
)

// rpmPackage is an installed or downloaded RPM.
type rpmPackage struct {
	Name string
	// EVR is the epoch:version-release of the package.
	EVR  string
	Arch string
}

// parsePackages parses lines of `rpm -q --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n'`.
// With prefixed set, each line starts with an extra tab separated field
// (the RPM file name), which is dropped.
func parsePackages(r io.Reader, prefixed bool) ([]rpmPackage, error) {
	want := 3
	if prefixed {
		want = 4
	}
	var out []rpmPackage
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != want {
			return nil, fmt.Errorf("malformed package line %q", line)
		}
		f = f[len(f)-3:]
		out = append(out, rpmPackage{Name: f[0], EVR: f[1], Arch: f[2]})
	}
	return out, sc.Err()
}

// scriptlet is one scriptlet, trigger or file trigger printed by
// `rpm -q --scripts --triggers --filetriggers`.
type scriptlet struct {
	// Source is the package the scriptlet comes from, for example "new openssl".
	Source string
	// Tag is the scriptlet type, for example "postinstall" or "triggerin".
	Tag string
	// Prog is the interpreter, or the program run for program-only scriptlets.
	Prog string
	// Body is the script body.
	Body string
}

var (
	// "postinstall program: /sbin/ldconfig".
	programHeader = regexp.MustCompile(`^([a-z]+) program: (.+)$`)
	// "postinstall scriptlet (using /bin/sh):" and
	// "triggerin scriptlet (using /bin/sh) -- glibc".
	scriptletHeader = regexp.MustCompile(`^([a-z]+) scriptlet(?: \(using (.*?)\))?(?::| -- .*)$`)

	ldconfigPrograms = map[string]bool{
		"/sbin/ldconfig":     true,
		"/usr/sbin/ldconfig": true,
	}
	shells = map[string]bool{
		shell:           true,
		"/usr/bin/sh":   true,
		"/bin/bash":     true,
		"/usr/bin/bash": true,
	}
)

// shell is the default scriptlet interpreter, also used to run the
// prepare and apply scripts.
const shell = "/bin/sh"

// sectionMarker starts a section of the scripts dump; the rest of the line
// names the package the following scriptlets belong to.
const sectionMarker = "@@@ "

// parseScriptlets parses the scripts dump written by the prepare step: rpm
// query output split into sections by lines starting with [sectionMarker].
func parseScriptlets(r io.Reader) ([]scriptlet, error) {
	var out []scriptlet
	var cur *scriptlet
	var body []string
	source := ""
	flush := func() {
		if cur != nil {
			cur.Body = strings.Join(body, "\n")
			out = append(out, *cur)
		}
		cur, body = nil, nil
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if s, ok := strings.CutPrefix(line, sectionMarker); ok {
			flush()
			source = strings.TrimSpace(s)
			continue
		}
		if m := programHeader.FindStringSubmatch(line); m != nil {
			flush()
			out = append(out, scriptlet{Source: source, Tag: m[1], Prog: strings.TrimSpace(m[2])})
			continue
		}
		if m := scriptletHeader.FindStringSubmatch(line); m != nil {
			flush()
			cur = &scriptlet{Source: source, Tag: m[1], Prog: m[2]}
			continue
		}
		if cur != nil {
			body = append(body, line)
			continue
		}
		if strings.TrimSpace(line) != "" {
			return nil, fmt.Errorf("unexpected line in scriptlet dump: %q", line)
		}
	}
	flush()
	return out, sc.Err()
}

// Sources of scriptlets in the scripts dump.
const (
	sourceNew       = "new"
	sourceInstalled = "installed"
)

// runsOnUpgrade reports whether s can run when its package is upgraded. All
// scriptlets of the new package except %verifyscript can run. Of the
// installed package being replaced, only the erase-time scriptlets run. Any
// trigger can fire.
func (s scriptlet) runsOnUpgrade() bool {
	if s.Tag == "verify" {
		return false
	}
	if strings.Contains(s.Tag, "trigger") {
		return true
	}
	if kind, _, _ := strings.Cut(s.Source, " "); kind == sourceInstalled {
		switch s.Tag {
		case "preuninstall", "postuninstall", "preuntrans", "postuntrans":
			return true
		}
		return false
	}
	return true
}

// ldconfigOnly reports whether running s can at most refresh the dynamic
// linker cache.
func (s scriptlet) ldconfigOnly() bool {
	body := strings.TrimSpace(s.Body)
	if ldconfigPrograms[s.Prog] {
		return body == ""
	}
	if !shells[s.Prog] {
		return false
	}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line != "ldconfig" && !ldconfigPrograms[line] {
			return false
		}
	}
	return true
}

// safetyInput is the data collected before changing the image.
type safetyInput struct {
	Installed  []rpmPackage
	Downloaded []rpmPackage
	Scriptlets []scriptlet
	// TestExitCode and TestOutput are the result of
	// `rpm --root ROOT -U --test <rpms>` against the image's package database.
	TestExitCode int
	TestOutput   string
	// ExcludeDocs is set when the image was installed without documentation.
	ExcludeDocs bool
	// ResolveError holds the package manager's explanation when the updates
	// could not be resolved against the packages installed in the image.
	ResolveError string
}

// resolverProblems extracts the lines explaining why tdnf could not resolve
// the update from its output, falling back to the last lines of the log.
func resolverProblems(log string) string {
	lines := strings.Split(strings.TrimSpace(log), "\n")
	var out []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		lower := strings.ToLower(l)
		if strings.Contains(lower, "requires") || strings.Contains(lower, "conflicts") ||
			strings.Contains(lower, "nothing provides") || strings.Contains(lower, "problem") ||
			strings.HasPrefix(lower, "error") {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		out = lines
	}
	const maxLines = 10
	if len(out) > maxLines {
		out = out[len(out)-maxLines:]
	}
	return strings.Join(out, "\n")
}

// docsExcluded reports whether the image was installed without documentation
// (for example with tsflags=nodocs, which Dalec uses unless docs are
// requested): some documentation file is recorded as "not installed". It
// reads lines of `rpm -qa --qf '[%{FILEFLAGS:fflags}\t%{FILESTATES:fstate}\n]'`.
func docsExcluded(r io.Reader) (bool, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		flags, state, ok := strings.Cut(sc.Text(), "\t")
		if !ok {
			continue
		}
		if strings.Contains(flags, "d") && state == "not installed" {
			return true, nil
		}
	}
	return false, sc.Err()
}

// SafetyError lists the reasons an update cannot be applied by replacing layers.
type SafetyError struct {
	Reasons []string
}

func (e *SafetyError) Error() string {
	var b strings.Builder
	b.WriteString("the update cannot be applied by replacing layers:")
	for _, r := range e.Reasons {
		b.WriteString("\n  - " + r)
	}
	b.WriteString("\nRun copa without --layers=replace to patch the image by adding a layer instead.")
	return b.String()
}

// checkSafety decides whether the downloaded packages can be applied to the
// image by replacing layers. It requires that every downloaded package
// upgrades a package already installed in the image, that the transaction
// passes rpm's dependency check against the image's own package database, and
// that no scriptlet that could run does more than refresh the linker cache.
func checkSafety(in *safetyInput) error {
	if in.ResolveError != "" {
		return &SafetyError{Reasons: []string{
			"the package manager cannot resolve the update against the packages installed in the image:\n" + in.ResolveError,
		}}
	}

	var reasons []string

	installed := make(map[string][]rpmPackage)
	for _, p := range in.Installed {
		installed[p.Name] = append(installed[p.Name], p)
	}
	for _, d := range in.Downloaded {
		olds := installed[d.Name]
		if len(olds) == 0 {
			reasons = append(reasons, fmt.Sprintf("%s %s is not installed in the image: the update would add a new package", d.Name, d.EVR))
			continue
		}
		var old *rpmPackage
		for i := range olds {
			if olds[i].Arch == d.Arch || d.Arch == "noarch" || olds[i].Arch == "noarch" {
				old = &olds[i]
				break
			}
		}
		if old == nil {
			reasons = append(reasons, fmt.Sprintf("%s.%s %s does not match the installed architecture of %s", d.Name, d.Arch, d.EVR, d.Name))
			continue
		}
		if !rpmver.NewVersion(old.EVR).LessThan(rpmver.NewVersion(d.EVR)) {
			reasons = append(reasons, fmt.Sprintf("%s %s is not newer than the installed %s", d.Name, d.EVR, old.EVR))
		}
	}

	if in.TestExitCode != 0 {
		out := strings.TrimSpace(in.TestOutput)
		if out == "" {
			out = fmt.Sprintf("exit code %d", in.TestExitCode)
		}
		reasons = append(reasons, "rpm -U --test failed against the image's package database: "+out)
	}

	var bad []string
	for _, s := range in.Scriptlets {
		if s.runsOnUpgrade() && !s.ldconfigOnly() {
			prog := s.Prog
			if prog == "" {
				prog = "unknown interpreter"
			}
			bad = append(bad, fmt.Sprintf("%s: %s (%s)", s.Source, s.Tag, prog))
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		reasons = append(reasons, "scriptlets other than an ldconfig refresh would run: "+strings.Join(bad, "; "))
	}

	if len(reasons) > 0 {
		return &SafetyError{Reasons: reasons}
	}
	return nil
}
