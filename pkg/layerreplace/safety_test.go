package layerreplace

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scriptsDump is shaped like the output of the prepare step, using real
// `rpm -q --scripts --triggers --filetriggers` output from Azure Linux 3.
const scriptsDump = `@@@ new glibc
postinstall program: /sbin/ldconfig
postuninstall program: /sbin/ldconfig
@@@ installed glibc
postinstall program: /sbin/ldconfig
postuninstall program: /sbin/ldconfig
@@@ new bash
postinstall scriptlet (using /bin/sh):
if [ $1 -eq 1 ] ; then
    if [ ! -f "/root/.bash_logout" ] ; then
        cp /etc/skel/.bash_logout /root/.bash_logout
    fi
fi
@@@ installed bash
postinstall scriptlet (using /bin/sh):
echo installed
@@@ trigger zlib
triggerin scriptlet (using /bin/sh) -- glibc
/sbin/ldconfig
@@@ trigger foo
filetriggerin scriptlet (using <lua>) -- /usr/lib64
print("hi")
`

func TestParseScriptlets(t *testing.T) {
	got, err := parseScriptlets(strings.NewReader(scriptsDump))
	require.NoError(t, err)
	require.Len(t, got, 8)

	assert.Equal(t, scriptlet{Source: "new glibc", Tag: "postinstall", Prog: "/sbin/ldconfig"}, got[0])
	assert.Equal(t, "new bash", got[4].Source)
	assert.Equal(t, "/bin/sh", got[4].Prog)
	assert.Contains(t, got[4].Body, "cp /etc/skel/.bash_logout")
	assert.Equal(t, scriptlet{Source: "trigger zlib", Tag: "triggerin", Prog: "/bin/sh", Body: "/sbin/ldconfig"}, got[6])
	assert.Equal(t, "<lua>", got[7].Prog)

	_, err = parseScriptlets(strings.NewReader("garbage before any header\n"))
	assert.ErrorContains(t, err, "unexpected line")
}

func TestScriptletDecisions(t *testing.T) {
	tests := []struct {
		name     string
		s        scriptlet
		runs     bool
		ldconfig bool
	}{
		{"ldconfig program", scriptlet{Source: "new glibc", Tag: "postinstall", Prog: "/sbin/ldconfig"}, true, true},
		{"usr ldconfig program", scriptlet{Source: "new glibc", Tag: "postinstall", Prog: "/usr/sbin/ldconfig"}, true, true},
		{"ldconfig program with body", scriptlet{Source: "new x", Tag: "postinstall", Prog: "/sbin/ldconfig", Body: "-X"}, true, false},
		{"shell ldconfig", scriptlet{Source: "new x", Tag: "postinstall", Prog: "/bin/sh", Body: "# refresh\n/sbin/ldconfig\n"}, true, true},
		{"shell bare ldconfig", scriptlet{Source: "new x", Tag: "postuninstall", Prog: "/bin/sh", Body: "ldconfig"}, true, true},
		{"empty shell", scriptlet{Source: "new x", Tag: "pretrans", Prog: "/bin/sh"}, true, true},
		{"shell script", scriptlet{Source: "new x", Tag: "postinstall", Prog: "/bin/sh", Body: "/sbin/ldconfig\nrm -rf /tmp/x"}, true, false},
		{"lua", scriptlet{Source: "new x", Tag: "posttrans", Prog: "<lua>", Body: "posix.exec('/sbin/ldconfig')"}, true, false},
		{"other program", scriptlet{Source: "new x", Tag: "postinstall", Prog: "/usr/bin/systemctl"}, true, false},
		{"verify never runs", scriptlet{Source: "new x", Tag: "verify", Prog: "/bin/sh", Body: "exit 1"}, false, false},
		{"old postinstall does not run on upgrade", scriptlet{Source: "installed x", Tag: "postinstall", Prog: "/bin/sh", Body: "echo"}, false, false},
		{"old postuninstall runs on upgrade", scriptlet{Source: "installed x", Tag: "postuninstall", Prog: "/bin/sh", Body: "echo"}, true, false},
		{"old trigger runs", scriptlet{Source: "installed x", Tag: "triggerun", Prog: "/bin/sh", Body: "echo"}, true, false},
		{"installed file trigger runs", scriptlet{Source: "trigger y", Tag: "transfiletriggerin", Prog: "/bin/sh", Body: "echo"}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.runs, tt.s.runsOnUpgrade())
			if tt.runs {
				assert.Equal(t, tt.ldconfig, tt.s.ldconfigOnly())
			}
		})
	}
}

func TestCheckSafety(t *testing.T) {
	installed := []rpmPackage{
		{Name: "openssl", EVR: "0:3.3.5-5.azl3", Arch: "x86_64"},
		{Name: "openssl-libs", EVR: "0:3.3.5-5.azl3", Arch: "x86_64"},
		{Name: "tzdata", EVR: "0:2026c-1.azl3", Arch: "noarch"},
		{Name: "prebuilt-ca-certificates", EVR: "1:3.0.0-19.azl3", Arch: "noarch"},
	}
	ok := []rpmPackage{
		{Name: "openssl", EVR: "0:3.3.7-7.azl3", Arch: "x86_64"},
		{Name: "openssl-libs", EVR: "0:3.3.7-7.azl3", Arch: "x86_64"},
	}

	tests := []struct {
		name    string
		in      safetyInput
		reasons []string
	}{
		{
			name: "safe update",
			in: safetyInput{
				Installed: installed, Downloaded: ok,
				Scriptlets: []scriptlet{{Source: "new openssl-libs", Tag: "postinstall", Prog: "/sbin/ldconfig"}},
			},
		},
		{
			name: "new package",
			in: safetyInput{
				Installed:  installed,
				Downloaded: append(ok, rpmPackage{Name: "libxcrypt", EVR: "0:4.4.36-2.azl3", Arch: "x86_64"}),
			},
			reasons: []string{"libxcrypt 0:4.4.36-2.azl3 is not installed in the image"},
		},
		{
			name: "not newer",
			in: safetyInput{
				Installed:  installed,
				Downloaded: []rpmPackage{{Name: "openssl", EVR: "0:3.3.5-5.azl3", Arch: "x86_64"}},
			},
			reasons: []string{"openssl 0:3.3.5-5.azl3 is not newer than the installed 0:3.3.5-5.azl3"},
		},
		{
			name: "epoch makes an older looking version newer",
			in: safetyInput{
				Installed:  installed,
				Downloaded: []rpmPackage{{Name: "prebuilt-ca-certificates", EVR: "2:1.0.0-1.azl3", Arch: "noarch"}},
			},
		},
		{
			name: "epoch downgrade",
			in: safetyInput{
				Installed:  installed,
				Downloaded: []rpmPackage{{Name: "prebuilt-ca-certificates", EVR: "0:3.0.0-20.azl3", Arch: "noarch"}},
			},
			reasons: []string{"is not newer than the installed 1:3.0.0-19.azl3"},
		},
		{
			name: "architecture mismatch",
			in: safetyInput{
				Installed:  installed,
				Downloaded: []rpmPackage{{Name: "openssl", EVR: "0:3.3.7-7.azl3", Arch: "aarch64"}},
			},
			reasons: []string{"openssl.aarch64 0:3.3.7-7.azl3 does not match the installed architecture"},
		},
		{
			name: "dependency check fails",
			in: safetyInput{
				Installed: installed, Downloaded: ok,
				TestExitCode: 1,
				TestOutput:   "error: Failed dependencies:\n\tlibfoo.so.1 is needed by openssl-3.3.7-7.azl3.x86_64\n",
			},
			reasons: []string{"rpm -U --test failed against the image's package database: error: Failed dependencies"},
		},
		{
			name: "scriptlet",
			in: safetyInput{
				Installed: installed, Downloaded: ok,
				Scriptlets: []scriptlet{
					{Source: "new openssl", Tag: "postinstall", Prog: "/bin/sh", Body: "systemctl restart foo"},
					{Source: "installed openssl", Tag: "postinstall", Prog: "/bin/sh", Body: "does not run on upgrade"},
				},
			},
			reasons: []string{"scriptlets other than an ldconfig refresh would run: new openssl: postinstall (/bin/sh)"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkSafety(&tt.in)
			if len(tt.reasons) == 0 {
				assert.NoError(t, err)
				return
			}
			var se *SafetyError
			require.True(t, errors.As(err, &se), "got %v", err)
			require.Len(t, se.Reasons, len(tt.reasons))
			for i, r := range tt.reasons {
				assert.Contains(t, se.Reasons[i], r)
			}
			assert.Contains(t, err.Error(), "Run copa without --layers=replace")
		})
	}
}

func TestParsePackages(t *testing.T) {
	got, err := parsePackages(strings.NewReader("openssl\t0:3.3.5-5.azl3\tx86_64\n\ngpg-pubkey\t0:3135ce90-5e6fda74\t(none)\n"), false)
	require.NoError(t, err)
	assert.Equal(t, []rpmPackage{
		{Name: "openssl", EVR: "0:3.3.5-5.azl3", Arch: "x86_64"},
		{Name: "gpg-pubkey", EVR: "0:3135ce90-5e6fda74", Arch: "(none)"},
	}, got)

	got, err = parsePackages(strings.NewReader("openssl-3.3.7-7.azl3.x86_64.rpm\topenssl\t0:3.3.7-7.azl3\tx86_64\n"), true)
	require.NoError(t, err)
	assert.Equal(t, []rpmPackage{{Name: "openssl", EVR: "0:3.3.7-7.azl3", Arch: "x86_64"}}, got)

	_, err = parsePackages(strings.NewReader("openssl\t0:3.3.5-5.azl3\n"), false)
	assert.ErrorContains(t, err, "malformed")
}

func TestDocsExcluded(t *testing.T) {
	excluded, err := docsExcluded(strings.NewReader("\tnormal\nd\tnot installed\nc\tnormal\n"))
	require.NoError(t, err)
	assert.True(t, excluded)

	excluded, err = docsExcluded(strings.NewReader("\tnormal\nd\tnormal\n\tnot installed\n"))
	require.NoError(t, err)
	assert.False(t, excluded, "only documentation files count")
}
