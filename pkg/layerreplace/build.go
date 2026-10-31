package layerreplace

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/common"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

// Paths inside the tooling container.
const (
	rootPath = "/copa/rootfs"
	outPath  = "/copa/out"
	prepPath = "/copa/prep"
)

// Files written by the prepare and apply steps.
const (
	installedFile  = "installed.tsv"
	downloadedFile = "downloaded.tsv"
	scriptsFile    = "scripts.txt"
	testOutputFile = "test.txt"
	testExitFile   = "test.rc"
	downloadLog    = "download.log"
	fileFlagsFile  = "fileflags.tsv"

	packagesFile = "packages.tsv"
	filesFile    = "files.tsv"
	verifyFile   = "verify.txt"
	resultFile   = "result.tsv"
	rootfsFile   = "rootfs.tar"

	maxDumpSize = int64(8 << 20)
)

// prepareScript downloads the updated RPMs for the image mounted at
// rootPath and collects what the safety checks need. It does not change the
// image: rootPath is a throwaway copy. The package names to update are the
// script arguments; with no arguments every package with an update is
// downloaded.
const prepareScript = `set -eu
root=` + rootPath + `
out=` + outPath + `
mkdir -p "$out/rpms"

rpm --root "$root" -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n' > "$out/` + installedFile + `"
# File flags and states tell whether the image was installed without docs.
rpm --root "$root" -qa --qf '[%{FILEFLAGS:fflags}\t%{FILESTATES:fstate}\n]' > "$out/` + fileFlagsFile + `"

# Only update packages that are installed in the image.
want=""
for p in "$@"; do
	if rpm --root "$root" -q "$p" > /dev/null 2>&1; then
		want="$want $p"
	else
		echo "skipping $p: not installed in the image" >&2
	fi
done

if [ "$#" -eq 0 ] || [ -n "$want" ]; then
	# The image has no repository configuration of its own; use the tooling
	# image's repositories.
	# shellcheck disable=SC2086
	if ! tdnf upgrade -y --downloadonly --downloaddir="$out/rpms" --installroot="$root" \
		--releasever="$RELEASEVER" --setopt=reposdir=/etc/yum.repos.d $want > "$out/` + downloadLog + `" 2>&1; then
		cat "$out/` + downloadLog + `" >&2
		exit 1
	fi
fi

: > "$out/` + downloadedFile + `"
: > "$out/` + scriptsFile + `"
set -- "$out"/rpms/*.rpm
[ -f "$1" ] || exit 0

for f in "$@"; do
	n=$(rpm -qp --nosignature --qf '%{NAME}' "$f")
	printf '%s\t' "$(basename "$f")" >> "$out/` + downloadedFile + `"
	rpm -qp --nosignature --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n' "$f" >> "$out/` + downloadedFile + `"
	{
		echo "@@@ new $n"
		rpm -qp --nosignature --scripts --triggers --filetriggers "$f"
		# The scriptlets of the installed version (for example %preun and
		# %postun) run during the upgrade too.
		echo "@@@ installed $n"
		if rpm --root "$root" -q "$n" > /dev/null 2>&1; then
			rpm --root "$root" -q --scripts "$n"
		fi
	} >> "$out/` + scriptsFile + `" 2> /dev/null
done

# Triggers of installed packages can fire on the upgrade.
for n in $(rpm --root "$root" -qa --qf '%{NAME}\n' | sort -u); do
	echo "@@@ trigger $n"
	rpm --root "$root" -q --triggers --filetriggers "$n" 2> /dev/null
done >> "$out/` + scriptsFile + `"

set +e
rpm --root "$root" -U --test "$@" > "$out/` + testOutputFile + `" 2>&1
echo $? > "$out/` + testExitFile + `"
`

// applyScript installs the RPMs prepared by prepareScript into the image
// mounted at rootPath, writes the RPM data used to classify files (the same
// queries as Dalec's targets/linux/rpm/distro/layers.go) and an archive of the
// upgraded root filesystem. The script arguments are the package names whose
// versions are validated against the scanner report.
const applyScript = `set -eu
root=` + rootPath + `
out=` + outPath + `

# shellcheck disable=SC2086
rpm --root "$root" -U $RPM_FLAGS ` + prepPath + `/rpms/*.rpm

rpm --root "$root" -qa --qf '%{NAME}\t%{SOURCERPM}\n' > "$out/` + packagesFile + `"
rpm --root "$root" -qa --qf '[%{=NAME}\t%{FILESTATES:fstate}\t%{FILEFLAGS:fflags}\t%{FILENAMES}\n]' > "$out/` + filesFile + `"
# rpm -V exits non-zero when it finds differences, which is expected.
rpm --root "$root" -Va --nodeps --noscripts > "$out/` + verifyFile + `" || true
: > "$out/` + resultFile + `"
if [ "$#" -gt 0 ]; then
	rpm --root "$root" -qa --qf '` + pkgmgr.RPMResultQueryFormat + `' "$@" > "$out/` + resultFile + `"
fi

tar --create --file "$out/` + rootfsFile + `" --directory "$root" \
	--format=posix --pax-option=delete=atime,delete=ctime \
	--numeric-owner --xattrs --xattrs-include='*' --sort=name .
`

// buildParams configures the BuildKit part of a replace run.
type buildParams struct {
	// ImageRef is the digest reference of the image to patch.
	ImageRef string
	Platform ispec.Platform
	// Packages are the package names to update; nil updates every package.
	Packages []string
	// ResultPackages are the package names whose versions are validated.
	ResultPackages []string
	// OutputDir receives the files written by the apply step.
	OutputDir string
}

// buildResult is what the BuildKit part of a replace run found.
type buildResult struct {
	OSInfo     *common.OSInfo
	Downloaded []rpmPackage
}

// runBuild prepares and checks the update in BuildKit and, if it is safe,
// applies it and exports the upgraded root filesystem and RPM data to
// p.OutputDir.
func runBuild(ctx context.Context, bkClient *client.Client, p *buildParams, progress chan *client.SolveStatus) (*buildResult, error) {
	solveOpt := authenticatedSolveOpt()
	solveOpt.Exports = []client.ExportEntry{{Type: client.ExporterLocal, OutputDir: p.OutputDir}}

	res := &buildResult{}
	// Errors returned from the build function reach the caller through
	// BuildKit and lose their type, so decisions are also kept here.
	var decision error
	_, err := bkClient.Build(ctx, solveOpt, "copa", func(ctx context.Context, c gwclient.Client) (*gwclient.Result, error) {
		platform := p.Platform
		image := llb.Image(p.ImageRef, llb.Platform(platform), llb.WithCustomName("Load image "+p.ImageRef))

		osRelease, err := common.ExtractOSReleaseFromState(ctx, c, &image)
		if err != nil {
			return nil, fmt.Errorf("reading /etc/os-release from the image: %w", err)
		}
		res.OSInfo, err = common.GetOSInfo(ctx, osRelease)
		if err != nil {
			return nil, fmt.Errorf("detecting the image OS: %w", err)
		}
		if res.OSInfo.Type != utils.OSTypeAzureLinux || !strings.HasPrefix(res.OSInfo.Version, "3.") {
			return nil, fmt.Errorf("replace mode supports Azure Linux 3 images, found %s %s", res.OSInfo.Type, res.OSInfo.Version)
		}
		releasever := strings.Join(strings.SplitN(res.OSInfo.Version, ".", 3)[:2], ".")

		tooling, toolingName, err := pkgmgr.ResolveRPMToolingImage(ctx, c, res.OSInfo.Type, res.OSInfo.Version, &platform)
		if err != nil {
			return nil, fmt.Errorf("resolving the RPM tooling image: %w", err)
		}
		log.Debugf("Using tooling image %s", toolingName)
		tooling = tooling.Run(
			llb.Args([]string{"tdnf", "install", "-y", "tar"}),
			llb.WithProxy(utils.GetProxy()),
			llb.WithCustomName("Install tooling"),
		).Root()

		prep := tooling.Run(
			llb.Args(append([]string{shell, "-c", prepareScript, "copa-prepare"}, p.Packages...)),
			llb.AddEnv("RELEASEVER", releasever),
			llb.AddMount(rootPath, image),
			llb.WithProxy(utils.GetProxy()),
			llb.WithCustomName("Download updates and collect safety check data"),
		).AddMount(outPath, llb.Scratch())

		prepRef, err := solve(ctx, c, &prep, &platform)
		if err != nil {
			return nil, err
		}
		in, err := readSafetyInput(ctx, prepRef)
		if err != nil {
			return nil, err
		}
		res.Downloaded = in.Downloaded
		if len(in.Downloaded) == 0 {
			decision = types.ErrNoUpdatesFound
			return nil, decision
		}
		for _, d := range in.Downloaded {
			log.Infof("Update available: %s %s (%s)", d.Name, d.EVR, d.Arch)
		}
		if err := checkSafety(in); err != nil {
			decision = err
			return nil, err
		}
		log.Info("Safety checks passed: all updates replace installed packages, dependencies resolve, scriptlets are ldconfig-only")

		rpmFlags := ""
		if in.ExcludeDocs {
			log.Info("The image was installed without documentation; installing updates with --excludedocs")
			rpmFlags = "--excludedocs"
		}
		applied := tooling.Run(
			llb.Args(append([]string{shell, "-c", applyScript, "copa-apply"}, p.ResultPackages...)),
			llb.AddMount(rootPath, image),
			llb.AddMount(prepPath, prep, llb.Readonly),
			llb.AddEnv("RPM_FLAGS", rpmFlags),
			llb.WithCustomName("Apply updates and archive the upgraded root filesystem"),
		).AddMount(outPath, llb.Scratch())

		def, err := applied.Marshal(ctx, llb.Platform(platform))
		if err != nil {
			return nil, err
		}
		return c.Solve(ctx, gwclient.SolveRequest{Definition: def.ToPB(), Evaluate: true})
	}, progress)
	if decision != nil {
		return res, decision
	}
	if err != nil {
		return res, err
	}
	return res, nil
}

func solve(ctx context.Context, c gwclient.Client, st *llb.State, platform *ispec.Platform) (gwclient.Reference, error) {
	def, err := st.Marshal(ctx, llb.Platform(*platform))
	if err != nil {
		return nil, err
	}
	r, err := c.Solve(ctx, gwclient.SolveRequest{Definition: def.ToPB(), Evaluate: true})
	if err != nil {
		return nil, err
	}
	return r.SingleRef()
}

func readSafetyInput(ctx context.Context, ref gwclient.Reference) (*safetyInput, error) {
	read := func(name string) ([]byte, error) {
		dt, err := buildkit.ReadFileWithLimit(ctx, ref, name, maxDumpSize)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", name, err)
		}
		return dt, nil
	}

	in := &safetyInput{}
	dt, err := read(installedFile)
	if err != nil {
		return nil, err
	}
	if in.Installed, err = parsePackages(bytes.NewReader(dt), false); err != nil {
		return nil, err
	}
	if dt, err = read(downloadedFile); err != nil {
		return nil, err
	}
	if in.Downloaded, err = parsePackages(bytes.NewReader(dt), true); err != nil {
		return nil, err
	}
	if len(in.Downloaded) == 0 {
		return in, nil
	}
	if dt, err = read(fileFlagsFile); err != nil {
		return nil, err
	}
	if in.ExcludeDocs, err = docsExcluded(bytes.NewReader(dt)); err != nil {
		return nil, err
	}
	if dt, err = read(scriptsFile); err != nil {
		return nil, err
	}
	if in.Scriptlets, err = parseScriptlets(bytes.NewReader(dt)); err != nil {
		return nil, err
	}
	if dt, err = read(testOutputFile); err != nil {
		return nil, err
	}
	in.TestOutput = string(dt)
	if dt, err = read(testExitFile); err != nil {
		return nil, err
	}
	if in.TestExitCode, err = strconv.Atoi(strings.TrimSpace(string(dt))); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", testExitFile, err)
	}
	return in, nil
}
