package layerreplace

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/containerd/platforms"
	"github.com/distribution/reference"
	"github.com/docker/cli/cli/config"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/compression"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/auth/authprovider"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/common"
	"github.com/project-copacetic/copacetic/pkg/layersplit"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/report"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/project-copacetic/copacetic/pkg/vex"
)

const flagHint = "--layers=" + types.LayerModeReplace

// for testing.
var newBuildkitClient = buildkit.NewClient

// ValidateOptions checks that opts can be used with the replace layers mode.
func ValidateOptions(opts *types.Options) error {
	switch {
	case opts.Image == "":
		return fmt.Errorf("%s requires --image", flagHint)
	case !opts.Push:
		return fmt.Errorf("%s assembles the patched image in the registry: pass --push", flagHint)
	case len(opts.Platforms) > 1:
		return fmt.Errorf("%s patches a single platform: pass at most one --platform", flagHint)
	case opts.OCIDir != "":
		return fmt.Errorf("%s cannot be used with --oci-dir", flagHint)
	case opts.PkgTypes != "" && opts.PkgTypes != utils.PkgTypeOS:
		return fmt.Errorf("%s only patches OS packages: --pkg-types must be %q", flagHint, utils.PkgTypeOS)
	case opts.ToolchainPatchLevel != "":
		return fmt.Errorf("%s cannot be used with --toolchain-patch-level", flagHint)
	case opts.ChiselRelease != "":
		return fmt.Errorf("%s cannot be used with --chisel-release", flagHint)
	}
	if opts.Report != "" {
		fi, err := os.Stat(opts.Report)
		if err != nil {
			return fmt.Errorf("report path %s: %w", opts.Report, err)
		}
		if fi.IsDir() {
			return fmt.Errorf("%s takes a single report file, not a directory", flagHint)
		}
	}
	return nil
}

// Run patches opts.Image by replacing the layers of the updated packages and
// the state layer, then pushes the result to the patched tag.
func Run(ctx context.Context, opts *types.Options) error {
	if err := ValidateOptions(opts); err != nil {
		return err
	}

	srcRef, err := name.ParseReference(opts.Image)
	if err != nil {
		return fmt.Errorf("parsing image reference %s: %w", opts.Image, err)
	}
	named, err := reference.ParseNormalizedNamed(opts.Image)
	if err != nil {
		return fmt.Errorf("parsing image reference %s: %w", opts.Image, err)
	}
	repo, tag, err := common.ResolvePatchedImageName(named, opts.PatchedTag, opts.Suffix)
	if err != nil {
		return err
	}
	dstRef, err := name.NewTag(repo + ":" + tag)
	if err != nil {
		return fmt.Errorf("parsing patched image reference: %w", err)
	}

	var reportManifest *unversioned.UpdateManifest
	var updates unversioned.UpdatePackages
	if opts.Report != "" {
		reportManifest, err = report.TryParseScanReport(opts.Report, opts.Scanner, utils.PkgTypeOS, opts.LibraryPatchLevel)
		if err != nil {
			return err
		}
		updates, err = pkgmgr.GetUniqueLatestUpdates(reportManifest.OSUpdates, pkgmgr.RPMVersionComparer(), opts.IgnoreError)
		if err != nil {
			return err
		}
		if len(updates) == 0 {
			return types.ErrNoUpdatesFound
		}
		if err := pkgmgr.ValidateOSPackageNames(updates); err != nil {
			return err
		}
	}

	remoteOpts := []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx)}
	src, platform, err := resolveSource(srcRef, opts.Platforms, reportManifest, remoteOpts)
	if err != nil {
		return err
	}
	srcDigest, err := src.Digest()
	if err != nil {
		return err
	}
	cfg, err := src.ConfigFile()
	if err != nil {
		return fmt.Errorf("reading image config: %w", err)
	}
	layout, err := ParseLayout(cfg)
	if err != nil {
		if errors.Is(err, ErrNotPerPackage) {
			return fmt.Errorf("%w; %s only works on images built by Dalec with image.layers set to per-package, run copa without it", err, flagHint)
		}
		return err
	}
	log.Infof("Image %s@%s (%s) has %d Dalec per-package layers out of %d",
		srcRef.Context(), srcDigest, platforms.Format(platform), len(layout.Layers), layout.NumLayers)

	workDir, cleanup, err := workingDir(opts.WorkingFolder)
	if err != nil {
		return err
	}
	defer cleanup()
	outDir := filepath.Join(workDir, "out")

	var pkgNames []string
	for _, u := range updates {
		pkgNames = append(pkgNames, u.Name)
	}
	params := &buildParams{
		ImageRef:       srcRef.Context().Digest(srcDigest.String()).String(),
		Platform:       platform,
		Packages:       pkgNames,
		ResultPackages: pkgNames,
		OutputDir:      outDir,
	}
	built, err := buildWithProgress(ctx, opts, params)
	if err != nil {
		return err
	}

	var errPkgs []string
	if updates != nil {
		results, err := os.ReadFile(filepath.Join(outDir, resultFile))
		if err != nil {
			return err
		}
		if errPkgs, err = pkgmgr.ValidateRPMPackageVersions(updates, results, opts.IgnoreError); err != nil {
			return err
		}
	}

	patched, summary, err := rebuildLayers(src, layout, outDir, workDir, built.Downloaded)
	if err != nil {
		return err
	}

	pushed, err := push(dstRef, patched, remoteOpts)
	if err != nil {
		return err
	}
	summary.Uploaded = pushed
	digest, err := patched.Digest()
	if err != nil {
		return err
	}
	summary.log()
	log.Infof("Patched image (%s): %s@%s", platforms.Format(platform), dstRef, digest)

	if reportManifest != nil && opts.Output != "" {
		validated := *reportManifest
		validated.OSUpdates = nil
		validated.LangUpdates = nil
		for _, u := range reportManifest.OSUpdates {
			if !contains(errPkgs, u.Name) {
				validated.OSUpdates = append(validated.OSUpdates, u)
			}
		}
		if len(validated.OSUpdates) > 0 {
			if err := vex.TryOutputVexDocument(&validated, "rpm", dstRef.Context().Digest(digest.String()).String(), opts.Format, opts.Output); err != nil {
				return err
			}
		}
	} else if opts.Output != "" {
		log.Warn("No vulnerability report was provided, so no VEX output will be generated.")
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// resolveSource returns the platform image to patch. Image indexes may hold a
// single platform image plus attestation manifests; any other multi-platform
// index requires --platform.
func resolveSource(ref name.Reference, wanted []string, rep *unversioned.UpdateManifest, opts []remote.Option) (v1.Image, ispec.Platform, error) {
	desc, err := remote.Get(ref, opts...)
	if err != nil {
		return nil, ispec.Platform{}, fmt.Errorf("fetching %s from the registry (%s needs the image in a registry): %w", ref, flagHint, err)
	}

	var want *ispec.Platform
	switch {
	case len(wanted) == 1:
		p, err := platforms.Parse(wanted[0])
		if err != nil {
			return nil, ispec.Platform{}, fmt.Errorf("parsing platform %q: %w", wanted[0], err)
		}
		want = &p
	case rep != nil && rep.Metadata.Config.Arch != "":
		want = &ispec.Platform{OS: "linux", Architecture: rep.Metadata.Config.Arch, Variant: rep.Metadata.Config.Variant}
	}

	var img v1.Image
	if desc.MediaType.IsIndex() {
		idx, err := desc.ImageIndex()
		if err != nil {
			return nil, ispec.Platform{}, err
		}
		im, err := idx.IndexManifest()
		if err != nil {
			return nil, ispec.Platform{}, err
		}
		var matches []v1.Descriptor
		for i := range im.Manifests {
			m := &im.Manifests[i]
			if !m.MediaType.IsImage() || m.Platform == nil || m.Platform.OS == "unknown" {
				continue
			}
			p := ispec.Platform{OS: m.Platform.OS, Architecture: m.Platform.Architecture, Variant: m.Platform.Variant}
			if want == nil || platforms.Only(*want).Match(p) {
				matches = append(matches, *m)
			}
		}
		if len(matches) != 1 {
			return nil, ispec.Platform{}, fmt.Errorf("%s has %d matching platform images; %s patches one platform, select it with --platform", ref, len(matches), flagHint)
		}
		if img, err = idx.Image(matches[0].Digest); err != nil {
			return nil, ispec.Platform{}, err
		}
	} else if img, err = desc.Image(); err != nil {
		return nil, ispec.Platform{}, err
	}

	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, ispec.Platform{}, err
	}
	p := platforms.Normalize(ispec.Platform{OS: cfg.OS, Architecture: cfg.Architecture, Variant: cfg.Variant})
	if want != nil && !platforms.Only(*want).Match(p) {
		return nil, ispec.Platform{}, fmt.Errorf("image platform %s does not match requested platform %s", platforms.Format(p), platforms.Format(*want))
	}
	return img, p, nil
}

func workingDir(dir string) (string, func(), error) {
	if dir == "" {
		d, err := os.MkdirTemp("", "copa-replace-*")
		if err != nil {
			return "", nil, err
		}
		return d, func() { removeUnlessDebug(d) }, nil
	}
	d, err := os.MkdirTemp(dir, "copa-replace-*")
	if err != nil {
		return "", nil, err
	}
	return d, func() { removeUnlessDebug(d) }, nil
}

func removeUnlessDebug(dir string) {
	if log.GetLevel() >= log.DebugLevel {
		log.Warnf("--debug specified, working folder at %s needs to be manually cleaned up", dir)
		return
	}
	os.RemoveAll(dir)
}

// authenticatedSolveOpt returns a solve option carrying the local Docker
// registry credentials, like the regular patch flow.
func authenticatedSolveOpt() client.SolveOpt {
	dockerConfig := config.LoadDefaultConfigFile(os.Stderr)
	authConfig := authprovider.DockerAuthProviderConfig{AuthConfigProvider: authprovider.LoadAuthConfig(dockerConfig)}
	return client.SolveOpt{Session: []session.Attachable{authprovider.NewDockerAuthProvider(authConfig)}}
}

func buildWithProgress(ctx context.Context, opts *types.Options, p *buildParams) (*buildResult, error) {
	bkClient, err := newBuildkitClient(ctx, buildkit.Opts{
		Addr:       opts.BkAddr,
		CACertPath: opts.BkCACertPath,
		CertPath:   opts.BkCertPath,
		KeyPath:    opts.BkKeyPath,
	})
	if err != nil {
		return nil, err
	}
	defer bkClient.Close()

	ch := make(chan *client.SolveStatus, 128)
	eg, egCtx := errgroup.WithContext(ctx)
	var res *buildResult
	eg.Go(func() error {
		var err error
		res, err = runBuild(egCtx, bkClient, p, ch)
		return err
	})
	common.DisplayProgress(egCtx, eg, ch, opts.Progress)
	if err := eg.Wait(); err != nil {
		return nil, err
	}
	return res, nil
}

// layerChange describes a replaced layer.
type layerChange struct {
	Index    int
	Group    layersplit.Group
	Old, New v1.Descriptor
}

// summary describes the patched image for the user.
type summary struct {
	Reused   int
	Replaced []layerChange
	Uploaded *pushStats
}

func (s *summary) log() {
	log.Infof("Reused %d layers unchanged; replaced %d:", s.Reused, len(s.Replaced))
	for i := range s.Replaced {
		c := &s.Replaced[i]
		what := c.Group.Kind + " " + c.Group.Name
		if len(c.Group.Packages) > 0 {
			what += " (" + strings.Join(c.Group.Packages, ", ") + ")"
		}
		log.Infof("  layer %d %s: %s (%d bytes) -> %s (%d bytes)", c.Index, what, c.Old.Digest, c.Old.Size, c.New.Digest, c.New.Size)
	}
	if u := s.Uploaded; u != nil {
		log.Infof("Uploaded %d bytes in %d blobs (layers and config); %d blobs already in the target repository, %d reused layers mounted or copied (%d bytes)",
			u.UploadedBytes, u.UploadedBlobs, u.ExistingBlobs, u.CopiedBlobs, u.CopiedBytes)
	}
}

// rebuildLayers classifies the upgraded root filesystem exported to outDir,
// writes new contents for the affected layers, assembles the patched image
// and verifies it against the upgraded root filesystem.
func rebuildLayers(src v1.Image, layout *Layout, outDir, workDir string, downloaded []rpmPackage) (*assembledImage, *summary, error) {
	in, err := readInputs(outDir, layout)
	if err != nil {
		return nil, nil, err
	}

	f, err := os.Open(filepath.Join(outDir, rootfsFile))
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	fs, err := indexRootFS(f, st.Size())
	if err != nil {
		return nil, nil, err
	}

	asg, err := classify(fs.Root(), in, layout)
	if err != nil {
		return nil, nil, err
	}
	var updated []string
	for _, d := range downloaded {
		updated = append(updated, d.Name)
	}
	affected := affectedLayers(updated, layout, asg)

	manifest, err := src.Manifest()
	if err != nil {
		return nil, nil, err
	}
	sum := &summary{Reused: layout.NumLayers - len(affected)}
	var repls []replacement
	for _, pos := range affected {
		li := layout.Layers[pos]
		old := manifest.Layers[li.Index]
		layer, err := writeLayerFile(fs, asg, pos, old.MediaType, filepath.Join(workDir, fmt.Sprintf("layer-%d.tar", li.Index)))
		if err != nil {
			return nil, nil, fmt.Errorf("writing layer %d (%s %s): %w", li.Index, li.Group.Kind, li.Group.Name, err)
		}
		group := li.Group
		if group.Kind != layersplit.KindState {
			group.Packages = asg.packages[pos]
		}
		repls = append(repls, replacement{Index: li.Index, Layer: layer, History: li.History, Group: group})

		digest, err := layer.Digest()
		if err != nil {
			return nil, nil, err
		}
		size, err := layer.Size()
		if err != nil {
			return nil, nil, err
		}
		sum.Replaced = append(sum.Replaced, layerChange{Index: li.Index, Group: group, Old: old, New: v1.Descriptor{Digest: digest, Size: size}})
	}

	patched, err := assemble(src, repls)
	if err != nil {
		return nil, nil, err
	}

	log.Info("Verifying the patched image against the upgraded root filesystem")
	fl := newFlattener()
	for i, l := range patched.layers {
		rc, err := l.Uncompressed()
		if err != nil {
			return nil, nil, fmt.Errorf("reading layer %d: %w", i, err)
		}
		err = fl.apply(rc)
		rc.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("reading layer %d: %w", i, err)
		}
	}
	if err := verifyTree(fs.Tree(), fl.tree); err != nil {
		return nil, nil, fmt.Errorf("%w\nThe image was not pushed. Run copa without %s to patch it by adding a layer instead", err, flagHint)
	}
	log.Infof("Verified: the patched image matches the upgraded root filesystem (%d entries)", len(fl.tree))
	return patched, sum, nil
}

func readInputs(outDir string, layout *Layout) (layersplit.Inputs, error) {
	in := layersplit.Inputs{App: layout.App}
	read := func(file string) (*bytes.Reader, error) {
		dt, err := os.ReadFile(filepath.Join(outDir, file))
		if err != nil {
			return nil, err
		}
		return bytes.NewReader(dt), nil
	}

	r, err := read(packagesFile)
	if err != nil {
		return in, err
	}
	if in.Packages, err = layersplit.ParseRPMPackages(r); err != nil {
		return in, fmt.Errorf("parsing %s: %w", packagesFile, err)
	}
	if r, err = read(filesFile); err != nil {
		return in, err
	}
	if in.Files, err = layersplit.ParseRPMFiles(r); err != nil {
		return in, fmt.Errorf("parsing %s: %w", filesFile, err)
	}
	if r, err = read(verifyFile); err != nil {
		return in, err
	}
	if in.Modified, err = layersplit.ParseRPMVerify(r); err != nil {
		return in, fmt.Errorf("parsing %s: %w", verifyFile, err)
	}
	return in, nil
}

// writeLayerFile writes the paths assigned to layer pos into an uncompressed
// tar file and returns it as a layer compressed like the layer it replaces.
func writeLayerFile(fs *rootFS, asg *assignment, pos int, mt ggcrtypes.MediaType, file string) (v1.Layer, error) {
	f, err := os.Create(file)
	if err != nil {
		return nil, err
	}
	// Dalec normalizes directory timestamps to SOURCE_DATE_EPOCH or 0.
	err = fs.writeLayer(f, func(p string) bool { return asg.layer[p] == pos }, time.Unix(0, 0))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	return newLayer(file, mt)
}

func newLayer(file string, mt ggcrtypes.MediaType) (v1.Layer, error) {
	opts := []tarball.LayerOption{tarball.WithMediaType(mt), tarball.WithCompressedCaching}
	switch mt {
	case ggcrtypes.OCILayer, ggcrtypes.DockerLayer:
		// Match the compression level BuildKit uses rather than ggcr's default of BestSpeed.
		opts = append(opts, tarball.WithCompressionLevel(gzip.DefaultCompression))
	case ggcrtypes.OCILayerZStd:
		opts = append(opts, tarball.WithCompression(compression.ZStd))
	default:
		return nil, fmt.Errorf("unsupported layer media type %s", mt)
	}
	return tarball.LayerFromFile(file, opts...)
}

// pushStats describes what a push transferred.
type pushStats struct {
	UploadedBlobs int
	UploadedBytes int64
	ExistingBlobs int
	CopiedBlobs   int
	CopiedBytes   int64
}

// push writes img to ref. Blobs already in the target repository are not
// uploaded again.
func push(ref name.Tag, img *assembledImage, opts []remote.Option) (*pushStats, error) {
	stats := &pushStats{}
	exists := func(h v1.Hash) bool {
		l, err := remote.Layer(ref.Context().Digest(h.String()), opts...)
		if err != nil {
			return false
		}
		_, err = l.Size()
		return err == nil
	}

	configName, err := img.ConfigName()
	if err != nil {
		return nil, err
	}
	if exists(configName) {
		stats.ExistingBlobs++
	} else {
		stats.UploadedBlobs++
		stats.UploadedBytes += int64(len(img.config))
	}
	for _, l := range img.layers {
		h, err := l.Digest()
		if err != nil {
			return nil, err
		}
		size, err := l.Size()
		if err != nil {
			return nil, err
		}
		switch {
		case exists(h):
			stats.ExistingBlobs++
		case isRemote(l):
			stats.CopiedBlobs++
			stats.CopiedBytes += size
		default:
			stats.UploadedBlobs++
			stats.UploadedBytes += size
		}
	}

	log.Infof("Pushing %s", ref)
	if err := remote.Write(ref, img, opts...); err != nil {
		return nil, fmt.Errorf("pushing %s: %w", ref, err)
	}
	return stats, nil
}

func isRemote(l v1.Layer) bool {
	_, ok := l.(*remote.MountableLayer)
	return ok
}
