package patch

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/ocilayout"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

func snapshotOSVersionSelectionLayout(t *testing.T, root string) map[string][]byte {
	t.Helper()
	files := make(map[string][]byte)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[relative] = data
		return nil
	})
	require.NoError(t, err)
	return files
}

func TestOCIIndexDescriptorOSVersionSelection(t *testing.T) {
	for _, order := range []struct {
		name     string
		versions []string
	}{
		{name: "ascending", versions: []string{"azurelinux-2.0", "azurelinux-3.0"}},
		{name: "descending", versions: []string{"azurelinux-3.0", "azurelinux-2.0"}},
	} {
		t.Run(order.name, func(t *testing.T) {
			root := t.TempDir()
			var manifests []ispec.Descriptor
			byVersion := make(map[string]ispec.Descriptor)
			var wantPlatforms []types.PatchPlatform
			for _, version := range order.versions {
				// Distinct configs/manifests, but only the descriptors declare os.version.
				desc := writeRepatchManifest(t, root, repatchChild{
					arch:                  "amd64",
					descriptorAnnotations: map[string]string{"example.descriptor": version},
				}, map[string]string{"example.config": version})
				desc.Platform.OSVersion = version
				manifests = append(manifests, desc)
				byVersion[version] = desc
				wantPlatforms = append(wantPlatforms, types.PatchPlatform{Platform: *desc.Platform})

				manifestData, err := os.ReadFile(filepath.Join(root, "blobs", desc.Digest.Algorithm().String(), desc.Digest.Encoded()))
				require.NoError(t, err)
				var manifest ispec.Manifest
				require.NoError(t, json.Unmarshal(manifestData, &manifest))
				configData, err := os.ReadFile(filepath.Join(root, "blobs", manifest.Config.Digest.Algorithm().String(), manifest.Config.Digest.Encoded()))
				require.NoError(t, err)
				var config map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(configData, &config))
				require.NotContains(t, config, "os.version", "the regression requires descriptor-only OS versions")
			}
			require.NotEqual(t, manifests[0].Digest, manifests[1].Digest)
			indexData, err := json.Marshal(map[string]any{
				"schemaVersion": 2,
				"mediaType":     ispec.MediaTypeImageIndex,
				"manifests":     manifests,
			})
			require.NoError(t, err)
			index := writeSolveTestBlob(t, root, ispec.MediaTypeImageIndex, indexData)
			writeRepatchLayout(t, root, &index)
			before := snapshotOSVersionSelectionLayout(t, root)
			t.Cleanup(func() {
				assert.Equal(t, before, snapshotOSVersionSelectionLayout(t, root), "selection must not change the source layout")
			})

			source, err := ocilayout.Open(t.Context(), root, "", "")
			require.NoError(t, err)
			require.Equal(t, index, source.Descriptor, "the selected image must be the index, not its first manifest")
			discovered, err := discoverPlatformsForOptions(t.Context(), &types.Options{OCISource: source})
			require.NoError(t, err)
			require.ElementsMatch(t, wantPlatforms, discovered, "discovery must retain both descriptor OS versions")
			report := &unversioned.UpdateManifest{Metadata: unversioned.Metadata{Config: unversioned.Config{Arch: "amd64"}}}

			for _, test := range []struct {
				name      string
				version   string
				wantError string
			}{
				{name: "underspecified", wantError: "matches 2 platforms"},
				{name: "version 2", version: "azurelinux-2.0"},
				{name: "version 3", version: "azurelinux-3.0"},
				{name: "unknown version", version: "azurelinux-4.0", wantError: "matches 0 platforms"},
			} {
				t.Run(test.name, func(t *testing.T) {
					target := ispec.Platform{OS: "linux", Architecture: "amd64", OSVersion: test.version}
					selector := "linux/amd64"
					if test.version != "" {
						selector = "linux(" + test.version + ")/amd64"
					}
					for _, selection := range []struct {
						name    string
						resolve func(*testing.T) (types.PatchPlatform, error)
					}{
						{
							name: "platform constraint",
							resolve: func(_ *testing.T) (types.PatchPlatform, error) {
								return resolveOCIPlatform(discovered, &target)
							},
						},
						{
							name: "CLI",
							resolve: func(t *testing.T) (types.PatchPlatform, error) {
								selected, err := filterOCIPlatforms(discovered, []string{selector})
								if err != nil {
									return types.PatchPlatform{}, err
								}
								require.Len(t, selected, 1)
								return selected[0], nil
							},
						},
						{
							name: "report",
							resolve: func(_ *testing.T) (types.PatchPlatform, error) {
								// Reports constrain the architecture; an explicit CLI version disambiguates it.
								var targets []string
								if test.version != "" {
									targets = []string{selector}
								}
								return resolveOCIReportPlatform(discovered, targets, report)
							},
						},
					} {
						t.Run(selection.name, func(t *testing.T) {
							selected, err := selection.resolve(t)
							if test.wantError != "" {
								require.ErrorContains(t, err, test.wantError)
								assert.ErrorContains(t, err, "azurelinux-2.0")
								assert.ErrorContains(t, err, "azurelinux-3.0")
								assert.Equal(t, types.PatchPlatform{}, selected, "a failed constraint must not select a manifest")
								return
							}
							require.NoError(t, err)
							want := byVersion[test.version]
							require.Equal(t, types.PatchPlatform{Platform: *want.Platform}, selected)
							actual, err := source.PlatformDescriptor(t.Context(), &selected.Platform)
							require.NoError(t, err)
							assert.Equal(t, want, *actual, "selection must retain the exact source digest, size, media type, platform and annotations")
						})
					}
				})
			}
		})
	}
}
