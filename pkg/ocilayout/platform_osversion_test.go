package ocilayout

import (
	"testing"

	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDescriptorOSVersionWithoutConfigOSVersion(t *testing.T) {
	for _, indexed := range []bool{false, true} {
		name := "manifest"
		if indexed {
			name = "index"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			configPlatform := ocispec.Platform{OS: "linux", Architecture: "amd64"}
			desc := newImageManifest(t, root, &configPlatform, map[string]string{"example.descriptor": "kept"}, nil)
			declared := configPlatform
			declared.OSVersion = "azurelinux-3.0"
			desc.Platform = &declared
			selected := desc
			if indexed {
				selected = writeBlob(t, root, ocispec.MediaTypeImageIndex, marshalJSON(t, ocispec.Index{
					Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{desc},
				}))
			}
			newLayoutAt(t, root, []ocispec.Descriptor{selected})
			before := snapshotLayout(t, root)

			source, err := Open(t.Context(), root, "", "")
			require.NoError(t, err)
			found, err := source.Platforms(t.Context())
			require.NoError(t, err)
			assert.Equal(t, []ocispec.Platform{declared}, found)
			actual, err := source.PlatformDescriptor(t.Context(), &declared)
			require.NoError(t, err)
			assert.Equal(t, desc, *actual)
			if !indexed {
				actual, err = source.PlatformDescriptor(t.Context(), nil)
				require.NoError(t, err)
				assert.Equal(t, desc, *actual)
			}
			for _, version := range []string{"", "azurelinux-2.0"} {
				target := declared
				target.OSVersion = version
				_, err := source.PlatformDescriptor(t.Context(), &target)
				require.Error(t, err, "lookup must still require the exact OS version")
			}
			manifest, err := source.selectedManifest(t.Context(), actual)
			require.NoError(t, err)
			actualConfig, err := source.configPlatform(t.Context(), &manifest.Config)
			require.NoError(t, err)
			assert.Equal(t, configPlatform, actualConfig, "the config must remain unmodified")

			copied, err := source.CopyPlatform(t.Context(), t.TempDir(), &declared, make(map[string]bool))
			require.NoError(t, err)
			assert.Equal(t, desc, *copied, "preserved images retain their descriptor metadata and blobs")
			assert.Equal(t, before, snapshotLayout(t, root))
		})
	}
}

func TestConfigOSVersionOmissionDoesNotHidePlatformConflicts(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*ocispec.Platform)
	}{
		{"OS", func(p *ocispec.Platform) { p.OS = "windows" }},
		{"architecture", func(p *ocispec.Platform) { p.Architecture = "amd64" }},
		{"variant", func(p *ocispec.Platform) { p.Variant = "v6" }},
		{"OS features", func(p *ocispec.Platform) { p.OSFeatures = []string{"other"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			platform := ocispec.Platform{OS: "linux", Architecture: "arm", Variant: "v7", OSFeatures: []string{"feature"}}
			desc := newImageManifest(t, root, &platform, nil, nil)
			declared := platform
			declared.OSVersion = "fixture.1"
			test.change(&declared)
			desc.Platform = &declared
			newLayoutAt(t, root, []ocispec.Descriptor{desc})
			_, err := Open(t.Context(), root, "", "")
			require.ErrorContains(t, err, "conflicts with image config platform")
		})
	}
}
