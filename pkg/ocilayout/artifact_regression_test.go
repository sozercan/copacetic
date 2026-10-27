package ocilayout

import (
	"path/filepath"
	"testing"

	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLegacyArtifactsDoNotParticipateInImageSelection(t *testing.T) {
	for _, mediaType := range []string{ocispec.MediaTypeImageManifest, dockerMediaTypeManifest} {
		t.Run(mediaType, func(t *testing.T) {
			root := t.TempDir()
			platform := &ocispec.Platform{OS: "linux", Architecture: "amd64"}
			image := newImageManifest(t, root, platform, nil, nil)
			config := writeBlob(t, root, nonImageMediaType, []byte(`{}`))
			layer := writeBlob(t, root, nonImageMediaType, []byte("artifact data"))
			artifact := writeBlob(t, root, mediaType, marshalJSON(t, ocispec.Manifest{
				Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: mediaType,
				Config: config, Layers: []ocispec.Descriptor{layer},
			}))
			declaredPlatform := artifact
			declaredPlatform.Platform = platform
			for _, test := range []struct {
				name        string
				descriptors []ocispec.Descriptor
			}{
				{name: "top-level", descriptors: []ocispec.Descriptor{artifact, image}},
				{name: "index child without platform", descriptors: []ocispec.Descriptor{writeBlob(t, root, ocispec.MediaTypeImageIndex, marshalJSON(t, ocispec.Index{
					Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{artifact, image},
				}))}},
				{name: "index child with platform", descriptors: []ocispec.Descriptor{writeBlob(t, root, ocispec.MediaTypeImageIndex, marshalJSON(t, ocispec.Index{
					Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{declaredPlatform, image},
				}))}},
			} {
				t.Run(test.name, func(t *testing.T) {
					newLayoutAt(t, root, test.descriptors)
					before := snapshotLayout(t, root)
					source, err := Open(t.Context(), root, "", "")
					require.NoError(t, err)
					found, err := source.Platforms(t.Context())
					require.NoError(t, err)
					assert.Equal(t, []ocispec.Platform{*platform}, found)
					output := t.TempDir()
					desc, err := source.CopyPlatform(t.Context(), output, platform, make(map[string]bool))
					require.NoError(t, err)
					assert.Equal(t, image.Digest, desc.Digest)
					for _, blob := range []ocispec.Descriptor{artifact, config, layer} {
						assert.NoFileExists(t, filepath.Join(output, "blobs", blob.Digest.Algorithm().String(), blob.Digest.Encoded()))
					}
					assert.Equal(t, before, snapshotLayout(t, root))
				})
			}
			newLayoutAt(t, root, []ocispec.Descriptor{artifact, image})
			_, err := Open(t.Context(), root, "", artifact.Digest.String())
			require.ErrorContains(t, err, "unsupported config mediaType", "explicit artifact selection must still be rejected")
		})
	}
}

func TestMissingConfigMediaTypeRemainsAnImageCandidate(t *testing.T) {
	root := t.TempDir()
	image := newImageManifest(t, root, &ocispec.Platform{OS: "linux", Architecture: "amd64"}, nil, nil)
	malformed := writeBlob(t, root, ocispec.MediaTypeImageManifest, marshalJSON(t, ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
	}))
	newLayoutAt(t, root, []ocispec.Descriptor{image, malformed})
	_, err := Open(t.Context(), root, "", "")
	require.ErrorContains(t, err, "2 top-level images")
	_, err = Open(t.Context(), root, "", malformed.Digest.String())
	require.ErrorContains(t, err, "unsupported config mediaType")
}
