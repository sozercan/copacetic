package ocilayout

import (
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFullImageSelectorsRespectRepository(t *testing.T) {
	for _, test := range []struct {
		name          string
		selector      string
		targetName    string
		includeTarget bool
		wantError     string
	}{
		{name: "missing repository", selector: "nginx:latest", wantError: "unavailable"},
		{name: "familiar name", selector: "nginx:latest", targetName: "docker.io/library/nginx:latest", includeTarget: true},
		{name: "normalized name", selector: "docker.io/library/nginx:latest", targetName: "nginx:latest", includeTarget: true},
		{name: "untagged repository", selector: "nginx:latest", targetName: "docker.io/library/nginx", includeTarget: true},
		{name: "tag alias in same repository", selector: "nginx:latest", targetName: "docker.io/library/nginx:old", includeTarget: true},
		{name: "bare tag stays ambiguous", selector: "latest", targetName: "docker.io/library/nginx:latest", includeTarget: true, wantError: "2 descriptors"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			other := newImageManifest(t, root, &ocispec.Platform{OS: "linux", Architecture: "amd64"}, map[string]string{
				annotationImageName:       "docker.io/library/alpine:latest",
				ocispec.AnnotationRefName: "latest",
			}, nil)
			target := newImageManifest(t, root, &ocispec.Platform{OS: "linux", Architecture: "arm64"}, map[string]string{
				annotationImageName:       test.targetName,
				ocispec.AnnotationRefName: "latest",
			}, nil)
			descriptors := []ocispec.Descriptor{other}
			if test.includeTarget {
				descriptors = append(descriptors, target)
			}
			fixture := newLayoutAt(t, root, descriptors)
			source, err := Open(t.Context(), fixture.path, "", test.selector)
			if test.wantError != "" {
				require.ErrorContains(t, err, test.wantError)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, target.Digest, source.Descriptor.Digest)
		})
	}
}

func TestImageSelectorsNormalizeAnnotatedReferences(t *testing.T) {
	for _, key := range []string{annotationImageName, ocispec.AnnotationRefName} {
		t.Run(key, func(t *testing.T) {
			root := t.TempDir()
			first := newImageManifest(t, root, &ocispec.Platform{OS: "linux", Architecture: "amd64"}, map[string]string{
				key: "docker.io/nginx:latest",
			}, nil)
			second := newImageManifest(t, root, &ocispec.Platform{OS: "linux", Architecture: "arm64"}, map[string]string{
				key: "docker.io/library/nginx:latest",
			}, nil)
			alias := first
			alias.Annotations = map[string]string{key: "docker.io/library/nginx:latest"}
			for _, test := range []struct {
				name        string
				descriptors []ocispec.Descriptor
				ambiguous   bool
			}{
				{name: "single equivalent name", descriptors: []ocispec.Descriptor{first}},
				{name: "different images", descriptors: []ocispec.Descriptor{first, second}, ambiguous: true},
				{name: "reversed images", descriptors: []ocispec.Descriptor{second, first}, ambiguous: true},
				{name: "same image aliases", descriptors: []ocispec.Descriptor{first, alias}},
			} {
				t.Run(test.name, func(t *testing.T) {
					fixture := newLayoutAt(t, root, test.descriptors)
					before := snapshotLayout(t, root)
					for _, selector := range []string{"nginx:latest", "docker.io/nginx:latest", "docker.io/library/nginx:latest"} {
						source, err := Open(t.Context(), fixture.path, "", selector)
						if test.ambiguous {
							require.ErrorContains(t, err, "2 descriptors matching", "selector %s", selector)
							assert.ErrorContains(t, err, first.Digest.String())
							assert.ErrorContains(t, err, second.Digest.String())
						} else {
							require.NoError(t, err, "selector %s", selector)
							assert.Equal(t, first.Digest, source.Descriptor.Digest)
						}
					}
					assert.Equal(t, before, snapshotLayout(t, root))
				})
			}
		})
	}
}
