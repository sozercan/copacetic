package layerreplace

import (
	"errors"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/layersplit"
)

func perPackageConfig(history []v1.History, layers int) *v1.ConfigFile {
	cfg := &v1.ConfigFile{History: history}
	cfg.Config.Labels = map[string]string{layersplit.LabelImageLayers: layersplit.ImageLayersPerPackage}
	for range layers {
		cfg.RootFS.DiffIDs = append(cfg.RootFS.DiffIDs, v1.Hash{Algorithm: "sha256", Hex: "00"})
	}
	return cfg
}

// demoHistory mirrors the history of a real Dalec per-package image: Dalec
// layers followed by empty layers BuildKit adds after the image is built.
func demoHistory() []v1.History {
	return []v1.History{
		{Comment: "dalec.layer.v1 kind=os name=glibc packages=glibc"},
		{EmptyLayer: true, Comment: "ENV FOO=bar"},
		{Comment: "dalec.layer.v1 kind=os name=openssl packages=openssl,openssl-libs"},
		{Comment: "dalec.layer.v1 kind=os name=misc packages=bzip2-libs,zlib"},
		{Comment: "dalec.layer.v1 kind=app name=layers-demo packages=layers-demo"},
		{Comment: "dalec.layer.v1 kind=state name=state"},
		{Comment: "buildkit.exporter.image.v0"},
		{Comment: "buildkit.exporter.image.v0"},
	}
}

func TestParseLayout(t *testing.T) {
	l, err := ParseLayout(perPackageConfig(demoHistory(), 7))
	require.NoError(t, err)

	assert.Equal(t, 7, l.NumLayers)
	require.Len(t, l.Layers, 5)
	// The empty history entry does not count as a layer.
	assert.Equal(t, LayerInfo{Index: 1, History: 2, Group: layersplit.Group{Kind: "os", Name: "openssl", Packages: []string{"openssl", "openssl-libs"}}}, l.Layers[1])
	assert.Equal(t, 4, l.StateLayer().Index)
	assert.Equal(t, 5, l.StateLayer().History)
	assert.Equal(t, map[string]bool{"layers-demo": true}, l.App)

	pos, ok := l.LayerForPackage("openssl-libs")
	assert.True(t, ok)
	assert.Equal(t, 1, pos)
	pos, ok = l.LayerForGroup("os", "misc")
	assert.True(t, ok)
	assert.Equal(t, 2, pos)
	_, ok = l.LayerForPackage("bash")
	assert.False(t, ok)
}

func TestParseLayoutErrors(t *testing.T) {
	tests := []struct {
		name    string
		cfg     func() *v1.ConfigFile
		want    string
		notPerP bool
	}{
		{
			name: "no label",
			cfg: func() *v1.ConfigFile {
				c := perPackageConfig(demoHistory(), 7)
				c.Config.Labels = nil
				return c
			},
			want: "label dev.dalec.image.layers is not set", notPerP: true,
		},
		{
			name: "other layers mode",
			cfg: func() *v1.ConfigFile {
				c := perPackageConfig(demoHistory(), 7)
				c.Config.Labels[layersplit.LabelImageLayers] = "single"
				return c
			},
			want: `is "single"`, notPerP: true,
		},
		{
			name: "no dalec comments",
			cfg: func() *v1.ConfigFile {
				return perPackageConfig([]v1.History{{Comment: "buildkit.exporter.image.v0"}}, 1)
			},
			want: "no layer has a dalec.layer.v1 history comment", notPerP: true,
		},
		{
			name: "no state layer",
			cfg: func() *v1.ConfigFile {
				return perPackageConfig([]v1.History{{Comment: "dalec.layer.v1 kind=os name=glibc packages=glibc"}}, 1)
			},
			want: "no state layer", notPerP: true,
		},
		{
			name: "history does not match layers",
			cfg:  func() *v1.ConfigFile { return perPackageConfig(demoHistory(), 8) },
			want: "describes 7 layers but the image has 8",
		},
		{
			name: "package in two layers",
			cfg: func() *v1.ConfigFile {
				return perPackageConfig([]v1.History{
					{Comment: "dalec.layer.v1 kind=os name=a packages=x"},
					{Comment: "dalec.layer.v1 kind=os name=b packages=x"},
					{Comment: "dalec.layer.v1 kind=state name=state"},
				}, 3)
			},
			want: "package x is listed in layers 0 and 1",
		},
		{
			name: "unknown kind",
			cfg: func() *v1.ConfigFile {
				return perPackageConfig([]v1.History{{Comment: "dalec.layer.v1 kind=weird name=a"}}, 1)
			},
			want: "unknown Dalec layer kind",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseLayout(tt.cfg())
			require.Error(t, err)
			assert.ErrorContains(t, err, tt.want)
			assert.Equal(t, tt.notPerP, errors.Is(err, ErrNotPerPackage))
		})
	}
}
