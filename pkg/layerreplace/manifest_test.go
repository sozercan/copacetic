package layerreplace

import (
	"bytes"
	"encoding/json"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/google/go-containerregistry/pkg/v1/validate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/layersplit"
)

// syntheticImage returns an OCI image with one random layer per history
// entry of demoHistory (skipping empty entries) and the per-package label.
func syntheticImage(t *testing.T) v1.Image {
	t.Helper()
	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, types.OCIConfigJSON)
	var adds []mutate.Addendum
	for _, h := range demoHistory() {
		if h.EmptyLayer {
			adds = append(adds, mutate.Addendum{History: h})
			continue
		}
		l, err := random.Layer(512, types.OCILayer)
		require.NoError(t, err)
		adds = append(adds, mutate.Addendum{Layer: l, History: h, Annotations: map[string]string{"keep": "me"}})
	}
	img, err := mutate.Append(img, adds...)
	require.NoError(t, err)

	cfg, err := img.ConfigFile()
	require.NoError(t, err)
	cfg = cfg.DeepCopy()
	cfg.Config.Labels = map[string]string{layersplit.LabelImageLayers: layersplit.ImageLayersPerPackage}
	cfg.Config.Entrypoint = []string{"/usr/bin/demo"}
	img, err = mutate.ConfigFile(img, cfg)
	require.NoError(t, err)
	return img
}

func rawLayers(t *testing.T, manifest []byte) []json.RawMessage {
	t.Helper()
	var m struct {
		Layers []json.RawMessage `json:"layers"`
	}
	require.NoError(t, json.Unmarshal(manifest, &m))
	return m.Layers
}

func TestAssembleReplacesOnlyAffectedLayers(t *testing.T) {
	src := syntheticImage(t)
	srcCfg, err := src.ConfigFile()
	require.NoError(t, err)
	layout, err := ParseLayout(srcCfg)
	require.NoError(t, err)
	srcManifest, err := src.RawManifest()
	require.NoError(t, err)

	openssl := layout.Layers[1]
	state := layout.StateLayer()
	newOpenssl, err := random.Layer(1024, types.OCILayer)
	require.NoError(t, err)
	newState, err := random.Layer(1024, types.OCILayer)
	require.NoError(t, err)

	opensslGroup := openssl.Group
	opensslGroup.Packages = []string{"openssl", "openssl-libs", "openssl-tools"}
	img, err := assemble(src, []replacement{
		{Index: openssl.Index, Layer: newOpenssl, History: openssl.History, Group: opensslGroup},
		{Index: state.Index, Layer: newState, History: state.History, Group: state.Group},
	})
	require.NoError(t, err)

	// The assembled image is internally consistent: manifest and config
	// digests, layer digests and diff_ids all match.
	require.NoError(t, validate.Image(img))

	oldRaw := rawLayers(t, srcManifest)
	newRaw := rawLayers(t, img.manifest)
	require.Len(t, newRaw, len(oldRaw))
	for i := range oldRaw {
		if i == openssl.Index || i == state.Index {
			assert.NotEqual(t, oldRaw[i], newRaw[i], "layer %d must be replaced", i)
			continue
		}
		assert.Equal(t, string(compact(t, oldRaw[i])), string(newRaw[i]), "layer %d descriptor must be unchanged", i)
	}

	m, err := img.Manifest()
	require.NoError(t, err)
	newDigest, _ := newOpenssl.Digest()
	assert.Equal(t, newDigest, m.Layers[openssl.Index].Digest)
	assert.Equal(t, types.OCILayer, m.Layers[openssl.Index].MediaType)
	assert.Nil(t, m.Layers[openssl.Index].Annotations, "annotations of the old blob are dropped")
	assert.Equal(t, map[string]string{"keep": "me"}, m.Layers[0].Annotations)

	cfg, err := img.ConfigFile()
	require.NoError(t, err)
	newDiffID, _ := newOpenssl.DiffID()
	newStateDiffID, _ := newState.DiffID()
	for i, d := range cfg.RootFS.DiffIDs {
		switch i {
		case openssl.Index:
			assert.Equal(t, newDiffID, d)
		case state.Index:
			assert.Equal(t, newStateDiffID, d)
		default:
			assert.Equal(t, srcCfg.RootFS.DiffIDs[i], d)
		}
	}

	// The comment changes only where the group changed.
	assert.Equal(t, "dalec.layer.v1 kind=os name=openssl packages=openssl,openssl-libs,openssl-tools", cfg.History[openssl.History].Comment)
	assert.Equal(t, "dalec: files from openssl, openssl-libs, openssl-tools", cfg.History[openssl.History].CreatedBy)
	assert.Equal(t, srcCfg.History[state.History], cfg.History[state.History])
	assert.Equal(t, srcCfg.History[1], cfg.History[1])
	assert.Equal(t, srcCfg.Config, cfg.Config)

	// Reused layers are the source image's own layer objects.
	srcLayers, err := src.Layers()
	require.NoError(t, err)
	assert.Same(t, srcLayers[0], img.layers[0])
	assert.Same(t, newOpenssl, img.layers[openssl.Index])
}

func compact(t *testing.T, raw []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	require.NoError(t, json.Compact(&b, raw))
	return b.Bytes()
}

func TestRewriteImageErrors(t *testing.T) {
	src := syntheticImage(t)
	rawManifest, err := src.RawManifest()
	require.NoError(t, err)
	rawConfig, err := src.RawConfigFile()
	require.NoError(t, err)
	l, err := random.Layer(16, types.OCILayer)
	require.NoError(t, err)

	_, _, err = rewriteImage(rawManifest, rawConfig, []replacement{{Index: 99, Layer: l, History: -1}})
	assert.ErrorContains(t, err, "out of range")

	_, _, err = rewriteImage(rawManifest, rawConfig, []replacement{{Index: 0, Layer: l, History: 99}})
	assert.ErrorContains(t, err, "history index 99 out of range")

	_, _, err = rewriteImage([]byte("{"), rawConfig, nil)
	assert.ErrorContains(t, err, "parsing image manifest")
}
