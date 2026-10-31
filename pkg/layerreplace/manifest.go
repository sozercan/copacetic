package layerreplace

import (
	"bytes"
	"encoding/json"
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/project-copacetic/copacetic/pkg/layersplit"
)

// replacement is a layer of the source image to be replaced.
type replacement struct {
	// Index is the index of the layer in the manifest and rootfs.diff_ids.
	Index int
	// Layer is the new layer.
	Layer v1.Layer
	// History is the index of the layer's config history entry, or -1.
	History int
	// Group is the group held by the new layer. Its history comment replaces
	// the old one when it differs.
	Group layersplit.Group
}

// rewriteImage returns the manifest and config of the source image with the
// given layers replaced. Everything else is kept: unchanged layer descriptors
// are copied verbatim, rootfs.diff_ids are updated at the replaced indexes, and
// the history comment of a replaced layer is updated if its group changed.
func rewriteImage(rawManifest, rawConfig []byte, repls []replacement) ([]byte, []byte, error) {
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return nil, nil, fmt.Errorf("parsing image config: %w", err)
	}
	var rootfs map[string]json.RawMessage
	if err := json.Unmarshal(cfg["rootfs"], &rootfs); err != nil {
		return nil, nil, fmt.Errorf("parsing image config rootfs: %w", err)
	}
	var diffIDs []string
	if err := json.Unmarshal(rootfs["diff_ids"], &diffIDs); err != nil {
		return nil, nil, fmt.Errorf("parsing image config diff_ids: %w", err)
	}
	var history []map[string]json.RawMessage
	if h, ok := cfg["history"]; ok {
		if err := json.Unmarshal(h, &history); err != nil {
			return nil, nil, fmt.Errorf("parsing image config history: %w", err)
		}
	}

	var manifest map[string]json.RawMessage
	if err := json.Unmarshal(rawManifest, &manifest); err != nil {
		return nil, nil, fmt.Errorf("parsing image manifest: %w", err)
	}
	var layers []json.RawMessage
	if err := json.Unmarshal(manifest["layers"], &layers); err != nil {
		return nil, nil, fmt.Errorf("parsing image manifest layers: %w", err)
	}
	if len(layers) != len(diffIDs) {
		return nil, nil, fmt.Errorf("image manifest has %d layers but config has %d diff_ids", len(layers), len(diffIDs))
	}

	for _, r := range repls {
		if r.Index < 0 || r.Index >= len(layers) {
			return nil, nil, fmt.Errorf("layer index %d out of range", r.Index)
		}
		var old v1.Descriptor
		if err := json.Unmarshal(layers[r.Index], &old); err != nil {
			return nil, nil, fmt.Errorf("parsing descriptor of layer %d: %w", r.Index, err)
		}
		digest, err := r.Layer.Digest()
		if err != nil {
			return nil, nil, err
		}
		size, err := r.Layer.Size()
		if err != nil {
			return nil, nil, err
		}
		diffID, err := r.Layer.DiffID()
		if err != nil {
			return nil, nil, err
		}
		// Annotations of the old descriptor describe the old blob, so they
		// are not carried over.
		desc, err := marshalJSON(v1.Descriptor{MediaType: old.MediaType, Size: size, Digest: digest})
		if err != nil {
			return nil, nil, err
		}
		layers[r.Index] = desc
		diffIDs[r.Index] = diffID.String()

		if r.History < 0 {
			continue
		}
		if r.History >= len(history) {
			return nil, nil, fmt.Errorf("history index %d out of range", r.History)
		}
		var oldComment string
		if c, ok := history[r.History]["comment"]; ok {
			if err := json.Unmarshal(c, &oldComment); err != nil {
				return nil, nil, fmt.Errorf("parsing history comment %d: %w", r.History, err)
			}
		}
		if comment := r.Group.HistoryComment(); comment != oldComment {
			if history[r.History]["comment"], err = marshalJSON(comment); err != nil {
				return nil, nil, err
			}
			if history[r.History]["created_by"], err = marshalJSON(r.Group.HistoryCreatedBy()); err != nil {
				return nil, nil, err
			}
		}
	}

	var err error
	if rootfs["diff_ids"], err = marshalJSON(diffIDs); err != nil {
		return nil, nil, err
	}
	if cfg["rootfs"], err = marshalJSON(rootfs); err != nil {
		return nil, nil, err
	}
	if history != nil {
		if cfg["history"], err = marshalJSON(history); err != nil {
			return nil, nil, err
		}
	}
	newConfig, err := marshalJSON(cfg)
	if err != nil {
		return nil, nil, err
	}

	var configDesc v1.Descriptor
	if err := json.Unmarshal(manifest["config"], &configDesc); err != nil {
		return nil, nil, fmt.Errorf("parsing config descriptor: %w", err)
	}
	configDesc.Digest, configDesc.Size, err = v1.SHA256(bytes.NewReader(newConfig))
	if err != nil {
		return nil, nil, err
	}
	if manifest["config"], err = marshalJSON(configDesc); err != nil {
		return nil, nil, err
	}
	if manifest["layers"], err = marshalJSON(layers); err != nil {
		return nil, nil, err
	}
	newManifest, err := marshalJSON(manifest)
	if err != nil {
		return nil, nil, err
	}
	return newManifest, newConfig, nil
}

// marshalJSON encodes v without HTML escaping so raw descriptors copied from
// the source manifest keep their content.
func marshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// assembledImage is an image made of a raw manifest and config plus the
// layers it references. Reused layers are the source image's own layer
// objects, so the registry client can skip or cross-repository mount them.
type assembledImage struct {
	manifest  []byte
	config    []byte
	mediaType types.MediaType
	layers    []v1.Layer
}

var _ v1.Image = (*assembledImage)(nil)

func (a *assembledImage) Layers() ([]v1.Layer, error)               { return a.layers, nil }
func (a *assembledImage) MediaType() (types.MediaType, error)       { return a.mediaType, nil }
func (a *assembledImage) Size() (int64, error)                      { return int64(len(a.manifest)), nil }
func (a *assembledImage) ConfigName() (v1.Hash, error)              { return partial.ConfigName(a) }
func (a *assembledImage) ConfigFile() (*v1.ConfigFile, error)       { return partial.ConfigFile(a) }
func (a *assembledImage) RawConfigFile() ([]byte, error)            { return a.config, nil }
func (a *assembledImage) Digest() (v1.Hash, error)                  { return partial.Digest(a) }
func (a *assembledImage) Manifest() (*v1.Manifest, error)           { return partial.Manifest(a) }
func (a *assembledImage) RawManifest() ([]byte, error)              { return a.manifest, nil }
func (a *assembledImage) LayerByDiffID(h v1.Hash) (v1.Layer, error) { return a.findLayer(h, true) }
func (a *assembledImage) LayerByDigest(h v1.Hash) (v1.Layer, error) {
	if cfg, err := a.ConfigName(); err == nil && cfg == h {
		return partial.ConfigLayer(a)
	}
	return a.findLayer(h, false)
}

func (a *assembledImage) findLayer(h v1.Hash, diffID bool) (v1.Layer, error) {
	for _, l := range a.layers {
		get := l.Digest
		if diffID {
			get = l.DiffID
		}
		if got, err := get(); err == nil && got == h {
			return l, nil
		}
	}
	return nil, fmt.Errorf("layer %s is not part of the image", h)
}

// assemble builds the patched image from the source image and replacements.
func assemble(src v1.Image, repls []replacement) (*assembledImage, error) {
	rawManifest, err := src.RawManifest()
	if err != nil {
		return nil, err
	}
	rawConfig, err := src.RawConfigFile()
	if err != nil {
		return nil, err
	}
	mt, err := src.MediaType()
	if err != nil {
		return nil, err
	}
	layers, err := src.Layers()
	if err != nil {
		return nil, err
	}
	manifest, config, err := rewriteImage(rawManifest, rawConfig, repls)
	if err != nil {
		return nil, err
	}

	out := make([]v1.Layer, len(layers))
	copy(out, layers)
	for _, r := range repls {
		out[r.Index] = r.Layer
	}
	return &assembledImage{manifest: manifest, config: config, mediaType: mt, layers: out}, nil
}
