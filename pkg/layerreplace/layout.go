// Package layerreplace implements the experimental "replace layers" patch mode
// for images built by Dalec with one layer per package (`image.layers:
// per-package`). Instead of adding a patch layer on top of the image, it
// replaces the layers of the updated packages and the final state layer in the
// existing image, reuses every other layer blob as-is, and pushes the result.
package layerreplace

import (
	"errors"
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/project-copacetic/copacetic/pkg/layersplit"
)

// ErrNotPerPackage is returned for images that do not use Dalec's
// per-package layer layout.
var ErrNotPerPackage = errors.New("image does not use Dalec per-package layers")

// LayerInfo describes one Dalec layer of an image.
type LayerInfo struct {
	// Index is the index of the layer in the image manifest and rootfs.diff_ids.
	Index int
	// History is the index of the layer's entry in the image config history.
	History int
	// Group is the group parsed from the layer's history comment.
	Group layersplit.Group
}

// Layout is the per-package layer layout of an image, parsed from its config.
type Layout struct {
	// Layers lists the Dalec layers in image order.
	Layers []LayerInfo
	// State is the position in Layers of the state layer.
	State int
	// NumLayers is the total number of layers in the image, including layers
	// that were not written by Dalec (for example trailing empty layers).
	NumLayers int
	// App is the set of packages built from the Dalec spec.
	App map[string]bool

	byPackage map[string]int
	byGroup   map[string]int
}

// ParseLayout reads the Dalec per-package layer layout from an image config.
// Layers are identified by their history comment, never by position; layers
// without a Dalec comment (such as trailing empty layers added by BuildKit)
// are left out of the layout but counted in NumLayers.
func ParseLayout(cfg *v1.ConfigFile) (*Layout, error) {
	if cfg == nil {
		return nil, errors.New("image has no config")
	}
	if v := cfg.Config.Labels[layersplit.LabelImageLayers]; v != layersplit.ImageLayersPerPackage {
		if v == "" {
			return nil, fmt.Errorf("%w: label %s is not set", ErrNotPerPackage, layersplit.LabelImageLayers)
		}
		return nil, fmt.Errorf("%w: label %s is %q, want %q", ErrNotPerPackage, layersplit.LabelImageLayers, v, layersplit.ImageLayersPerPackage)
	}

	l := &Layout{
		State:     -1,
		NumLayers: len(cfg.RootFS.DiffIDs),
		App:       make(map[string]bool),
		byPackage: make(map[string]int),
		byGroup:   make(map[string]int),
	}

	layer := 0
	for i, h := range cfg.History {
		if h.EmptyLayer {
			continue
		}
		idx := layer
		layer++

		g, ok := layersplit.ParseHistoryComment(h.Comment)
		if !ok {
			continue
		}
		if idx >= l.NumLayers {
			return nil, fmt.Errorf("history entry %d (%q) has no matching layer: the image has %d layers", i, h.Comment, l.NumLayers)
		}

		key := groupKey(g.Kind, g.Name)
		if prev, dup := l.byGroup[key]; dup {
			return nil, fmt.Errorf("layers %d and %d both hold Dalec group %s", l.Layers[prev].Index, idx, key)
		}
		pos := len(l.Layers)
		l.byGroup[key] = pos
		l.Layers = append(l.Layers, LayerInfo{Index: idx, History: i, Group: g})

		switch g.Kind {
		case layersplit.KindState:
			l.State = pos
		case layersplit.KindOS, layersplit.KindApp:
		default:
			return nil, fmt.Errorf("layer %d has unknown Dalec layer kind %q", idx, g.Kind)
		}
		for _, p := range g.Packages {
			if prev, dup := l.byPackage[p]; dup {
				return nil, fmt.Errorf("package %s is listed in layers %d and %d", p, l.Layers[prev].Index, idx)
			}
			l.byPackage[p] = pos
			if g.Kind == layersplit.KindApp {
				l.App[p] = true
			}
		}
	}
	if layer != l.NumLayers {
		return nil, fmt.Errorf("image history describes %d layers but the image has %d; cannot map Dalec layers", layer, l.NumLayers)
	}
	if len(l.Layers) == 0 {
		return nil, fmt.Errorf("%w: no layer has a %s history comment", ErrNotPerPackage, layersplit.HistoryCommentPrefix)
	}
	if l.State < 0 {
		return nil, fmt.Errorf("%w: no state layer found in the image history", ErrNotPerPackage)
	}
	return l, nil
}

// StateLayer returns the state layer.
func (l *Layout) StateLayer() LayerInfo {
	return l.Layers[l.State]
}

// LayerForPackage returns the position in Layers of the layer listing pkg.
func (l *Layout) LayerForPackage(pkg string) (int, bool) {
	i, ok := l.byPackage[pkg]
	return i, ok
}

// LayerForGroup returns the position in Layers of the layer holding the group
// with the given kind and name.
func (l *Layout) LayerForGroup(kind, name string) (int, bool) {
	i, ok := l.byGroup[groupKey(kind, name)]
	return i, ok
}

func groupKey(kind, name string) string {
	return kind + ":" + name
}
