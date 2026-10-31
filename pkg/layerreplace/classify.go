package layerreplace

import (
	"fmt"
	"sort"

	"github.com/project-copacetic/copacetic/pkg/layersplit"
)

// assignment maps the classified root filesystem onto the layers of an image.
type assignment struct {
	// layer maps each path to its position in Layout.Layers.
	layer map[string]int
	// packages maps a position in Layout.Layers to the sorted packages the
	// new classification puts in that layer.
	packages map[int][]string
	// groupLayer maps the index of a plan group to its position in Layout.Layers.
	groupLayer []int
}

// classify assigns every path of root to a layer of layout using Dalec's
// grouping rules. Groups are matched to existing layers by kind and name and,
// for groups Dalec folded into a combined "misc" layer, by package membership.
func classify(root layersplit.Root, in layersplit.Inputs, layout *Layout) (*assignment, error) {
	// Never fold groups: the set of layers is fixed by the existing image.
	plan, err := layersplit.BuildPlan(root, in, layersplit.Options{MaxLayers: len(root) + len(in.App) + 2})
	if err != nil {
		return nil, fmt.Errorf("classifying the upgraded root filesystem: %w", err)
	}

	a := &assignment{
		layer:      make(map[string]int, len(plan.Assign)),
		packages:   make(map[int][]string),
		groupLayer: make([]int, len(plan.Groups)),
	}
	pkgSets := make(map[int]map[string]bool)
	for gi, g := range plan.Groups {
		pos, err := layerForGroup(g, layout)
		if err != nil {
			return nil, err
		}
		a.groupLayer[gi] = pos
		if pkgSets[pos] == nil {
			pkgSets[pos] = make(map[string]bool)
		}
		for _, p := range g.Packages {
			pkgSets[pos][p] = true
		}
	}
	for pos, set := range pkgSets {
		pkgs := make([]string, 0, len(set))
		for p := range set {
			pkgs = append(pkgs, p)
		}
		sort.Strings(pkgs)
		a.packages[pos] = pkgs
	}
	for p, gi := range plan.Assign {
		a.layer[p] = a.groupLayer[gi]
	}
	return a, nil
}

func layerForGroup(g layersplit.Group, layout *Layout) (int, error) {
	if g.Kind == layersplit.KindState {
		return layout.State, nil
	}
	if pos, ok := layout.LayerForGroup(g.Kind, g.Name); ok {
		return pos, nil
	}

	// Dalec folds the smallest groups into a "misc" layer when an image has
	// more groups than its layer budget; find it through the packages.
	found := -1
	for _, p := range g.Packages {
		pos, ok := layout.LayerForPackage(p)
		if !ok {
			continue
		}
		if found >= 0 && found != pos {
			return 0, fmt.Errorf("packages of group %s:%s are spread over layers %d and %d of the image",
				g.Kind, g.Name, layout.Layers[found].Index, layout.Layers[pos].Index)
		}
		found = pos
	}
	if found < 0 {
		return 0, fmt.Errorf("files of package group %s:%s (%v) have no layer in the image; the update adds content the image layout does not have",
			g.Kind, g.Name, g.Packages)
	}
	return found, nil
}

// affectedLayers returns the positions in layout.Layers of the layers that
// must be rewritten when the given packages are updated: the layers that held
// the packages before the update, the layers that hold them after it, and the
// state layer. The result is sorted.
func affectedLayers(updated []string, layout *Layout, a *assignment) []int {
	set := map[int]bool{layout.State: true}
	for _, pkg := range updated {
		if pos, ok := layout.LayerForPackage(pkg); ok {
			set[pos] = true
		}
		for pos, pkgs := range a.packages {
			for _, p := range pkgs {
				if p == pkg {
					set[pos] = true
				}
			}
		}
	}
	out := make([]int, 0, len(set))
	for pos := range set {
		out = append(out, pos)
	}
	sort.Ints(out)
	return out
}
