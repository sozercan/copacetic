package layerreplace

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/types"
)

func TestValidateOptions(t *testing.T) {
	reportFile := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, os.WriteFile(reportFile, []byte("{}"), 0o600))

	base := func() *types.Options {
		return &types.Options{Image: "example.com/app:1", Push: true, PkgTypes: "os", LayerMode: types.LayerModeReplace}
	}
	tests := []struct {
		name   string
		modify func(*types.Options)
		want   string
	}{
		{name: "valid", modify: func(*types.Options) {}},
		{name: "valid with report", modify: func(o *types.Options) { o.Report = reportFile }},
		{name: "push required", modify: func(o *types.Options) { o.Push = false }, want: "pass --push"},
		{name: "single platform", modify: func(o *types.Options) { o.Platforms = []string{"linux/amd64", "linux/arm64"} }, want: "single platform"},
		{name: "oci dir", modify: func(o *types.Options) { o.OCIDir = "out" }, want: "--oci-dir"},
		{name: "library packages", modify: func(o *types.Options) { o.PkgTypes = "os,library" }, want: "only patches OS packages"},
		{name: "toolchain", modify: func(o *types.Options) { o.ToolchainPatchLevel = "patch" }, want: "--toolchain-patch-level"},
		{name: "report directory", modify: func(o *types.Options) { o.Report = t.TempDir() }, want: "single report file"},
		{name: "missing report", modify: func(o *types.Options) { o.Report = filepath.Join(t.TempDir(), "missing.json") }, want: "report path"},
		{name: "image required", modify: func(o *types.Options) { o.Image = "" }, want: "requires --image"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := base()
			tt.modify(o)
			err := ValidateOptions(o)
			if tt.want == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tt.want)
		})
	}
}
