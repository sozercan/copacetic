// ------------------------------------------------------------
// Copyright (c) Project Copacetic authors.
// Licensed under the MIT License.
// ------------------------------------------------------------

package langmgr

import (
	"context"
	"fmt"
	"strings"

	apkVer "github.com/knqyf263/go-apk-version"
	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
)

type pythonManager struct {
	config        *buildkit.Config
	workingFolder string
}

// Depending on go-apk-version lib for APK version comparison rules.
func isValidAPKVersion(v string) bool {
	return apkVer.Valid(v)
}

func isLessThanAPKVersion(v1, v2 string) bool {
	apkV1, _ := apkVer.NewVersion(v1)
	apkV2, _ := apkVer.NewVersion(v2)
	return apkV1.LessThan(apkV2)
}

func (pm *pythonManager) InstallUpdates(ctx context.Context, manifest *types.UpdateManifest, imageState *llb.State) (*llb.State, error) {
	// Resolve set of unique packages to update
	apkComparer := VersionComparer{isValidAPKVersion, isLessThanAPKVersion}
	updates, err := GetUniqueLatestUpdates(manifest.LangUpdates, apkComparer)
	if err != nil {
		return nil, err
	}
	if len(updates) == 0 {
		log.Warn("No update packages were specified to apply")
		return &pm.config.ImageState, nil
	}
	log.Debugf("latest unique pips: %v", updates)

	updatedImageState, err := pm.upgradePackages(ctx, updates, imageState)
	if err != nil {
		return nil, err
	}

	// Validate that the deployed packages are of the requested version or better
	// resultManifestPath := filepath.Join(pm.workingFolder, resultsPath, resultManifest)
	// if err := validatePythonPackageVersions(updates, apkComparer, resultManifestPath); err != nil {
	// 	return nil, err
	// }

	return updatedImageState, nil
}

// Patch a regular alpine image with:
//   - sh and apk installed on the image
//   - valid apk db state on the image
//
// TODO: support "distroless" Alpine images (e.g. APKO images)
// Still assumes that APK exists in the target image and is pathed, which can be addressed by
// mounting a copy of apk-tools-static into the image and invoking apk-static directly.
func (pm *pythonManager) upgradePackages(ctx context.Context, updates types.LangUpdatePackages, imageState *llb.State) (*llb.State, error) {
	// TODO: Add support for custom APK config
	pipUpdated := pm.config.ImageState.Run(llb.Shlex("pip check"), llb.WithProxy(utils.GetProxy())).Root()

	// Add all requested update packages
	// This works around cases where some packages (for example, tiff) require other packages in it's dependency tree to be updated
	// const apkAddTemplate = `apk add --no-cache %s`
	pkgStrings := []string{}
	for _, u := range updates {
		pkgStrings = append(pkgStrings, u.Name)
	}
	// addCmd := fmt.Sprintf(apkAddTemplate, strings.Join(pkgStrings, " "))
	// apkAdded := apkUpdated.Run(llb.Shlex(addCmd), llb.WithProxy(utils.GetProxy())).Root()

	// Install all requested update packages without specifying the version. This works around:
	//  - Reports being slightly out of date, where a newer security revision has displaced the one specified leading to not found errors.
	//  - Reports not specifying version epochs correct (e.g. bsdutils=2.36.1-8+deb11u1 instead of with epoch as 1:2.36.1-8+dev11u1)
	// Note that this keeps the log files from the operation, which we can consider removing as a size optimization in the future.
	const pipInstallTemplate = `pip install --upgrade %s`
	installCmd := fmt.Sprintf(pipInstallTemplate, strings.Join(pkgStrings, " "))
	pipInstalled := pm.config.ImageState.Run(llb.Shlex(installCmd), llb.WithProxy(utils.GetProxy())).Root()

	// Write updates-manifest to host for post-patch validation
	const outputResultsTemplate = `sh -c 'pip freeze %s > %s; if [[ $? -ne 0 ]]; then echo "WARN: pip freeze returned $?"; fi'`
	pkgs := strings.Trim(fmt.Sprintf("%s", pkgStrings), "[]")
	outputResultsCmd := fmt.Sprintf(outputResultsTemplate, pkgs, resultManifest)
	mkFolders := pipInstalled.File(llb.Mkdir(resultsPath, 0o744, llb.WithParents(true)))
	resultsWritten := mkFolders.Dir(resultsPath).Run(llb.Shlex(outputResultsCmd)).Root()
	resultsDiff := llb.Diff(pipInstalled, resultsWritten)

	if err := buildkit.SolveToLocal(ctx, pm.config.Client, &resultsDiff, pm.workingFolder); err != nil {
		return nil, err
	}

	// Diff the installed updates and merge that into the target image
	patchDiff := llb.Diff(pipUpdated, pipInstalled)
	patchMerge := llb.Merge([]llb.State{*imageState, patchDiff})
	return &patchMerge, nil
}
