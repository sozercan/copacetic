// ------------------------------------------------------------
// Copyright (c) Project Copacetic authors.
// Licensed under the MIT License.
// ------------------------------------------------------------

package report

import (
	"encoding/json"
	"errors"
	"os"
	"strings"

	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/davecgh/go-spew/spew"
	"github.com/project-copacetic/copacetic/pkg/types"
)

type TrivyParser struct{}

func parseTrivyReport(file string) (*trivyTypes.Report, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var msr trivyTypes.Report
	if err = json.Unmarshal(data, &msr); err != nil {
		return nil, &ErrorUnsupported{err}
	}
	return &msr, nil
}

func (t *TrivyParser) Parse(file string) (*types.UpdateManifest, error) {
	report, err := parseTrivyReport(file)
	if err != nil {
		return nil, err
	}

	// Precondition check
	result := trivyTypes.Result{}
	for i := range report.Results {
		r := &report.Results[i]
		if r.Class == "os-pkgs" {
			if result.Class != "" {
				return nil, errors.New("unexpected multiple results for os-pkgs")
			}
			result = *r
		}
		if r.Class == "lang-pkgs" {
			if r.Target == "Python" {
				// if result.Class != "" {
				// 	return nil, errors.New("unexpected multiple results for lang-pkgs")
				// }
				result = *r
			}
		}
	}
	if result.Class == "" {
		return nil, errors.New("no scanning results for os-pkgs or lang-pkgs found")
	}

	updates := types.UpdateManifest{
		OSType:    report.Metadata.OS.Family,
		OSVersion: report.Metadata.OS.Name,
		Arch:      report.Metadata.ImageConfig.Architecture,
	}

	for i := range result.Vulnerabilities {
		vuln := &result.Vulnerabilities[i]
		if vuln.FixedVersion != "" {

			if strings.Contains(vuln.FixedVersion, ",") {
				splitVersions := strings.Split(vuln.FixedVersion, ",")
				vuln.FixedVersion = strings.TrimSpace(splitVersions[0])
			}

			updates.Updates = append(updates.Updates, types.UpdatePackage{Name: vuln.PkgName, Version: vuln.FixedVersion})
			spew.Dump(updates)
		}
	}

	return &updates, nil
}
