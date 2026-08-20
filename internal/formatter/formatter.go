package formatter

import (
	"fmt"
	"strings"

	"github.com/user/cvechecker/internal/i18n"
	"github.com/user/cvechecker/internal/models"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
	colorCyan   = "\033[36m"
	colorMagenta = "\033[35m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

func PrintBanner() {
	fmt.Printf(`
%s╔══════════════════════════════════════════╗
║        🔍 CVE Checker v1.0.0             ║
║    Server Vulnerability Scanner          ║
╚══════════════════════════════════════════╝%s
`, colorCyan, colorReset)
}

func PrintOSInfo(info models.OSInfo) {
	fmt.Printf("\n%s[%s]%s\n", colorBold, i18n.Labels.OSInfo(), colorReset)
	fmt.Printf("  OS     : %s\n", info.Name)
	fmt.Printf("  Version: %s\n", info.Version)
	fmt.Printf("  Arch   : %s\n", info.Arch)
}

func PrintPackageList(packages []models.Package) {
	if len(packages) == 0 {
		fmt.Printf("\n%s[!] %s%s\n", colorYellow, i18n.Labels.NoPackages(), colorReset)
		return
	}

	byManager := make(map[string][]models.Package)
	for _, p := range packages {
		byManager[p.Manager] = append(byManager[p.Manager], p)
	}

	for manager, pkgs := range byManager {
		fmt.Printf("\n%s[Package Manager: %s] %d packages detected%s\n", colorBold, strings.ToUpper(manager), len(pkgs), colorReset)

		limit := 20
		if len(pkgs) < limit {
			limit = len(pkgs)
		}
		for i := 0; i < limit; i++ {
			fmt.Printf("  %s%-30s%s  %s\n", colorGreen, pkgs[i].Name, colorReset, pkgs[i].Version)
		}
		if len(pkgs) > 20 {
			fmt.Printf("  %s... and %d more packages%s\n", colorDim, len(pkgs)-20, colorReset)
		}
	}

	fmt.Printf("\n  %sTotal: %d packages%s\n", colorBold, len(packages), colorReset)
}

func PrintVulnerabilityResults(vulns map[string][]models.CVEDetail) {
	if len(vulns) == 0 {
		fmt.Printf("\n%s[✓] %s%s\n", colorGreen, i18n.Labels.NoCVEFound(), colorReset)
		return
	}

	critical, high, medium, low := 0, 0, 0, 0

	fmt.Printf("\n%s[⚠ Vulnerability Results]%s\n", colorBold, colorReset)
	fmt.Println(strings.Repeat("─", 60))

	for pkg, cves := range vulns {
		fmt.Printf("\n📦 %s%s%s (%d CVEs)\n", colorBold, pkg, colorReset, len(cves))

		for _, cve := range cves {
			severityColor := colorGreen
			switch cve.Severity {
			case "CRITICAL":
				severityColor = colorRed
				critical++
			case "HIGH":
				severityColor = colorRed
				high++
			case "MEDIUM":
				severityColor = colorYellow
				medium++
			case "LOW":
				severityColor = colorGreen
				low++
			}

			desc := cve.Description
			if len(desc) > 120 {
				desc = desc[:117] + "..."
			}

			fmt.Printf("  %s%-10s%s %s (Score: %.1f)\n", severityColor, cve.Severity, colorReset, cve.ID, cve.Score)
			fmt.Printf("    %s%s%s\n", colorDim, desc, colorReset)
			fmt.Printf("    %s%s%s\n", colorCyan, cve.URL, colorReset)

			printSolution(cve)
			fmt.Println()
		}
	}

	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("\n%s[%s]%s\n", colorBold, i18n.Labels.Summary(), colorReset)
	fmt.Printf("  🔴 %s : %d\n", i18n.Labels.Critical(), critical)
	fmt.Printf("  🟠 %s     : %d\n", i18n.Labels.High(), high)
	fmt.Printf("  🟡 %s   : %d\n", i18n.Labels.Medium(), medium)
	fmt.Printf("  🟢 %s      : %d\n", i18n.Labels.Low(), low)
	fmt.Printf("  📊 %s    : %d\n", i18n.Labels.Total(), critical+high+medium+low)
}

func printSolution(cve models.CVEDetail) {
	sol := cve.Solution

	if sol.FixVersion != "" {
		fmt.Printf("    %s🔧 %s:%s %s\n", colorGreen, i18n.Labels.FixVersion(), colorReset, sol.FixVersion)
	}

	if sol.UpgradeCmd != "" {
		fmt.Printf("    %s💡 %s:%s %s\n", colorMagenta, i18n.Labels.Run(), colorReset, sol.UpgradeCmd)
	}

	if sol.Description != "" {
		fmt.Printf("    %s📋 %s:%s %s\n", colorGreen, i18n.Labels.Solution(), colorReset, sol.Description)
	}

	if len(sol.References) > 0 {
		fmt.Printf("    %s🔗 %s:%s\n", colorCyan, i18n.Labels.Patches(), colorReset)
		limit := len(sol.References)
		if limit > 3 {
			limit = 3
		}
		for _, ref := range sol.References[:limit] {
			fmt.Printf("       • %s\n", ref)
		}
	}

	if sol.Workaround != "" {
		fmt.Printf("    %s⚠ %s:%s %s\n", colorYellow, i18n.Labels.Workaround(), colorReset, sol.Workaround)
	}
}

func PrintScanProgress(msg string) {
	fmt.Printf("  %s→ %s%s\n", colorDim, msg, colorReset)
}
