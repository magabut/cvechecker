package solution

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/user/cvechecker/internal/i18n"
	"github.com/user/cvechecker/internal/models"
)

func GenerateUpgradeCommand(pkgName, fixVersion, manager string) string {
	if fixVersion == "" {
		return ""
	}

	switch manager {
	case "dpkg":
		return fmt.Sprintf("sudo apt update && sudo apt install --only-upgrade %s", pkgName)
	case "rpm":
		return fmt.Sprintf("sudo yum update %s", pkgName)
	case "apk":
		return fmt.Sprintf("sudo apk upgrade %s", pkgName)
	case "brew":
		return fmt.Sprintf("brew upgrade %s", pkgName)
	case "pip":
		return fmt.Sprintf("pip3 install --upgrade %s==%s", pkgName, fixVersion)
	default:
		return detectDefaultCommand(pkgName, fixVersion)
	}
}

func detectDefaultCommand(pkgName, fixVersion string) string {
	if runtime.GOOS == "linux" {
		if commandExists("apt") {
			return fmt.Sprintf("sudo apt update && sudo apt install --only-upgrade %s", pkgName)
		}
		if commandExists("yum") {
			return fmt.Sprintf("sudo yum update %s", pkgName)
		}
		if commandExists("dnf") {
			return fmt.Sprintf("sudo dnf update %s", pkgName)
		}
		if commandExists("apk") {
			return fmt.Sprintf("sudo apk upgrade %s", pkgName)
		}
	}

	if runtime.GOOS == "darwin" {
		if commandExists("brew") {
			return fmt.Sprintf("brew upgrade %s", pkgName)
		}
	}

	return fmt.Sprintf("Upgrade %s to version %s or later", pkgName, fixVersion)
}

func commandExists(cmd string) bool {
	switch cmd {
	case "apt", "yum", "dnf", "apk", "brew":
		return true
	}
	return false
}

func GenerateWorkaround(cve models.CVEDetail) string {
	desc := strings.ToLower(cve.Description)

	if strings.Contains(desc, "remote") && strings.Contains(desc, "code execution") {
		return i18n.Labels.RestrictNet()
	}
	if strings.Contains(desc, "denial of service") || strings.Contains(desc, "dos") {
		return i18n.Labels.MonitorAvail()
	}
	if strings.Contains(desc, "privilege escalation") {
		return i18n.Labels.ReviewPerms()
	}
	if strings.Contains(desc, "information disclosure") || strings.Contains(desc, "sensitive") {
		return i18n.Labels.ReviewPerms()
	}
	if strings.Contains(desc, "cross-site scripting") || strings.Contains(desc, "xss") {
		return i18n.Labels.EnableCSP()
	}
	if strings.Contains(desc, "sql injection") {
		return i18n.Labels.ValidateInput()
	}
	if strings.Contains(desc, "buffer overflow") {
		return i18n.Labels.EnableASLR()
	}

	return i18n.Labels.ReviewVendor()
}
