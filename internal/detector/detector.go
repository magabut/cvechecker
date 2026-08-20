package detector

import (
	"bufio"
	"bytes"
	"os/exec"
	"runtime"
	"strings"

	"github.com/user/cvechecker/internal/models"
)

func DetectOS() models.OSInfo {
	info := models.OSInfo{
		Name: runtime.GOOS,
		Arch: runtime.GOARCH,
	}

	switch runtime.GOOS {
	case "linux":
		info.Name, info.Version = detectLinuxOS()
	case "darwin":
		info.Name = "macos"
		info.Version = detectMacOSVersion()
	}

	return info
}

func detectLinuxOS() (string, string) {
	if out, err := exec.Command("cat", "/etc/os-release").Output(); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(out))
		name, version := "", ""
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				name = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
			}
			if strings.HasPrefix(line, "VERSION_ID=") {
				version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
			}
		}
		if name != "" {
			return name, version
		}
	}
	return "linux", "unknown"
}

func detectMacOSVersion() string {
	out, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func DetectPackages() []models.Package {
	var pkgs []models.Package

	if runtime.GOOS == "linux" {
		pkgs = append(pkgs, detectDpkgPackages()...)
		pkgs = append(pkgs, detectRpmPackages()...)
		pkgs = append(pkgs, detectApkPackages()...)
	}

	pkgs = append(pkgs, detectBrewPackages()...)
	pkgs = append(pkgs, detectPipPackages()...)

	return pkgs
}

func runCommand(name string, args ...string) []string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return nil
	}

	var result []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

func detectDpkgPackages() []models.Package {
	var pkgs []models.Package
	lines := runCommand("dpkg-query", "-W", "-f", "${Package}\t${Version}\n")
	for _, line := range lines {
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) == 2 {
			pkgs = append(pkgs, models.Package{
				Name:    parts[0],
				Version: parts[1],
				Manager: "dpkg",
			})
		}
	}
	return pkgs
}

func detectRpmPackages() []models.Package {
	var pkgs []models.Package
	lines := runCommand("rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n")
	for _, line := range lines {
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) == 2 {
			pkgs = append(pkgs, models.Package{
				Name:    parts[0],
				Version: parts[1],
				Manager: "rpm",
			})
		}
	}
	return pkgs
}

func detectApkPackages() []models.Package {
	var pkgs []models.Package
	lines := runCommand("apk", "info", "-v")
	for _, line := range lines {
		parts := strings.SplitN(line, "-", 2)
		if len(parts) == 2 {
			pkgs = append(pkgs, models.Package{
				Name:    parts[0],
				Version: parts[1],
				Manager: "apk",
			})
		}
	}
	return pkgs
}

func detectBrewPackages() []models.Package {
	var pkgs []models.Package
	lines := runCommand("brew", "list", "--formula", "--versions")
	for _, line := range lines {
		parts := strings.SplitN(line, " ", 2)
		if len(parts) == 2 {
			verParts := strings.Fields(parts[1])
			version := verParts[0]
			pkgs = append(pkgs, models.Package{
				Name:    parts[0],
				Version: version,
				Manager: "brew",
			})
		}
	}
	return pkgs
}

func detectPipPackages() []models.Package {
	var pkgs []models.Package
	lines := runCommand("pip3", "list", "--format=columns")
	for i, line := range lines {
		if i < 2 {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			pkgs = append(pkgs, models.Package{
				Name:    strings.ToLower(parts[0]),
				Version: parts[1],
				Manager: "pip",
			})
		}
	}
	return pkgs
}
