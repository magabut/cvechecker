package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/user/cvechecker/internal/config"
	"github.com/user/cvechecker/internal/detector"
	"github.com/user/cvechecker/internal/formatter"
	"github.com/user/cvechecker/internal/i18n"
	"github.com/user/cvechecker/internal/models"
	"github.com/user/cvechecker/internal/nvd"
	"github.com/user/cvechecker/internal/solution"
)

func main() {
	lang := ""
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "-lang" && i+1 < len(os.Args) {
			lang = os.Args[i+1]
			break
		}
	}

	if lang != "" {
		i18n.InitWith(lang)
	} else {
		i18n.Init()
	}

	args := os.Args[1:]
	for i, arg := range args {
		if arg == "-lang" && i+1 < len(args) {
			args = append(args[:i], args[i+2:]...)
			break
		}
	}

	if len(args) < 1 {
		formatter.PrintBanner()
		printUsage()
		os.Exit(1)
	}

	cmd := args[0]
	switch cmd {
	case "scan":
		scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
		scanLimit := scanCmd.Int("limit", 50, "max packages to scan")
		scanAPIKey := scanCmd.String("key", "", "NVD API key (optional, improves rate limit)")
		scanVerbose := scanCmd.Bool("verbose", false, "show all detected packages")
		scanFix := scanCmd.Bool("fix", false, "show upgrade commands for vulnerable packages")
		_ = scanCmd.Parse(args[1:])
		apiKey := config.GetAPIKey(*scanAPIKey)
		runScan(*scanLimit, apiKey, *scanVerbose, *scanFix)
	case "check":
		checkCmd := flag.NewFlagSet("check", flag.ExitOnError)
		checkPackage := checkCmd.String("p", "", "package name to check")
		checkVersion := checkCmd.String("v", "", "package version")
		checkAPIKey := checkCmd.String("key", "", "NVD API key (optional)")
		checkFix := checkCmd.Bool("fix", false, "show upgrade commands for vulnerable packages")
		_ = checkCmd.Parse(args[1:])
		if *checkPackage == "" {
			fmt.Fprintf(os.Stderr, "Error: package name is required (-p flag)\n")
			os.Exit(1)
		}
		apiKey := config.GetAPIKey(*checkAPIKey)
		runCheck(*checkPackage, *checkVersion, apiKey, *checkFix)
	case "config":
		if len(args) < 2 {
			runConfig()
		} else {
			runConfigCommand(args[1], args[2:])
		}
	case "help", "-h", "--help":
		formatter.PrintBanner()
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`
Usage:
  cvechecker [global options] scan [options]     Scan installed packages for CVEs
  cvechecker [global options] check [options]    Check a specific package for CVEs
  cvechecker config [command]                    Manage configuration

Global Options:
  -lang     Force language: en or id (default: auto-detect from system locale)

Scan Options:
  -limit    Max packages to scan (default: 50)
  -key      NVD API key for higher rate limits
  -verbose  Show all detected packages
  -fix      Show upgrade commands for vulnerable packages

Check Options:
  -p        Package name (required)
  -v        Package version (optional)
  -key      NVD API key
  -fix      Show upgrade commands for vulnerable packages

Config Commands:
  set-key <api_key>   Save NVD API key to config file
  show                Show current configuration
  reset               Reset configuration file

Examples:
  cvechecker config set-key YOUR_API_KEY
  cvechecker config show
  cvechecker -lang en scan -fix
  cvechecker -lang id check -p openssl -v 1.1.1 -fix
  cvechecker help`)
}

func runConfig() {
	cfg := config.Load()
	path := config.GetPath()

	fmt.Println("\n[Configuration]")
	fmt.Printf("  Config File : %s\n", path)

	if cfg.APIKey != "" {
		masked := cfg.APIKey[:4] + "****" + cfg.APIKey[len(cfg.APIKey)-4:]
		if len(cfg.APIKey) <= 8 {
			masked = "****"
		}
		fmt.Printf("  NVD API Key : %s\n", masked)
	} else {
		fmt.Printf("  NVD API Key : %s\n", "(not set)")
	}

	fmt.Println("\nCommands:")
	fmt.Println("  cvechecker config set-key <api_key>   Save API key")
	fmt.Println("  cvechecker config show                Show this info")
	fmt.Println("  cvechecker config reset               Reset config")
}

func runConfigCommand(subcmd string, args []string) {
	switch subcmd {
	case "set-key":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "Error: API key is required")
			fmt.Fprintln(os.Stderr, "Usage: cvechecker config set-key <api_key>")
			os.Exit(1)
		}
		if err := config.SetAPIKey(args[0]); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving API key: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("API key saved successfully")
		fmt.Printf("Config: %s\n", config.GetPath())

	case "show":
		runConfig()

	case "reset":
		cfg := config.Config{}
		if err := config.Save(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error resetting config: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Config reset successfully")

	default:
		fmt.Fprintf(os.Stderr, "Unknown config command: %s\n", subcmd)
		fmt.Println("Available commands: set-key, show, reset")
		os.Exit(1)
	}
}

func runScan(limit int, apiKey string, verbose bool, showFix bool) {
	formatter.PrintBanner()

	formatter.PrintScanProgress("Detecting operating system...")
	osInfo := detector.DetectOS()
	formatter.PrintOSInfo(osInfo)

	formatter.PrintScanProgress("Detecting installed packages...")
	packages := detector.DetectPackages()

	if !verbose && len(packages) > limit {
		packages = packages[:limit]
	}

	formatter.PrintPackageList(packages)

	if len(packages) == 0 {
		formatter.PrintScanProgress("No packages to scan. Exiting.")
		return
	}

	client := nvd.NewClient(apiKey)
	vulns := make(map[string][]models.CVEDetail)

	scanLimit := limit
	if scanLimit > 30 {
		scanLimit = 30
	}

	for i := 0; i < len(packages) && i < scanLimit; i++ {
		pkg := packages[i]
		formatter.PrintScanProgress(fmt.Sprintf("Checking %s %s...", pkg.Name, pkg.Version))

		query := pkg.Name
		if pkg.Version != "" {
			query = pkg.Name + " " + pkg.Version
		}

		cves, err := client.SearchCVE(query)
		if err != nil {
			formatter.PrintScanProgress(fmt.Sprintf("  Warning: %v", err))
			time.Sleep(nvd.GetRateLimitDelay())
			continue
		}

		if len(cves) > 0 {
			if showFix {
				for j := range cves {
					cves[j].Solution.UpgradeCmd = solution.GenerateUpgradeCommand(
						pkg.Name,
						cves[j].Solution.FixVersion,
						pkg.Manager,
					)
					cves[j].Solution.Workaround = solution.GenerateWorkaround(cves[j])
				}
			}
			key := fmt.Sprintf("%s (%s)", pkg.Name, pkg.Version)
			vulns[key] = cves
		}

		if i < len(packages)-1 {
			time.Sleep(nvd.GetRateLimitDelay())
		}
	}

	formatter.PrintVulnerabilityResults(vulns)
}

func runCheck(packageName, version, apiKey string, showFix bool) {
	formatter.PrintBanner()

	formatter.PrintScanProgress(fmt.Sprintf("Checking CVEs for %s %s...", packageName, version))

	client := nvd.NewClient(apiKey)
	query := packageName
	if version != "" {
		query = packageName + " " + version
	}

	cves, err := client.SearchCVE(query)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if showFix && len(cves) > 0 {
		for i := range cves {
			cves[i].Solution.UpgradeCmd = solution.GenerateUpgradeCommand(
				packageName,
				cves[i].Solution.FixVersion,
				"auto",
			)
			cves[i].Solution.Workaround = solution.GenerateWorkaround(cves[i])
		}
	}

	vulns := make(map[string][]models.CVEDetail)
	if len(cves) > 0 {
		key := fmt.Sprintf("%s (%s)", packageName, version)
		vulns[key] = cves
	}

	formatter.PrintVulnerabilityResults(vulns)
}
