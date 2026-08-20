package models

type OSInfo struct {
	Name    string
	Version string
	Arch    string
}

type Package struct {
	Name    string
	Version string
	Manager string
}

type CVEDetail struct {
	ID          string
	Description string
	Severity    string
	Score       float64
	URL         string
	Published   string
	Modified    string
	Solution    Solution
}

type Solution struct {
	FixVersion   string
	References   []string
	UpgradeCmd   string
	Workaround   string
	Description  string
}

type ScanResult struct {
	OS       OSInfo
	Packages []Package
	Vulns    map[string][]CVEDetail
}
