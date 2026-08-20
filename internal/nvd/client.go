package nvd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/user/cvechecker/internal/i18n"
	"github.com/user/cvechecker/internal/models"
)

const (
	baseURL        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	defaultResults = 20
	rateLimitDelay = 6 * time.Second
)

type Client struct {
	HTTPClient *http.Client
	APIKey     string
}

type apiResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID          string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Published string `json:"published"`
			Modified  string `json:"lastModified"`
			Metrics   struct {
				CVSSMetricV31 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CVSSMetricV2 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
			References []struct {
				URL    string   `json:"url"`
				Source string   `json:"source"`
				Tags   []string `json:"tags"`
			} `json:"references"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						VersionEndExcluding string `json:"versionEndExcluding"`
						Vulnerable          bool   `json:"vulnerable"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
	TotalResults int `json:"totalResults"`
}

func NewClient(apiKey string) *Client {
	return &Client{
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		APIKey:     apiKey,
	}
}

func (c *Client) SearchCVE(keyword string) ([]models.CVEDetail, error) {
	params := url.Values{}
	params.Set("keywordSearch", keyword)
	params.Set("resultsPerPage", fmt.Sprintf("%d", defaultResults))

	reqURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == 403 {
		return nil, fmt.Errorf("rate limited by NVD API, please wait and retry or use an API key")
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("NVD API returned status %d: %s", resp.StatusCode, string(body))
	}

	var apiResp apiResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse NVD response: %w", err)
	}

	var results []models.CVEDetail
	for _, vuln := range apiResp.Vulnerabilities {
		cve := vuln.CVE

		desc := ""
		for _, d := range cve.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}

		score, severity := extractScore(cve.Metrics)
		solution := extractSolution(cve.Configurations, cve.References)

		results = append(results, models.CVEDetail{
			ID:          cve.ID,
			Description: desc,
			Severity:    severity,
			Score:       score,
			URL:         fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve.ID),
			Published:   cve.Published,
			Modified:    cve.Modified,
			Solution:    solution,
		})
	}

	return results, nil
}

func extractScore(metrics struct {
	CVSSMetricV31 []struct {
		CVSSData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
	} `json:"cvssMetricV31"`
	CVSSMetricV2 []struct {
		CVSSData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
	} `json:"cvssMetricV2"`
}) (float64, string) {
	if len(metrics.CVSSMetricV31) > 0 {
		m := metrics.CVSSMetricV31[0].CVSSData
		return m.BaseScore, strings.ToUpper(m.BaseSeverity)
	}
	if len(metrics.CVSSMetricV2) > 0 {
		m := metrics.CVSSMetricV2[0].CVSSData
		return m.BaseScore, strings.ToUpper(m.BaseSeverity)
	}
	return 0, "UNKNOWN"
}

func extractSolution(configs []struct {
	Nodes []struct {
		CPEMatch []struct {
			VersionEndExcluding string `json:"versionEndExcluding"`
			Vulnerable          bool   `json:"vulnerable"`
		} `json:"cpeMatch"`
	} `json:"nodes"`
}, refs []struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}) models.Solution {
	sol := models.Solution{}

	for _, cfg := range configs {
		for _, node := range cfg.Nodes {
			for _, match := range node.CPEMatch {
				if match.VersionEndExcluding != "" && match.Vulnerable {
					if sol.FixVersion == "" {
						sol.FixVersion = match.VersionEndExcluding
					}
				}
			}
		}
	}

	for _, ref := range refs {
		for _, tag := range ref.Tags {
			if tag == "Patch" || tag == "Vendor Advisory" || tag == "Mitigation" {
				sol.References = append(sol.References, ref.URL)
			}
		}
	}

	if sol.FixVersion != "" {
		sol.Description = i18n.Labels.UpgradeTo(sol.FixVersion)
	}

	return sol
}

func GetRateLimitDelay() time.Duration {
	return rateLimitDelay
}
