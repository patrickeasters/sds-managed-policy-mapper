package sds

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type Client struct {
	httpClient *http.Client
	BaseURL    string
	Token      string
}

func NewClient(url, token string) Client {
	return Client{
		httpClient: &http.Client{
			Transport: http.DefaultTransport.(*http.Transport).Clone(),
		},
		BaseURL: strings.TrimSuffix(url, "/"),
		Token:   token,
	}
}

func (c *Client) get(path string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	req.Header.Add("Authorization", "Bearer "+c.Token)

	return c.httpClient.Do(req)
}

type Policy struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    int    `json:"severity"`
	Enabled     bool   `json:"enabled"`
	Type        string `json:"type"`
	Scope       string `json:"scope"`
	TemplateID  int    `json:"templateId"`
	Default     bool   `json:"isDefault"`
	Origin      string `json:"origin"`
	Rules       []Rule `json:"rules"`
}

func (p Policy) Managed() bool {
	return p.Default || p.TemplateID > 0
}

func (p Policy) FriendlyType() string {
	switch p.Type {
	case "falco":
		return "Workload"
	case "k8s_audit":
		return "Kubernetes Audit"
	case "aws_cloudtrail":
		return "AWS CloudTrail"
	case "gcp_auditlog":
		return "GCP Audit Logs"
	case "azure_platformlogs":
		return "Azure Platform Logs"
	}
	return ""
}

func (p Policy) FriendlySeverity() string {
	switch {
	case p.Severity >= 0 && p.Severity <= 3:
		return "High"
	case p.Severity >= 4 && p.Severity <= 5:
		return "Medium"
	case p.Severity == 6:
		return "Low"
	case p.Severity == 7:
		return "Info"
	}
	return ""
}

func (p Policy) FriendlyScope() string {
	if len(p.Scope) > 0 {
		return p.Scope
	}
	return "entire infrastructure"
}

type Rule struct {
	Name    string `json:"ruleName"`
	Enabled bool   `json:"enabled"`
}

func (c *Client) Policies() ([]Policy, error) {
	resp, err := c.get("/api/v2/policies")
	if err != nil {
		return nil, fmt.Errorf("failed to get policies from API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get policies (HTTP status: %d)", resp.StatusCode)
	}

	var policies []Policy
	err = json.NewDecoder(resp.Body).Decode(&policies)
	if err != nil {
		return nil, fmt.Errorf("failed to parse policies from API: %s", err)
	}

	return policies, nil
}
