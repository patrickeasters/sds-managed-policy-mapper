package html

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"text/template"

	"github.com/patrickeasters/sds-managed-policy-mapper/mapper"
)

//go:embed report.html.tmpl
var reportTemplate string

type Report struct {
	mapper.Map
}

func Render(w io.Writer, m mapper.Map) error {
	tmpl, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse report template: %w", err)
	}

	return tmpl.Execute(w, Report{m})
}

func (r Report) RuleHash(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:])[0:8]
}

func (r Report) ManagedLinks(name string) int {
	links := make(map[int]struct{})
	for _, l := range r.Links {
		if name == l.RuleName {
			links[l.DestPolicy] = struct{}{}
		}
	}
	return len(links)
}

func (r Report) CustomLinks(name string) int {
	links := make(map[int]struct{})
	for _, l := range r.Links {
		if name == l.RuleName {
			links[l.SourcePolicy] = struct{}{}
		}
	}
	return len(links)
}
