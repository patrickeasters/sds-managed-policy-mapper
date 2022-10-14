package mapper

import (
	"github.com/patrickeasters/sds-managed-policy-mapper/sds"
)

type Map struct {
	CustomPolicies  []sds.Policy
	ManagedPolicies []sds.Policy
	Links           []Link
}

type Link struct {
	SourcePolicy int
	DestPolicy   int
	RuleName     string
}

func Generate(policies []sds.Policy) Map {
	m := Map{}

	// Sort policies
	for _, pol := range policies {
		// Skip over compliance policies
		if pol.Origin == "Compliance" {
			continue
		}
		// Let's skip any policy types that don't come out of the box
		if pol.Type != "falco" && pol.Type != "k8s_audit" && pol.Type != "aws_cloudtrail" && pol.Type != "gcp_auditlog" && pol.Type != "azure_platformlogs" {
			continue
		}

		if pol.Managed() {
			m.ManagedPolicies = append(m.ManagedPolicies, pol)
		} else {
			m.CustomPolicies = append(m.CustomPolicies, pol)
		}
	}

	// Build links
	for _, pol := range m.CustomPolicies {
		for _, rule := range pol.Rules {
			// Find all managed policy links
			// This could definitely be optimized, but that's why I didn't study computer science
			// It's a one-off script after-all
			for _, mPol := range m.ManagedPolicies {
				for _, mRule := range mPol.Rules {
					// Generate a link if we find matching rule names
					if rule.Name == mRule.Name {
						link := Link{
							SourcePolicy: pol.ID,
							DestPolicy:   mPol.ID,
							RuleName:     rule.Name,
						}
						m.Links = append(m.Links, link)
					}
				}
			}
		}
	}

	return m
}
