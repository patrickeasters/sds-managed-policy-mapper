package main

import (
	"fmt"
	"os"

	"github.com/patrickeasters/sds-managed-policy-mapper/html"
	"github.com/patrickeasters/sds-managed-policy-mapper/mapper"
	"github.com/patrickeasters/sds-managed-policy-mapper/sds"

	"github.com/leaanthony/clir"
	"github.com/pkg/browser"
)

var version = "v0.1.0"

func main() {
	cli := clir.NewCli("sds-policy-mapper", "Sysdig Secure Managed Policy Mapper", version)

	// CLI options
	url := "https://secure.sysdig.com"
	cli.StringFlag("secure-url", "URL for Sysdig Secure", &url)

	token := ""
	cli.StringFlag("secure-token", "API token for Sysdig Secure (env: SECURE_API_TOKEN)", &token)

	// No Cli flag for the token, assign from the env var
	if len(token) == 0 {
		token = os.Getenv("SECURE_API_TOKEN")
	}

	// Missing token cli flag or environment variable
	_, ok := os.LookupEnv("SECURE_API_TOKEN")
	if !ok {
		fmt.Println("TOKEN NOT FOUND - Please ensure either the \"SECURE_API_TOKEN\" environment variable or the \"secure-token\" cli flag is set.")
		os.Exit(1)
	}

	outFile := "policies.html"
	cli.StringFlag("output", "Path to file for writing report", &outFile)

	openBrowser := false
	cli.BoolFlag("browser", "Automatically open report in browser", &openBrowser)

	cli.Action(func() error {
		// Get policies from API
		client := sds.NewClient(url, token)
		policies, err := client.Policies()
		if err != nil {
			return fmt.Errorf("unable to get policies from Sysdig API: %w", err)
		}

		// Build map from policy list
		policyMap := mapper.Generate(policies)

		// Open file for report
		f, err := os.Create(outFile)
		if err != nil {
			return fmt.Errorf("unable to create output file: %w", err)
		}
		defer f.Close()

		// Process report template to file
		err = html.Render(f, policyMap)
		if err != nil {
			return fmt.Errorf("unable to write report: %w", err)
		}

		// Optionally open browser
		if openBrowser {
			err := browser.OpenFile(outFile)
			if err != nil {
				return fmt.Errorf("unable to open report in browser: %w", err)
			}
		}

		return nil
	})

	if err := cli.Run(); err != nil {
		fmt.Printf("Failed to generate policy report: %s\n", err)
		os.Exit(1)
	}

}
