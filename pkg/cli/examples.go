package cli

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/terminal"
)

// fullExampleSection is one titled group of the --full-example tour.
type fullExampleSection struct {
	title    string
	examples []string
}

// fullExampleSections is the curated tour --full-example prints. It is data so
// TestFullExamplesParse can check every line against the real command tree.
func fullExampleSections() []fullExampleSection {
	return []fullExampleSection{
		{"Scanning", []string{
			"vigolium scan -t https://example.com",
			"vigolium scan -t https://example.com -t https://api.example.com",
			"vigolium scan -T targets.txt",
			"vigolium scan -t https://example.com --strategy deep",
			"vigolium scan -t https://example.com --scanning-profile quick",
			"vigolium scan -t https://example.com --scanning-profile full",
			"vigolium scan -t https://example.com --only dynamic-assessment",
			"vigolium scan -t https://example.com --skip discovery,spidering",
			"vigolium scan -t https://example.com -m xss-reflected,sqli-error",
			"vigolium scan -t https://example.com --module-tag spring --module-tag injection",
			"vigolium scan -t https://example.com --format jsonl -o results.jsonl",
			"vigolium scan -t https://example.com --format html -o report.html",
			"vigolium scan -t https://example.com --proxy http://127.0.0.1:8080",
			"vigolium scan -t https://example.com -c 100 --rate-limit 200",
			"vigolium scan -t https://example.com --scanning-max-duration 2h",
			"vigolium scan -t https://example.com --ext custom-check.js",
			"vigolium scan -t https://example.com --ext-dir ./my-extensions",
			"vigolium scan -t https://example.com --only extension --ext custom-check.js",
			"vigolium scan -t https://example.com --project-name my-project",
			"vigolium scan -t https://example.com --oast-url https://interact.sh/abc123",
			"vigolium scan -t https://example.com --known-issue-scan-tags cve,misconfig --known-issue-scan-severities critical,high",
		}},
		{"Running Single Phases", []string{
			"vigolium run discover -t https://example.com",
			"vigolium run spidering -t https://example.com",
			"vigolium run dynamic-assessment -t https://example.com",
			"vigolium run dynamic-assessment -t https://example.com --module-tag spring",
			"vigolium run external-harvest -t https://example.com",
			"vigolium run known-issue-scan -t https://example.com",
			"vigolium run known-issue-scan -t https://example.com --known-issue-scan-tags cve --known-issue-scan-severities critical,high",
			"vigolium run extension -t https://example.com --ext custom-check.js",
			"vigolium run deparos -t https://example.com",
			"vigolium run dast -t https://example.com",
		}},
		{"Input Modes", []string{
			"vigolium scan -I openapi -i openapi.yaml -t https://api.example.com",
			"vigolium scan -I burp -i burp-export.xml -t https://example.com",
			"vigolium scan -I curl -i requests.txt",
			"vigolium scan -I har -i traffic.har",
			"cat urls.txt | vigolium scan -i -",
		}},
		{"Ingestion", []string{
			"vigolium ingest -t https://example.com -I openapi -i spec.yaml",
			"vigolium ingest -t https://example.com -I burp -i export.xml",
			"cat urls.txt | vigolium ingest -i -",
		}},
		{"Server", []string{
			"vigolium server",
			"vigolium server --host 0.0.0.0 --service-port 8443",
			"vigolium server --no-auth",
			"vigolium server --scan-on-receive",
		}},
		{"Database & Results", []string{
			"vigolium db ls",
			"vigolium db ls --table findings",
			"vigolium db stats",
			"vigolium db clean --scan-uuid my-scan",
			"vigolium traffic",
			"vigolium traffic login",
			"vigolium finding",
			"vigolium export --format jsonl -o full-export.jsonl",
			"vigolium export --format jsonl --only findings",
			"vigolium export --format jsonl --only findings,http",
			"vigolium export --format html -o report.html",
		}},
		{"Strategy & Phases", []string{
			"vigolium strategy",
			"vigolium phase",
		}},
		{"Modules", []string{
			"vigolium module ls",
			"vigolium module enable xss",
			"vigolium module disable sqli",
			"vigolium scan -M",
		}},
		{"Extensions", []string{
			"vigolium ext ls",
			"vigolium ext docs",
			"vigolium ext preset",
			`vigolium ext eval 'vigolium.log.info("hello")'`,
			"vigolium ext eval --ext-file script.js",
		}},
		{"Scope", []string{
			"vigolium scope view",
			"vigolium scope set host.include '*.example.com'",
		}},
		{"Agent (AI)", []string{
			"vigolium agent query --source ./src --prompt-template security-code-review",
			"vigolium agent query --source ./src --prompt-template endpoint-discovery",
			"vigolium agent query 'review this code for vulnerabilities'",
			"vigolium agent query --agent-label code-review --prompt-file custom-prompt.md",
			"vigolium agent --list-templates",
			"vigolium agent swarm -t https://example.com --discover",
			"vigolium agent swarm -t https://example.com --discover --prompt 'focus on API injection'",
			"vigolium agent autopilot -t https://example.com",
		}},
		{"Configuration", []string{
			"vigolium config ls",
			"vigolium config clean",
			"vigolium version",
		}},
	}
}

func printFullExamples() {
	for _, sec := range fullExampleSections() {
		printSection(sec.title, sec.examples)
	}
}

func printSection(title string, examples []string) {
	fmt.Printf("  %s %s\n", terminal.InfoSymbol(), terminal.BoldCyan(title))
	for _, ex := range examples {
		fmt.Printf("    %s %s\n", terminal.ListSymbol(), terminal.Gray(ex))
	}
	fmt.Println()
}
