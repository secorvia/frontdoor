// Command frontdoor maps the federated trust that lets outside identities
// into your cloud accounts.
//
// Phase 1: AWS collection. frontdoor scan --aws --format json
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/secorvia/frontdoor/internal/awscollect"
	"github.com/secorvia/frontdoor/internal/azcollect"
	"github.com/secorvia/frontdoor/internal/gcpcollect"
	"github.com/secorvia/frontdoor/internal/model"
	"github.com/secorvia/frontdoor/internal/output"
	"github.com/secorvia/frontdoor/internal/rules"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "0.1.0-dev"

const (
	exitOK    = 0
	exitError = 2
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(exitError)
	}

	switch os.Args[1] {
	case "scan":
		os.Exit(runScan(os.Args[2:]))
	case "version", "--version", "-v":
		fmt.Println("frontdoor", version)
		os.Exit(exitOK)
	case "help", "--help", "-h":
		usage()
		os.Exit(exitOK)
	default:
		fmt.Fprintf(os.Stderr, "frontdoor: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(exitError)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `frontdoor - map the federated trust into your cloud accounts

Usage:
  frontdoor scan [flags]
  frontdoor version

Scan flags:
  --aws                 scan AWS (default when AWS credentials are present)
  --gcp                 scan GCP (Application Default Credentials)
  --gcp-project <ids>   comma-separated GCP project ids
  --gcp-all-projects    scan every project the caller can see
  --gcp-credentials <f> service account key file instead of ADC
  --azure               scan Azure / Entra ID (BETA)
  --azure-tenant <id>   Entra ID tenant id
  --azure-subscription <ids>  comma-separated subscription ids
  --azure-skip-arm      skip role assignments and managed identities
  --format <fmt>        terminal (default), json, sarif, mermaid
  --color <when>        auto (default), always, never. NO_COLOR is always honoured.
  --profile <name>      AWS shared-config profile
  --region <region>     AWS region used to sign requests (IAM is global)
  --vendors <file>      extra account-id -> vendor labels, JSON
  --include-service     also report AWS service-principal trusts (not external)
  --skip-access-keys    do not enumerate IAM user access keys
  --skip-org            do not call AWS Organizations
  --concurrency <n>     parallel per-role policy reads (default 8)
  --timeout <duration>  overall scan timeout (default 10m)
  --output <file>       write to a file instead of stdout
  --quiet               print only the summary line

Detection flags:
  --fail-on <severity>  exit 1 when a finding is at or above this
                        (critical, high, medium, low, info; default critical)
  --ignore-file <path>  .frontdoorignore to suppress findings
                        (default: ./.frontdoorignore when it exists)
  --no-rules            collect only; do not evaluate detection rules
  --stale-days <n>      unused for this many days counts as stale (default 90)
  --max-key-age <n>     an active access key older than this is flagged (default 90)
  --resolve             connect to each OIDC issuer over TLS to verify its
                        thumbprint (FD022). OFF by default: it is the only
                        network call frontdoor makes outside your cloud.
  --no-resolve          force that off, overriding --resolve

Exit codes: 0 clean, 1 findings at or above --fail-on, 2 tool error.

frontdoor is strictly read-only and sends nothing anywhere except to your
cloud provider's own APIs.
`)
}

func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = usage

	var (
		doAWS          = fs.Bool("aws", false, "scan AWS")
		doGCP          = fs.Bool("gcp", false, "scan GCP")
		doAzure        = fs.Bool("azure", false, "scan Azure (beta)")
		azTenant       = fs.String("azure-tenant", "", "Entra ID tenant id")
		azSubs         = fs.String("azure-subscription", "", "comma-separated Azure subscription ids")
		azSkipARM      = fs.Bool("azure-skip-arm", false, "skip Azure role assignments and managed identities")
		gcpProjects    = fs.String("gcp-project", "", "comma-separated GCP project ids")
		gcpAll         = fs.Bool("gcp-all-projects", false, "scan every visible GCP project")
		gcpCreds       = fs.String("gcp-credentials", "", "service account key file (default: ADC)")
		format         = fs.String("format", "terminal", "output format")
		colorWhen      = fs.String("color", "auto", "auto, always or never")
		profile        = fs.String("profile", "", "AWS profile")
		region         = fs.String("region", "", "AWS region")
		vendorsFile    = fs.String("vendors", "", "extra vendor account labels")
		includeService = fs.Bool("include-service", false, "include service-principal trusts")
		skipKeys       = fs.Bool("skip-access-keys", false, "skip IAM access keys")
		skipOrg        = fs.Bool("skip-org", false, "skip AWS Organizations")
		concurrency    = fs.Int("concurrency", 8, "parallel policy reads")
		timeout        = fs.Duration("timeout", 10*time.Minute, "overall timeout")
		outPath        = fs.String("output", "", "write output to file")
		quiet          = fs.Bool("quiet", false, "suppress summary")

		failOn     = fs.String("fail-on", "critical", "exit 1 at or above this severity")
		ignorePath = fs.String("ignore-file", "", "path to .frontdoorignore")
		noRules    = fs.Bool("no-rules", false, "collect only")
		staleDays  = fs.Int("stale-days", 90, "days unused before stale")
		maxKeyAge  = fs.Int("max-key-age", 90, "days before an active access key is flagged")
		doResolve  = fs.Bool("resolve", false, "verify OIDC thumbprints over TLS")
		noResolve  = fs.Bool("no-resolve", false, "never contact OIDC issuers")
	)
	if err := fs.Parse(args); err != nil {
		return exitError
	}

	// A provider-specific flag implies the provider, so nobody has to pass
	// --gcp --gcp-project or --azure --azure-tenant.
	if *gcpProjects != "" || *gcpAll || *gcpCreds != "" {
		*doGCP = true
	}
	if *azTenant != "" || *azSubs != "" || *azSkipARM {
		*doAzure = true
	}

	outFormat, ok := output.ParseFormat(*format)
	if !ok {
		fmt.Fprintf(os.Stderr, "frontdoor: --format %q is not one of terminal, json, sarif, mermaid\n", *format)
		return exitError
	}
	colorMode, ok := output.ParseColorMode(*colorWhen)
	if !ok {
		fmt.Fprintf(os.Stderr, "frontdoor: --color %q is not one of auto, always, never\n", *colorWhen)
		return exitError
	}
	failSeverity, ok := model.ParseSeverity(*failOn)
	if !ok {
		fmt.Fprintf(os.Stderr, "frontdoor: --fail-on %q is not a severity (critical, high, medium, low, info)\n", *failOn)
		return exitError
	}

	ignore, err := loadIgnore(*ignorePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "frontdoor:", err)
		return exitError
	}
	if *vendorsFile != "" {
		if err := awscollect.LoadVendorFile(*vendorsFile); err != nil {
			fmt.Fprintln(os.Stderr, "frontdoor:", err)
			return exitError
		}
	}

	// With no provider flag, scan whatever we can authenticate to. Naming one
	// provider means only that provider - otherwise `--gcp` would quietly also
	// scan AWS and the output would not match what was asked for.
	if !*doAWS && !*doGCP && !*doAzure {
		*doAWS = true
		*doGCP = credentialsPresent("GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT", "GCP_PROJECT", "CLOUDSDK_CORE_PROJECT")
		*doAzure = credentialsPresent("AZURE_TENANT_ID", "ARM_TENANT_ID")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// edges are the graph links the collectors find: AWS assume-role and GCP
	// impersonation. The cross-cloud ones are derived later, once both sides
	// are in the same result.
	var edges []model.Hop

	res := &model.Result{
		Tool:        "frontdoor",
		Version:     version,
		GeneratedAt: time.Now().UTC(),
		Accounts:    []model.Account{},
		Doors:       []model.Door{},
	}

	if *doAWS {
		collector, err := awscollect.New(ctx, awscollect.Options{
			Profile:        *profile,
			Region:         *region,
			Concurrency:    *concurrency,
			IncludeService: *includeService,
			SkipAccessKeys: *skipKeys,
			SkipOrg:        *skipOrg,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "frontdoor:", err)
			return exitError
		}
		if err := collector.Collect(ctx, res); err != nil {
			fmt.Fprintln(os.Stderr, "frontdoor:", err)
			return exitError
		}
		edges = append(edges, collector.AssumeEdges()...)
	}

	if *doGCP {
		collector, err := gcpcollect.New(ctx, gcpcollect.Options{
			Projects:        splitList(*gcpProjects),
			AllProjects:     *gcpAll,
			CredentialsFile: *gcpCreds,
			Concurrency:     *concurrency,
			SkipKeys:        *skipKeys,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "frontdoor:", err)
			return exitError
		}
		if err := collector.Collect(ctx, res); err != nil {
			fmt.Fprintln(os.Stderr, "frontdoor:", err)
			return exitError
		}
		edges = append(edges, collector.ImpersonationEdges()...)
	}

	if *doAzure {
		collector, err := azcollect.New(ctx, azcollect.Options{
			TenantID:      *azTenant,
			Subscriptions: splitList(*azSubs),
			SkipARM:       *azSkipARM,
			Concurrency:   *concurrency,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "frontdoor:", err)
			return exitError
		}
		if err := collector.Collect(ctx, res); err != nil {
			fmt.Fprintln(os.Stderr, "frontdoor:", err)
			return exitError
		}
		edges = append(edges, collector.ImpersonationEdges()...)
	}

	if !*noRules {
		opts := rules.Options{
			StaleDays:          *staleDays,
			MaxKeyAgeDays:      *maxKeyAge,
			Ignore:             ignore,
			ImpersonationEdges: edges,
		}
		if *doResolve && !*noResolve {
			opts.Resolved = rules.ResolveIssuers(ctx, res, 5*time.Second)
		}
		rules.Run(res, opts)
	}

	out := os.Stdout
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "frontdoor:", err)
			return exitError
		}
		defer f.Close()
		out = f
	}

	renderOpts := output.Options{
		Format:     outFormat,
		Color:      output.UseColor(colorMode, out),
		Width:      output.TerminalWidth(),
		Quiet:      *quiet,
		IgnorePath: ignoreSource(ignore, *ignorePath),
		Promo:      outFormat == output.FormatTerminal && os.Getenv("FRONTDOOR_NO_PROMO") == "",
	}
	if err := output.Write(out, res, renderOpts); err != nil {
		fmt.Fprintln(os.Stderr, "frontdoor:", err)
		return exitError
	}

	// The machine-readable formats own stdout, so the human summary goes to
	// stderr and a pipe stays clean.
	if !*quiet && outFormat != output.FormatTerminal {
		output.Summary(os.Stderr, res)
	}

	if *noRules {
		return exitOK
	}
	return output.ExitCode(res, failSeverity)
}

func ignoreSource(list *rules.IgnoreList, flagPath string) string {
	if list == nil || list.Len() == 0 {
		return ""
	}
	if list.Path != "" {
		return list.Path
	}
	return flagPath
}

// loadIgnore reads the ignore file. An explicit --ignore-file that does not
// exist is an error; the default one is used only when present.
func loadIgnore(path string) (*rules.IgnoreList, error) {
	if path != "" {
		return rules.ParseIgnoreFile(path)
	}
	const def = ".frontdoorignore"
	if _, err := os.Stat(def); err != nil {
		return nil, nil
	}
	return rules.ParseIgnoreFile(def)
}

// splitList turns a comma-separated flag value into a slice, dropping blanks
// so "a,,b," behaves.
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// credentialsPresent reports whether any of these environment variables is
// set, which is how the no-flag case decides whether to try a provider at all.
func credentialsPresent(names ...string) bool {
	for _, n := range names {
		if strings.TrimSpace(os.Getenv(n)) != "" {
			return true
		}
	}
	return false
}
