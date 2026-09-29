// Package output renders a scan result.
//
// The terminal report is the one people see first and the one they screenshot,
// so it gets the most care. JSON is the contract for tooling, SARIF is how the
// findings reach the GitHub Security tab, and mermaid is for pasting a trust
// graph into a README.
package output

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/secorvia/frontdoor/internal/model"
)

// Format is an output renderer.
type Format string

const (
	FormatTerminal Format = "terminal"
	FormatJSON     Format = "json"
	FormatSARIF    Format = "sarif"
	FormatMermaid  Format = "mermaid"
)

// ParseFormat accepts the names used on the command line.
func ParseFormat(s string) (Format, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "terminal", "text", "tty":
		return FormatTerminal, true
	case "json":
		return FormatJSON, true
	case "sarif":
		return FormatSARIF, true
	case "mermaid":
		return FormatMermaid, true
	}
	return "", false
}

// Options control rendering.
type Options struct {
	Format Format
	Color  bool
	Width  int
	// Quiet prints the summary line and nothing else.
	Quiet bool
	// IgnorePath is named in the footer so a reader can find the suppressions.
	IgnorePath string
	// Promo prints one dimmed line pointing at the hosted product. It is off
	// unless the caller turns it on, and it never appears in a machine format.
	Promo bool
}

func (o Options) width() int {
	switch {
	case o.Width > 0:
		return o.Width
	default:
		return 96
	}
}

// Write renders res in the requested format.
func Write(w io.Writer, res *model.Result, opts Options) error {
	if opts.Quiet {
		Summary(w, res)
		return nil
	}
	switch opts.Format {
	case FormatJSON:
		return JSON(w, res)
	case FormatSARIF:
		return SARIF(w, res)
	case FormatMermaid:
		return Mermaid(w, res)
	default:
		return Terminal(w, res, opts)
	}
}

// --- colour ------------------------------------------------------------------

// ColorMode is the --color setting.
type ColorMode string

const (
	ColorAuto   ColorMode = "auto"
	ColorAlways ColorMode = "always"
	ColorNever  ColorMode = "never"
)

// ParseColorMode accepts the names used on the command line.
func ParseColorMode(s string) (ColorMode, bool) {
	switch ColorMode(strings.ToLower(strings.TrimSpace(s))) {
	case ColorAuto, "":
		return ColorAuto, true
	case ColorAlways:
		return ColorAlways, true
	case ColorNever:
		return ColorNever, true
	}
	return "", false
}

// UseColor decides whether to emit ANSI escapes.
//
// NO_COLOR is honoured unconditionally (https://no-color.org): if it is set to
// anything at all, no escapes are emitted, even with --color always. A user who
// sets it has told us what they want.
func UseColor(mode ColorMode, f *os.File) bool {
	if _, noColor := os.LookupEnv("NO_COLOR"); noColor {
		return false
	}
	switch mode {
	case ColorNever:
		return false
	case ColorAlways:
		return true
	}
	if !isTerminal(f) {
		return false
	}
	if term := os.Getenv("TERM"); term == "dumb" {
		return false
	}
	if runtime.GOOS == "windows" {
		// Go does not enable virtual terminal processing for us, and doing it
		// would mean a syscall dependency. These are set by every Windows
		// console that renders ANSI.
		return os.Getenv("WT_SESSION") != "" ||
			os.Getenv("ANSICON") != "" ||
			os.Getenv("ConEmuANSI") == "ON" ||
			os.Getenv("TERM") != ""
	}
	return true
}

func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// TerminalWidth returns the width to wrap at, honouring COLUMNS.
func TerminalWidth() int {
	if v := os.Getenv("COLUMNS"); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n >= 40 {
			if n > 120 {
				return 120
			}
			return n
		}
	}
	return 96
}

// paint applies an ANSI code when colour is on, and is a no-op when it is off,
// so the layout code never branches on it.
type paint struct{ on bool }

func (p paint) wrap(code, s string) string {
	if !p.on || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p paint) bold(s string) string   { return p.wrap("1", s) }
func (p paint) dim(s string) string    { return p.wrap("2", s) }
func (p paint) red(s string) string    { return p.wrap("1;31", s) }
func (p paint) orange(s string) string { return p.wrap("1;33", s) }
func (p paint) yellow(s string) string { return p.wrap("33", s) }
func (p paint) blue(s string) string   { return p.wrap("36", s) }
func (p paint) green(s string) string  { return p.wrap("32", s) }

func (p paint) severity(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return p.red(strings.ToUpper(string(s)))
	case model.SeverityHigh:
		return p.orange(strings.ToUpper(string(s)))
	case model.SeverityMedium:
		return p.yellow(strings.ToUpper(string(s)))
	default:
		return p.dim(strings.ToUpper(string(s)))
	}
}
