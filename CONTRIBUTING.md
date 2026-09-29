# Contributing to frontdoor

The most useful contributions to a security scanner are usually not new
features. They are:

1. **A false positive.** If `frontdoor` flagged something that is actually
   correct, that is a bug worth more than a new rule. Open an issue with the
   policy (redacted) and what it should have said.
2. **A vendor account id** with the vendor's own doc URL — see
   [`internal/awscollect/vendors.go`](internal/awscollect/vendors.go).
3. **A subject grammar** for a CI platform we do not parse yet.
4. **A rule**, with the discipline below.

## Getting set up

```bash
git clone https://github.com/secorvia/frontdoor
cd frontdoor
go test ./...        # everything runs from fixtures: no cloud, no credentials
go vet ./...
gofmt -l .
```

Go 1.26 or newer. There is no other tooling to install.

## The rules the code follows

These are not style preferences. They are the reasons anyone would trust the
output, and CI enforces the first two.

**Strictly read-only.** Every cloud call is a `List`, `Get`, `Describe` or
`Search`. If your change adds a call whose name begins with a mutating verb, CI
fails the build. There is no exception and no flag to turn it off.

**No new network egress.** `frontdoor` talks to the cloud provider you pointed
it at and nowhere else. The single exception is `--resolve`, which is opt-in.
CI fails if HTTP code appears outside the collectors and that one file.

**Never say more than you know.** This is the one that takes discipline. If a
call was denied, the finding says so and lowers its own severity — it does not
assume the worst and it does not stay silent. If an expression could not be
parsed, the finding says *that*, rather than guessing "wide open" or "fine".
Look at `FD005` and at the `understood` return from `ConstrainsSubject` for what
this looks like in practice.

**Never invent an identifier.** Account ids, role GUIDs and thumbprints are
either cited from the vendor's own documentation or left out. A wrong vendor
label tells somebody an unknown account is friendly.

**A finding without a fix is a complaint.** Every rule produces the text or the
command that fixes it, built from the real issuer, org and repository wherever
the policy already told us what they are.

## Adding a rule

A rule is a method on `evalContext` that appends a `model.Finding`. The whole
pattern is in [`internal/rules/federated.go`](internal/rules/federated.go).

1. **Pick the id.** `FD0xx` where the first digit groups severity roughly:
   `00x` critical, `01x` high, `02x` hygiene, `03x` chains.

2. **Write the test first, starting from a clean fixture.** Every rule test in
   this repo begins with a *correctly configured* door and breaks exactly one
   thing. That makes a false positive a compile-time-visible failure rather
   than something you find in production:

   ```go
   func TestCleanDoorProducesNoFindings(t *testing.T) { ... }
   ```

   If your rule fires on `githubDoor()` untouched, it is wrong.

3. **Write the rule.** It must fill, at minimum:

   | Field | What goes in it |
   |---|---|
   | `WhatIsWrong` | One sentence. Name the exact condition key or binding. |
   | `AttackerCan` | One sentence. A concrete action, not "could lead to compromise". |
   | `Evidence` | The policy text the finding rests on, so nobody takes our word for it. |
   | `Fix` | A summary, and a pasteable policy fragment or command where one exists. |

4. **Choose the severity honestly.** Contextual severity is encouraged and
   there are worked examples: `FD002` is critical with no subject condition and
   medium with an exact one, because on GitHub the audience was never the
   barrier. Crying critical on a safe configuration is how a scanner gets
   uninstalled.

5. **Handle the provider differences.** The same idea often means something
   different in each cloud, and copying a rule across is where false positives
   come from. Three worked examples live in the code:

   - An empty `allowedAudiences` on GCP is the *secure default*, so FD002 does
     not fire on it.
   - GCP and Azure do not report key last-use, so FD020 never says "never used"
     about one.
   - Thumbprints do not exist outside AWS, so FD022 skips the other providers.

6. **Add a docs page** at `docs/rules/FD0xx.md`. The CLI links to
   `https://secorvia.com/docs/frontdoor/FD0xx`, and that page is where someone
   who has never seen the tool learns what the finding means.

## Adding a subject grammar

Every CI platform invents its own `sub` claim format. They all live in
[`internal/issuers/issuers.go`](internal/issuers/issuers.go), shared by all
three collectors, because the same GitHub subject appears in an AWS trust
policy, a GCP workload identity binding and an Azure federated credential.

Add an `issuerSpec` with a `Match` on the issuer host and a `Parse` that fills
`Org`, `Project`, `Ref`, `Environment` and — most importantly — `Scope`:

| Scope | Means |
|---|---|
| `exact` | one identity, one ref |
| `project` | one repository, any ref |
| `org` | any repository in one organization |
| `anyone` | any customer of that issuer |

Getting `Scope` right matters more than a pretty `Display`: it is what the
rules and the chain ranking read.

Add a row to `TestParseSubject` covering the exact case, the org-wide case and
the wildcard case.

## Commit and PR

- One change per PR. A rule and a refactor in the same diff is two reviews.
- `gofmt -l .` must be empty; `go vet ./...` and `go test ./...` must pass.
- Comments explain *why*, not *what*. The code already says what it does.

## Reporting a vulnerability

If you find a flaw in `frontdoor` itself — something that makes it report a
door as closed when it is open — please do not open a public issue. Email
security@secorvia.com. Findings about your own cloud belong in your own
tracker, not here.

## Licence

Apache 2.0. By contributing you agree your work is licensed the same way.
