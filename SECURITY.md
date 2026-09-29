# Security policy

## Reporting a vulnerability

Email **security@secorvia.com**. Please do not open a public issue first.

You can also use GitHub's private reporting: **Security → Report a
vulnerability** on this repository.

Include whatever you have — a trust policy that reproduces it, the command you
ran, the output you got and the output you expected. A redacted policy document
is usually enough; we do not need your account id.

## What counts as a vulnerability here

`frontdoor` reads cloud configuration and reports what it finds. The worst
thing it can do is be wrong in the reassuring direction:

- **A false negative.** A door that is genuinely open and `frontdoor` does not
  report, or reports at a lower severity than it deserves. This is the most
  serious class of bug in this tool and the one we most want to hear about.
- **A condition parsed as restrictive when the cloud does not enforce it that
  way.** For example a condition operator we treat as pinning a subject when
  AWS or GCP would evaluate it as always true.
- **Anything that writes.** `frontdoor` makes no mutating API calls. A code
  path that does is a bug, regardless of whether it causes damage.
- **Anything that sends data anywhere.** The only outbound connections are to
  your cloud provider's own APIs, plus — with `--resolve` explicitly passed —
  a TLS handshake to each OIDC issuer to check its thumbprint. Any other
  network call, including telemetry or crash reporting, is a bug.
- **Credential leakage.** A secret, key or token written to stdout, to a
  report file or into an error message.

A false positive is a normal bug. Open an issue for it.

## What does not belong here

Findings about **your own cloud** go in your own tracker. If `frontdoor` tells
you a role is open to any GitHub repository, that is the tool working. Fix the
role.

Vulnerabilities in AWS, GCP or Azure themselves go to those vendors.

## What to expect

`frontdoor` is maintained by a small team, so an honest timeline rather than a
generous one:

- **Acknowledgement within 3 working days.** If you have not heard back by
  then, assume the mail went astray and send it again.
- An assessment, and a fix or an explanation of why it is not one, as soon as
  we can. We will tell you what we think the severity is and why.
- Credit in the release notes, unless you would rather not be named.

We will not threaten you with legal action for reporting something in good
faith, and we will not ask you to stay quiet indefinitely. If a fix is taking
us too long, publish.

## Supported versions

Until `v1.0.0`, only the latest release gets fixes. Upgrade before reporting.

## Scope

In scope: this repository — the CLI, the detection rules, the GitHub Action in
`.github/actions/frontdoor`, the release pipeline and `install.sh`.

Out of scope: the Secorvia hosted product at secorvia.com, which has its own
disclosure process at security@secorvia.com, and the documentation site.
