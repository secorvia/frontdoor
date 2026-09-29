# frontdoor rule documentation

One page per rule id. The CLI links to these from every finding, so each page is
written for someone who has just seen the id for the first time and wants three
things: what it means, whether it matters here, and what to change.

**Host these at `https://secorvia.com/docs/frontdoor/FD0xx`** — the CLI already
points there. The traffic should land on the domain, not on a repository page.

| Rule | Severity | Clouds |
|---|---|---|
| [FD001](rules/FD001.md) — nothing pins who may come through | critical / high | AWS, GCP, Azure |
| [FD002](rules/FD002.md) — the audience claim is not what it should be | critical → medium | AWS, GCP, Azure |
| [FD003](rules/FD003.md) — an open door into something that can escalate | critical | AWS, GCP, Azure |
| [FD005](rules/FD005.md) — the condition could not be evaluated, or does not apply | medium / low | AWS, GCP, Azure |
| [FD010](rules/FD010.md) — org-wide subject | high | AWS, GCP, Azure |
| [FD011](rules/FD011.md) — no branch or ref restriction | high | AWS, GCP, Azure |
| [FD012](rules/FD012.md) — the pull_request context is accepted | high | AWS, GCP, Azure |
| [FD013](rules/FD013.md) — cross-account trust with no ExternalId | high / medium | AWS |
| [FD014](rules/FD014.md) — trust to an account nobody can identify | high / medium | AWS |
| [FD015](rules/FD015.md) — trust rests on an organization name | high | AWS |
| [FD020](rules/FD020.md) — long-lived keys alongside federation | medium | AWS, GCP, Azure |
| [FD021](rules/FD021.md) — stale federation | medium | AWS, GCP |
| [FD022](rules/FD022.md) — OIDC thumbprint missing or stale | medium / low | AWS |
| [FD030](rules/FD030.md) — a chain, not a single grant | critical / high | GCP, AWS |
| [FD031](rules/FD031.md) — the chain crosses a cloud boundary | critical / high | cross-cloud |
