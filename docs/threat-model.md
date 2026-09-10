# Threat model

Scope: an MCP client, one or more MCP servers, and this gateway between them.

## Trust assumptions

| Component | Trust |
|---|---|
| The gateway process and its config | Trusted |
| The MCP client and the model | Semi-trusted. The model will follow convincing instructions found in its context, so it is treated as manipulable, not malicious |
| Upstream MCP servers | Untrusted. Assume any one may be malicious now or become malicious later |
| Tool return values | Untrusted. Content usually originates outside the server (a web page, an issue body, a file) |
| Principals holding bearer tokens | Semi-trusted. Authenticated, but confined by policy |

The model being manipulable is the central assumption. Every control below
exists because instructions reaching the model cannot be reliably ignored by
the model itself, so they must be stopped before they arrive.

## Attacks and controls

### T1 — Tool poisoning

A server embeds instructions in a tool description or schema. The client shows
the user only the tool name, so the payload is never reviewed.

Control: `scanner.py` inspects every model-visible string, including nested
schema `description`, `title`, `default`, `const` and `enum` values. Findings
accumulate into a risk score; at or above `quarantine_threshold` the tool is
removed from every tool list and calls to it are refused with the findings
attached.

Residual risk: static patterns miss novel phrasing. Mitigation is
`require_pin: true`, which inverts the default so nothing is callable until a
human approves it.

### T2 — Rug pull

A server passes review, then serves a different definition later.

Control: SHA-256 over name, title, description, schema and annotations is
pinned at approval and stored on disk. Any change quarantines the tool and
records both fingerprints. `refresh_interval_seconds` re-lists upstreams
periodically so the change is caught without a restart.

### T3 — Indirect prompt injection via tool output

The tool is clean; the data it returns is not.

Control: results are scanned with the same rules. At critical severity the
content is replaced with a notice telling the model the output was withheld
and to treat the source as untrusted; below that, a warning block is prepended
marking the content as data rather than instructions. Every finding lands in
the audit trail.

Residual risk: only `text` blocks are scanned. Image and resource blocks pass
through. A model may still act on borderline content that was annotated rather
than withheld.

### T4 — Cross-server tool shadowing

Server A's description contains instructions about how the model should use
server B's tools, hijacking a tool the user does trust.

Control: rule XTL001 flags conditional language about other tools being
called. Namespacing means the model addresses `server__tool`, so a shadowing
server cannot claim another server's name.

### T5 — Confused-deputy credential access

An agent is talked into reading `~/.ssh/id_rsa`, `.env` or `~/.aws/credentials`
through a legitimate file tool.

Control: argument guards apply regex denies to specific arguments, including
nested fields, evaluated before the call leaves the gateway. Rules EXF001 and
EXF002 also flag descriptions that reference credential material at all.

### T6 — Excessive agency

A compromised or confused agent performs destructive operations at machine
speed.

Control: deny lists remove capability outright; `require_approval` gates named
tools behind a human decision; token buckets bound the blast radius per
principal and per tool.

### T7 — Secret leakage into logs

Audit logs become a secondary target once they contain tool arguments.

Control: keys matching password, secret, token, api_key, authorization,
credential or private_key are redacted at write time. Long strings are
truncated. Redaction happens before the record is hashed, so redacted content
was never on disk.

### T8 — Audit tampering

An attacker with filesystem access edits history to hide a call.

Control: each record embeds the previous record's hash. `verify` walks the
chain and reports the sequence number where it breaks, distinguishing an
altered record from a broken link. Detection, not prevention — off-host
shipping or a transparency log is required for prevention.

### T9 — Context exhaustion

A server registers hundreds of tools, crowding out the user's actual task and
degrading tool selection.

Control: above `max_tools_exposed`, only the session working set and the meta
tools are exposed. Working sets are per session, so one session cannot inflate
another's context.

## Out of scope

- Compromise of the gateway host or its config
- Malicious client software impersonating a legitimate principal with a valid token
- Model weights or provider-side behaviour
- Denial of service against upstream servers by an authorized principal within its rate budget
- Side channels in upstream servers, such as an upstream that exfiltrates on its own initiative without instructing the model. Per-tool egress policy is on the roadmap and would partially address this.
