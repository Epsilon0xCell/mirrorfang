# MIRRORFANG

<svg xmlns="http://www.w3.org/2000/svg" width="720" height="120" viewBox="0 0 720 120"><rect width="720" height="120" fill="#000000"/><polygon points="60,25 90,60 60,95" fill="none" stroke="#ff0033" stroke-width="4"/><polygon points="100,25 70,60 100,95" fill="none" stroke="#ffffff" stroke-width="4"/><text x="140" y="58" font-family="monospace" font-size="30" fill="#ffffff">MIRRORFANG</text><text x="140" y="88" font-family="monospace" font-size="15" fill="#ff0033">THE BLACKLOCK INSTRUMENTS</text></svg>

**THE BLACKLOCK INSTRUMENTS** | A ShatterPoint Security research suite
**MIRRORFANG**: every attack ships with its detection
Author: Gavin Blacklock (Epsilon0xCell)

## Invariant

No naked attacks. Every technique in this pack ships with the log it produces,
the Sigma rule that fires on that log, and a matched benign log that the rule
must not fire on. A rule without a negative test is a claim, not a detection.

## One-command run

```bash
python3 -m mirrorfang.validator
python3 -m unittest discover -s tests -v
```

`scripts/validate.py` runs the same check in a CI-style step and exits non-zero
if any pair fails.

## Results and limits

Six pairs ship at v0.1.0, covering Active Directory and AI/MCP logs. The
validator checks every pair: each rule must fire on its attack log and must not
fire on its benign log.

Limits: the validator uses simple documented field matching, not a full Sigma
engine. Selection fields must all match; a field name may end in `|contains`,
`|startswith`, or `|endswith`; values may be scalars or lists. Convert and run
the rules with a full Sigma toolchain before production use. All logs are
synthetic samples, not captures from any real network.

## Detection

The detections are the product: one Sigma YAML rule per pair in
`pairs/<pair>/rule.yml`, beside `attack.jsonl` and `benign.jsonl`.

| Pair | Technique | Mapping | Surface |
|---|---|---|---|
| 01-kerberoasting | Kerberoasting RC4 Service Ticket Request | T1558.003 | Active Directory |
| 02-adcs-esc1-template | AD CS ESC1 Template Request With SAN | T1649 | Active Directory |
| 03-pass-the-hash-logon | Pass The Hash Style NTLM Logon Type 9 | T1550.002 | Active Directory |
| 04-mcp-description-injection | MCP Tool Description Contains Instruction Marker | MCP03 | AI and MCP |
| 05-mcp-canary-exfil | Agent Client Sends Canary Token To Local Listener | MCP03 | AI and MCP |
| 06-tool-output-shell-call | Shell Tool Call With Tool Output Provenance | LLM06 | AI and MCP |

Mappings use MITRE ATT&CK technique identifiers for the Active Directory pairs
and OWASP LLM / MCP identifiers for the AI and MCP pairs, as recorded in each
`pair.json`.

## Disclosure

This pack is defensive tooling built from synthetic logs. Report problems as
described in `SECURITY.md`. If a rule is adapted from another public Sigma
rule, credit the original author in the rule file before publishing it.
Licence: MIT, see `LICENSE`.
