# Grok prompts for adversarial assessments

Use these prompts only for targets and techniques authorized by the engagement rules. Treat generated cases and payloads as draft material: review scope, safety, references, commands, and evidence requirements before use. Remove secrets, tokens, personal data, and client-identifying details before pasting context into a third-party service.

## Generate a missing case

```text
You are an elite offensive security engineer helping with an authorized Web/API assessment.

Assessment context:
- Target type: Web / API
- Environment and scope boundaries: [describe approved environment and exclusions]
- Current coverage: [paste existing case titles or JSON]
- Coverage gap: [for example SSRF, JWT validation, or race conditions]
- Safety constraints: [request limits, prohibited actions, production restrictions]

Generate one complete PTECIAL-style case as strict JSON with these fields:
- id
- category
- reference (one primary CWE or OWASP identifier)
- title
- level (Basic, Intermediate, or Advanced)
- procedure (clear, ordered, authorization-aware test method)
- evidence (the minimum evidence needed to distinguish a vulnerability from a false positive)
- optional exercise containing setup, steps, command, and interpret

Requirements:
- Focus on real exploitability and a reproducible control-versus-test comparison.
- Prefer tool-agnostic instructions; commands must use placeholders, not real hosts or secrets.
- Use disposable accounts and reversible test data where state changes are involved.
- Stop at minimal proof. Exclude destructive payloads, persistence, credential collection, bulk extraction, denial of service, and scope expansion.
- Include cleanup or state verification where relevant.
- Return JSON only, without Markdown fences or commentary.
```

## Generate payloads and bypass probes

```text
You are supporting an authorized Web/API assessment.

Case:
[paste the case title, procedure, and evidence requirement]

Target context:
- Input location and parser: [path/query/header/JSON/HTML/etc.]
- Technology known with confidence: [or unknown]
- Approved environment: [test/staging/production constraints]
- Explicit prohibitions and request ceiling: [paste rules]

Generate:
1. Five to eight minimal, high-signal test payloads, including relevant encoding variants.
2. The parser or control assumption tested by each payload.
3. Common, non-destructive bypass probes ordered from least invasive to most invasive.
4. Expected vulnerable, secure, and inconclusive responses.
5. Burp Repeater guidance and curl one-liners using placeholders.
6. False-positive checks, stop conditions, evidence to capture, and cleanup.

Do not invent a technology fingerprint. Do not include destructive statements, live malware, persistence, credential theft, bulk data extraction, denial-of-service payloads, or methods that leave the authorized scope. Use harmless canaries and stop at minimal proof.
```

## Turn an observation into an evidence-ready finding

```text
Turn the authorized assessment observation below into a concise PTECIAL notebook finding.

Observation:
[paste the raw observation]

Context and affected asset:
[paste redacted context]

Control request/result:
[paste the expected or secure comparison]

Test request/result:
[paste the changed input and observed result]

Known impact:
[state demonstrated impact; do not speculate]

Evidence already captured:
[list request IDs, timestamps, screenshots, logs, or state checks]

Produce:
- Title
- Status: Confirmed / Needs validation / Informational
- Summary
- Preconditions and scope
- Reproduction steps with placeholders and redactions
- Observed result
- Expected secure result
- Demonstrated impact
- Evidence inventory
- False-positive checks performed
- Remediation guidance
- Retest acceptance criteria

Clearly label inference and missing evidence. Do not inflate severity, claim unobserved impact, expose secrets, or include unnecessary personal data. Preserve exact technical facts supplied in the observation.
```
