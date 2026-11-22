# PTECIAL

Static, client-side assessment notebook for authorized penetration testing and security assurance.

Open `index.html` in a browser or serve the directory as a static site. No build step, backend, or account is required.

## Usage

- Select an assessment area.
- Filter by search, difficulty, outcome, or severity.
- Set severity and impact on each case. When marking a case Not applicable, record the reason. Record notes, images, and engagement fields. Data is stored in the browser profile.
- Export the current area, full notebook, or findings only as Markdown (includes severity, impact, related cases, notes, and images).

Each case contains a procedure, acceptance evidence criterion, and a reference (CWE, OWASP, or external). Optional `related` arrays link verification and adversarial cases. Case IDs must remain stable because saved evidence references them.

## Assessment areas

Pre-engagement:

- Pre-engagement (scope, rules of engagement, data handling)

Verification targets (documentation, configuration, and workflow review):

- Web applications
- API security
- LLM applications
- CI/CD
- Thick clients (Windows, Linux)
- Mobile (Android, iOS)
- IoT
- Reverse engineering
- Firmware
- Cloud
- Active Directory

Adversarial targets (authorized active validation, high-level procedures only):

- Web adversarial
- API adversarial
- Mobile adversarial
- IoT adversarial
- Thick-client adversarial
- Firmware adversarial
- LLM adversarial

Adversarial cases intentionally omit payloads, bypass strings, and exploit steps. Some cases include links to [HackTricks](https://book.hacktricks.xyz) as external references. Review engagement scope and request limits before testing.

## Prompts

[`prompts/grok-case-generator.md`](prompts/grok-case-generator.md) contains bounded prompts for drafting missing cases and converting observations into evidence-ready findings. Review all generated content before use. Do not send secrets or client-identifying data to third-party services.

## Data

Notes, fields, outcomes, severity, impact, out-of-scope reasons, and images are stored locally in the browser. Clearing site data removes them. Markdown export includes cases, outcomes, severity, impact, related cases, notes, fields, and embedded images.
