# PTECIAL

Static, client-side assessment notebook for authorized penetration testing and security assurance.

Open `index.html` in a browser or serve the directory as a static site. No build step, backend, or account is required.

## Usage

- Select an assessment area.
- Filter by search, difficulty (Basic / Intermediate / Advanced), or outcome.
- Record notes, images, and engagement fields. Data is stored in the browser profile.
- Export the current area or full notebook as Markdown.

Each case contains a procedure, acceptance evidence criterion, and CWE or OWASP reference. Case IDs must remain stable because saved evidence references them.

## Assessment areas

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

Adversarial targets (authorized active validation, high-level procedures only):

- Web adversarial
- API adversarial
- Mobile adversarial
- IoT adversarial
- Thick-client adversarial
- Firmware adversarial
- LLM adversarial

Adversarial cases intentionally omit payloads, bypass strings, and exploit steps. Review engagement scope and request limits before testing.

## Prompts

[`prompts/grok-case-generator.md`](prompts/grok-case-generator.md) contains bounded prompts for drafting missing cases and converting observations into evidence-ready findings. Review all generated content before use. Do not send secrets or client-identifying data to third-party services.

## Data

Notes, fields, outcomes, and images are stored locally in the browser. Clearing site data removes them. Markdown export includes cases, outcomes, notes, fields, and embedded images.
