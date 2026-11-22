# PTECIAL assessment notebook

Open `index.html` in a browser or serve this directory as a static site. All application files are local. The notebook requires no account, build step, or backend.

Choose an assessment area and use the search, difficulty, or outcome filters to find a case. Each case has a procedure, an acceptance criterion, and an OWASP or MITRE CWE reference. Basic cases use a public application, documentation, or release URL. Intermediate cases use manual review and recorded evidence. Advanced cases trace a complete workflow using test accounts, fixtures, devices, or release records.

Use **Add field** at the top of the page for engagement details such as scope, build or reviewer. These fields follow you across targets and appear once in either report scope. Use **Note** and **Image** on individual cases. Fields previously saved on a case remain editable and export with that case. Notes, field edits and outcomes save in the current browser profile. Images save when the attachment transaction completes. Clearing site data removes local records.

Open **Run the assessment** for prerequisites, ordered observations, command examples where applicable, and help interpreting results. Set the named variables to your own approved URLs, packages, certificates or redacted exports. PowerShell examples are labeled in the preparation text. Commands are displayed as text for the reviewer.

Each file in `targets/` contains one target's case definitions, including its exercises. Keep case IDs stable when editing content because saved evidence uses those IDs. The script tags in `index.html` set the display order and support opening the notebook from disk.

**Export Markdown** downloads the current area or the full notebook, including cases, outcomes, multiline notes, named fields and embedded image data. Some Markdown viewers restrict embedded image display. Previous-version checklist notes found in the same browser storage are available below the case list under **Previous checklist notes**.
