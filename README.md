# PTECIAL — Pentest Checklists

Client-only web & API penetration testing checklists (basics → advanced), built to run on GitHub Pages or straight off disk. Nothing leaves the browser.

## Features

- **Two checklists** — Web Application (OWASP WSTG / Top 10) and API (OWASP API Security Top 10:2023). Switch via the dropdown.
- **Search** — press <kbd>/</kbd> anywhere to jump to search; matches are highlighted; <kbd>Esc</kbd> clears.
- **Level filter** — basic / intermediate / advanced.
- **Progress tracking** — checkboxes and per-item notes persist in `localStorage` (per checklist). Progress bar in the header.
- **Markdown export** — download the checklist with your checked state and notes embedded.
- **Markdown import** — re-import an edited `.md` file; checked state and notes are matched back by item ID, so you can edit offline and reload.
- Dark / light theme, "hide done", expand / collapse all, reset.

## Client-first architecture

There is no backend and no network calls. Checklist data is plain JS (`data/*.js`) assigned to `window.CHECKLISTS`, so the site works identically from `file://` and from GitHub Pages. All state lives in `localStorage`; import/export uses local `Blob` download and the file picker only.

## Run locally

Just open `index.html` in a browser — no server needed.

## Deploy to GitHub Pages

```bash
git init
git add .
git commit -m "Initial PTECIAL checklist site"
git branch -M main
git remote add origin https://github.com/0xdhanesh/PTECIAL.git
git push -u origin main
```

Then in the repo: **Settings → Pages → Build and deployment → Source: Deploy from a branch → `main` / `root`**. The site publishes at `https://0xdhanesh.github.io/PTECIAL/`.

## Adding or editing content

Each item in `data/web.js` / `data/api.js`:

```js
{ id: "WEB-RECON-01", l: "basic", t: "Short title", d: "One-line description." }
```

- `id` — **stable**; used for saved progress and markdown import. Don't reuse or change existing IDs.
- `l` — `basic` | `intermediate` | `advanced`.

To add a third checklist, create `data/foo.js` assigning `window.CHECKLISTS.foo = {...}`, add a `<script>` tag in `index.html`, and it appears in the dropdown automatically.

## References

- OWASP Web Security Testing Guide (WSTG)
- OWASP Top 10
- OWASP API Security Top 10:2023

These checklists are a testing aid; use them within an authorized engagement scope.
