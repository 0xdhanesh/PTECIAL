registerTarget({
  "id": "WEB",
  "name": "Web applications",
  "surface": "Browser sessions and application workflows",
  "cases": [
    {
      "id": "WEB-01",
      "category": "Browser transport",
      "reference": "CWE-319",
      "title": "Inspect the public entry point",
      "procedure": "Open the site URL and inspect the final address and security details in the browser.",
      "evidence": "Capture the final HTTPS origin and any browser transport warning.",
      "level": "Basic",
      "exercise": {
        "setup": "Set URL to the public HTTPS landing page being reviewed.",
        "steps": [
          "Inspect the response status and headers without credentials.",
          "Compare with the browser navigation and record any redirect destination."
        ],
        "command": "curl --silent --show-error --dump-header - --output /dev/null \"$URL\"",
        "interpret": "The first response can be a redirect. Record its destination separately from the final page. Redact cookie values."
      }
    },
    {
      "id": "WEB-02",
      "category": "Browser transport",
      "reference": "CWE-614",
      "title": "Review session cookie scope",
      "procedure": "Sign in with a test account and inspect session cookie attributes in browser storage. Record flags and domains only.",
      "evidence": "Show that the session cookie requires secure transport and is scoped to the intended host.",
      "level": "Intermediate"
    },
    {
      "id": "WEB-03",
      "category": "Browser transport",
      "reference": "CWE-613",
      "title": "Trace session termination",
      "procedure": "Open two views with the same test session. Sign out in one and refresh a protected page in the other. Check the server logout event.",
      "evidence": "Record the redirect or denial and the time the server invalidated the session.",
      "level": "Advanced"
    },
    {
      "id": "WEB-04",
      "category": "Data and privacy",
      "reference": "CWE-200",
      "title": "Review public page metadata",
      "procedure": "Inspect the title, social preview and embedded metadata on the public landing page.",
      "evidence": "Save the public values and identify any internal project or personal information.",
      "level": "Basic"
    },
    {
      "id": "WEB-05",
      "category": "Data and privacy",
      "reference": "CWE-525",
      "title": "Inspect private response caching",
      "procedure": "With a test account, inspect cache directives on an account page, its JSON response and a personalized download.",
      "evidence": "Record the directives beside the sensitivity of each response.",
      "level": "Intermediate"
    },
    {
      "id": "WEB-06",
      "category": "Data and privacy",
      "reference": "CWE-359",
      "title": "Follow account erasure",
      "procedure": "Create a disposable account with synthetic data and use its normal deletion flow. Check the user view, retention job and audit receipt with the owner.",
      "evidence": "Document disappearance from active views and the scheduled expiry of retained copies.",
      "level": "Advanced"
    },
    {
      "id": "WEB-07",
      "category": "Navigation and permissions",
      "reference": "CWE-209",
      "title": "Review public error presentation",
      "procedure": "Visit a nonexistent page under the supplied site URL and read the error presented by the application.",
      "evidence": "Capture the status and visible message. Internal paths and stack traces warrant review.",
      "level": "Basic"
    },
    {
      "id": "WEB-08",
      "category": "Navigation and permissions",
      "reference": "CWE-862",
      "title": "Reconcile privileged functions",
      "procedure": "Compare the role matrix with the server permission checks for a sensitive settings page and its save handler.",
      "evidence": "Record a decision point for each path and any missing owner approval.",
      "level": "Intermediate"
    },
    {
      "id": "WEB-09",
      "category": "Navigation and permissions",
      "reference": "CWE-841",
      "title": "Trace approval of a business change",
      "procedure": "Use the supported submit, approve and publish workflow with separate test roles. Inspect the saved state and audit event at each transition.",
      "evidence": "Link submission, approval identity and final published revision in order.",
      "level": "Advanced"
    },
    {
      "id": "WEB-10",
      "category": "Browser input and state changes",
      "reference": "CWE-79",
      "title": "Inspect the browser content policy",
      "procedure": "Use browser response details at the supplied URL to read the enforced content policy and distinguish report-only headers.",
      "evidence": "Record script sources and the policy actually applied to the page.",
      "level": "Basic",
      "exercise": {
        "setup": "Use an approved public page URL.",
        "steps": [
          "Inspect both content policy header types. Record the enforced script and frame directives.",
          "Compare those directives with the scripts required by the page and the browser policy console."
        ],
        "command": "curl -sS -D - -o /dev/null \"$URL\" | grep -i \"^content-security-policy\"",
        "interpret": "A report-only policy collects violations. Enforcement depends on the policy delivered to this response."
      }
    },
    {
      "id": "WEB-11",
      "category": "Browser input and state changes",
      "reference": "CWE-79",
      "title": "Review rendering of user text",
      "procedure": "Follow a profile field from storage into a template and a client-side preview. Review encoding for each output context.",
      "evidence": "Attach source locations and the regression assertion for displaying literal user text.",
      "level": "Intermediate"
    },
    {
      "id": "WEB-12",
      "category": "Browser input and state changes",
      "reference": "CWE-352",
      "title": "Trace request authenticity checks",
      "procedure": "Review the application’s existing request-authenticity regression suite for a disposable settings change. Compare accepted and rejected fixture results with audit records.",
      "evidence": "Show that only the approved same-session request updates the setting.",
      "level": "Advanced"
    },
    {
      "id": "WEB-13",
      "category": "Uploads and account recovery",
      "reference": "CWE-434",
      "title": "Inspect upload requirements",
      "procedure": "Read the published upload form for type, size and privacy requirements.",
      "evidence": "Record the visible constraints and default sharing audience.",
      "level": "Basic"
    },
    {
      "id": "WEB-14",
      "category": "Uploads and account recovery",
      "reference": "CWE-640",
      "title": "Review recovery token lifecycle",
      "procedure": "Review generation, expiration, storage and consumption of account recovery grants in supplied code.",
      "evidence": "Capture lifetime and evidence that consumption is atomic and single-use.",
      "level": "Intermediate"
    },
    {
      "id": "WEB-15",
      "category": "Uploads and account recovery",
      "reference": "CWE-434",
      "title": "Trace a document through quarantine",
      "procedure": "Upload a benign supported document in a test account. Follow receipt, scanner decision, release and deletion. Use the owner’s failure fixture to inspect the held state.",
      "evidence": "Attach both state histories and the first point at which download becomes available.",
      "level": "Advanced"
    },
    {
      "id": "WEB-16",
      "category": "Authentication and enrollment",
      "reference": "CWE-521",
      "title": "Read password enrollment requirements",
      "procedure": "Inspect the registration page for required length, passphrase support and recovery instructions.",
      "evidence": "Record constraints visible before a user submits personal information.",
      "level": "Basic"
    },
    {
      "id": "WEB-17",
      "category": "Authentication and enrollment",
      "reference": "CWE-307",
      "title": "Review authentication rate controls",
      "procedure": "Review the approved authentication configuration for challenge thresholds, account recovery and operator visibility.",
      "evidence": "Document counter scope, reset conditions and protections against locking out unrelated users.",
      "level": "Intermediate"
    },
    {
      "id": "WEB-18",
      "category": "Authentication and enrollment",
      "reference": "CWE-308",
      "title": "Trace authenticator replacement",
      "procedure": "Replace a factor on a disposable account through the supported flow. Follow identity confirmation, enrollment, retirement of the previous factor and notification.",
      "evidence": "Record each identity decision and confirm the account inventory contains the replacement.",
      "level": "Advanced"
    },
    {
      "id": "WEB-19",
      "category": "Cross-origin and embedded surfaces",
      "reference": "CWE-1021",
      "title": "Inspect framing policy",
      "procedure": "At the supplied URL, inspect response headers that set allowed frame ancestors.",
      "evidence": "Record the enforced directive and intended embedding partners.",
      "level": "Basic"
    },
    {
      "id": "WEB-20",
      "category": "Cross-origin and embedded surfaces",
      "reference": "CWE-942",
      "title": "Review cross-origin trust configuration",
      "procedure": "Compare allowed origins and credential settings for one authenticated frontend with the approved partner list.",
      "evidence": "Record explicit origins, environment ownership and the component setting the response policy.",
      "level": "Intermediate"
    },
    {
      "id": "WEB-21",
      "category": "Cross-origin and embedded surfaces",
      "reference": "CWE-346",
      "title": "Trace an embedded payment handoff",
      "procedure": "Complete a provider-supplied test checkout. Review browser message origins, server confirmation and the final order receipt with the owner.",
      "evidence": "Link the message source and verified provider receipt to one completed order.",
      "level": "Advanced"
    },
    {
      "id": "WEB-22",
      "category": "Administration and audit",
      "reference": "CWE-200",
      "title": "Inspect public status disclosures",
      "procedure": "Read the status or maintenance page linked from the target URL. Review the audience for dependency names and incident detail.",
      "evidence": "Capture any internal system identifiers visible to a public visitor.",
      "level": "Basic"
    },
    {
      "id": "WEB-23",
      "category": "Administration and audit",
      "reference": "CWE-778",
      "title": "Review privileged event coverage",
      "procedure": "Compare application audit events with the role matrix for changing access, exporting records and deleting accounts.",
      "evidence": "Record actor, target, timestamp and outcome coverage for each action.",
      "level": "Intermediate"
    },
    {
      "id": "WEB-24",
      "category": "Administration and audit",
      "reference": "CWE-269",
      "title": "Trace temporary elevation expiry",
      "procedure": "Grant a disposable reviewer time-limited access through the normal administration flow. After expiry, revisit the approved function and inspect its audit decision.",
      "evidence": "Show the grant interval, expiry and loss of the temporary permission.",
      "level": "Advanced"
    },
    {
      "id": "WEB-25",
      "category": "Caching and shared infrastructure",
      "reference": "CWE-525",
      "title": "Inspect public cache variation",
      "procedure": "Review the cache directives and variation headers on the public language or region selector page.",
      "evidence": "Record which dimensions influence the shared representation.",
      "level": "Basic"
    },
    {
      "id": "WEB-26",
      "category": "Caching and shared infrastructure",
      "reference": "CWE-444",
      "title": "Review proxy protocol alignment",
      "procedure": "Compare gateway and application server settings for HTTP versions, header normalization and handling of ambiguous requests.",
      "evidence": "Capture the documented rejection policy and consistency across the deployed tiers.",
      "level": "Intermediate"
    },
    {
      "id": "WEB-27",
      "category": "Caching and shared infrastructure",
      "reference": "CWE-524",
      "title": "Trace a published-content purge",
      "procedure": "Publish a harmless change to a staging page, request its normal cache purge and inspect the origin and edge copies.",
      "evidence": "Record revision, cache invalidation receipt and time until both layers show the updated text.",
      "level": "Advanced"
    }
  ]
});
