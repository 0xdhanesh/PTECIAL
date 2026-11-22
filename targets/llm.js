registerTarget({
  "id": "LLM",
  "name": "LLM applications",
  "surface": "Model interfaces, tools and retrieval",
  "cases": [
    {
      "id": "LLM-01",
      "category": "Data handling",
      "reference": "CWE-359",
      "title": "Read the input retention notice",
      "procedure": "At the assistant URL, inspect the notice shown before a user submits a question.",
      "evidence": "Record whether the notice identifies retention, downstream processing and available controls.",
      "level": "Basic"
    },
    {
      "id": "LLM-02",
      "category": "Data handling",
      "reference": "CWE-532",
      "title": "Inspect prompt telemetry",
      "procedure": "Compare a redacted model trace with the logging configuration and approved field list.",
      "evidence": "Show which fields reach support tools and which roles may read them.",
      "level": "Intermediate",
      "exercise": {
        "setup": "Set TRACE to a sanitized JSON trace exported by the model gateway for a synthetic question.",
        "steps": [
          "List the paths of scalar fields without printing their values.",
          "Compare prompt, retrieved document and output fields with the approved telemetry schema."
        ],
        "command": "jq -r 'paths(scalars) | map(tostring) | join(\".\")' \"$TRACE\"",
        "interpret": "Field presence identifies a storage location. Confirm masking and reader permissions with a synthetic marker."
      }
    },
    {
      "id": "LLM-03",
      "category": "Data handling",
      "reference": "CWE-359",
      "title": "Trace conversation deletion",
      "procedure": "Create a disposable conversation with a unique harmless phrase. Delete it using the supported workflow and review history, index deletion receipts and retention schedules.",
      "evidence": "Capture dated evidence for the conversation store, search index and backup expiry.",
      "level": "Advanced"
    },
    {
      "id": "LLM-04",
      "category": "Tool permissions",
      "reference": "CWE-250",
      "title": "Inventory advertised actions",
      "procedure": "Read the capabilities and permissions shown in the assistant UI at the supplied URL.",
      "evidence": "List read and write actions and the stated approval requirements.",
      "level": "Basic"
    },
    {
      "id": "LLM-05",
      "category": "Tool permissions",
      "reference": "CWE-862",
      "title": "Review tool authorization",
      "procedure": "Trace one write tool from its schema through the application authorization handler. Compare its service identity with the user permission model.",
      "evidence": "Attach the policy decision and the tool credential scope.",
      "level": "Intermediate"
    },
    {
      "id": "LLM-06",
      "category": "Tool permissions",
      "reference": "CWE-862",
      "title": "Trace a declined action",
      "procedure": "Request an ordinary change to a disposable record, decline the confirmation and inspect the record and action log.",
      "evidence": "Show the original revision, cancellation event and unchanged final revision.",
      "level": "Advanced"
    },
    {
      "id": "LLM-07",
      "category": "Knowledge sources",
      "reference": "CWE-345",
      "title": "Inspect answer attribution",
      "procedure": "Use a public sample question about a documented feature. Open the citation supplied with the answer.",
      "evidence": "Record whether the cited passage supports the claim and identifies a source version.",
      "level": "Basic"
    },
    {
      "id": "LLM-08",
      "category": "Knowledge sources",
      "reference": "CWE-862",
      "title": "Review retrieval filters",
      "procedure": "Review how document permissions are carried from ingestion into lookup and citation previews.",
      "evidence": "Map one synthetic document to its owner, index filter and preview decision.",
      "level": "Intermediate",
      "exercise": {
        "setup": "Set DOC to the redacted JSON metadata for one fixture document.",
        "steps": [
          "Compare owner and tenant fields with the index access filter.",
          "Trace the filter into both retrieval and citation preview paths."
        ],
        "command": "jq 'keys' \"$DOC\"",
        "interpret": "A permission field in metadata is only one input. Record the actual query predicate and preview decision."
      }
    },
    {
      "id": "LLM-09",
      "category": "Knowledge sources",
      "reference": "CWE-672",
      "title": "Trace withdrawal of a source",
      "procedure": "Publish an approved synthetic knowledge entry, confirm a cited answer, then withdraw it and wait for the stated index refresh.",
      "evidence": "Record source revision, index update and the subsequent answer to the same question.",
      "level": "Advanced"
    },
    {
      "id": "LLM-10",
      "category": "Instruction and retrieval boundaries",
      "reference": "CWE-200",
      "title": "Inspect conversation sharing controls",
      "procedure": "Read the sharing options visible at the assistant URL and the stated audience for a shared transcript.",
      "evidence": "Record default visibility and whether attached source material is included.",
      "level": "Basic"
    },
    {
      "id": "LLM-11",
      "category": "Instruction and retrieval boundaries",
      "reference": "CWE-20",
      "title": "Review the model input boundary",
      "procedure": "Inspect a redacted prompt assembly trace. Locate retrieved passages, application instructions and policy decisions outside the model.",
      "evidence": "Record the source label for each passage and which component authorizes actions.",
      "level": "Intermediate"
    },
    {
      "id": "LLM-12",
      "category": "Instruction and retrieval boundaries",
      "reference": "CWE-345",
      "title": "Evaluate conflicting source revisions",
      "procedure": "In a test index, publish two harmless revisions of a product limit with explicit effective dates. Ask the supported product question before and after refresh.",
      "evidence": "Save both answers and citations, expected effective revision and any stale answer.",
      "level": "Advanced"
    }
  ]
});
