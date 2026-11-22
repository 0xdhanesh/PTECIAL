registerTarget({
  "id": "CLOUD-ADV",
  "name": "Cloud adversarial testing",
  "surface": "Authorized active validation of identity, storage, and network boundaries",
  "cases": [
    {
      "id": "CLOUD-ADV-01",
      "category": "Identity boundaries",
      "reference": "CWE-284",
      "title": "Validate least-privilege enforcement across roles",
      "level": "Advanced",
      "procedure": "Using designated test identities, exercise actions that should be denied by the approved IAM model. Compare results against the documented role definitions and note any unexpected allowances.",
      "evidence": "Action matrix showing identity, requested action, policy decision, and actual outcome."
    },
    {
      "id": "CLOUD-ADV-02",
      "category": "Storage exposure",
      "reference": "CWE-732",
      "title": "Test storage resource access from unauthorized principals",
      "level": "Intermediate",
      "procedure": "With approved test principals outside the resource owner, attempt read and write operations on in-scope storage resources. Verify that public or cross-account access matches the approved design.",
      "evidence": "Access results for each principal and resource, including any error or success response."
    },
    {
      "id": "CLOUD-ADV-03",
      "category": "Network boundaries",
      "reference": "CWE-284",
      "title": "Validate security group and network policy enforcement",
      "level": "Advanced",
      "procedure": "From an approved external or cross-network test point, attempt connections to in-scope resources on ports that should be restricted. Confirm that the observed behavior matches the documented network controls.",
      "evidence": "Connection attempts with source, destination, port, and result."
    },
    {
      "id": "CLOUD-ADV-04",
      "category": "Logging integrity",
      "reference": "CWE-778",
      "title": "Verify that privileged actions generate audit events",
      "level": "Intermediate",
      "procedure": "Perform a small set of owner-approved privileged actions and confirm that corresponding audit events appear in the designated log store within the expected time window.",
      "evidence": "Action timestamps correlated with audit event records."
    }
  ]
});
