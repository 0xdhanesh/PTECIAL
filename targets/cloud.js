registerTarget({
  "id": "CLOUD",
  "name": "Cloud",
  "surface": "Verification of identity, storage, and network controls in cloud environments",
  "cases": [
    {
      "id": "CLOUD-01",
      "category": "Identity",
      "reference": "CWE-284",
      "title": "Review IAM policy least privilege",
      "level": "Intermediate",
      "procedure": "Compare attached IAM policies and roles against the documented least-privilege model for the in-scope accounts.",
      "evidence": "Policy inventory with role, attached policies, and noted deviations from the approved model."
    },
    {
      "id": "CLOUD-02",
      "category": "Storage",
      "reference": "CWE-732",
      "title": "Verify storage bucket and object access controls",
      "level": "Intermediate",
      "procedure": "Review public access settings and resource policies on in-scope storage resources. Confirm that public or broad access matches the approved design.",
      "evidence": "Resource list with public-access status and policy summary."
    },
    {
      "id": "CLOUD-03",
      "category": "Logging",
      "reference": "CWE-778",
      "title": "Confirm audit logging and retention",
      "level": "Basic",
      "procedure": "Verify that management-plane audit logs are enabled and retained according to the agreed policy for the in-scope accounts.",
      "evidence": "Logging configuration and retention setting for each in-scope account."
    },
    {
      "id": "CLOUD-04",
      "category": "Network",
      "reference": "CWE-284",
      "title": "Review security group and network policy exposure",
      "level": "Intermediate",
      "procedure": "Inspect security groups or equivalent network controls for overly broad inbound rules on in-scope resources.",
      "evidence": "Rule summary showing source, port, and resource for any non-default or broad rules."
    }
  ]
});
