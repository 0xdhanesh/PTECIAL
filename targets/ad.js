registerTarget({
  "id": "AD",
  "name": "Active Directory",
  "surface": "Verification of domain configuration, account hygiene, and privileged access",
  "cases": [
    {
      "id": "AD-01",
      "category": "Account hygiene",
      "reference": "CWE-284",
      "title": "Review privileged group membership",
      "level": "Intermediate",
      "procedure": "Inventory members of high-privilege groups (Domain Admins, Enterprise Admins, etc.) and compare against the approved administrative model.",
      "evidence": "Group membership list with last review date and noted exceptions."
    },
    {
      "id": "AD-02",
      "category": "Account hygiene",
      "reference": "CWE-521",
      "title": "Confirm password and account lockout policy",
      "level": "Basic",
      "procedure": "Review domain password and lockout policy settings against the organizational standard.",
      "evidence": "Policy settings and comparison to the approved standard."
    },
    {
      "id": "AD-03",
      "category": "Privileged access",
      "reference": "CWE-269",
      "title": "Verify separation of administrative accounts",
      "level": "Intermediate",
      "procedure": "Confirm that privileged administrative activities use dedicated accounts and that those accounts are not used for day-to-day work.",
      "evidence": "Account inventory showing usage separation and any exceptions."
    },
    {
      "id": "AD-04",
      "category": "Auditing",
      "reference": "CWE-778",
      "title": "Confirm directory auditing is enabled",
      "level": "Basic",
      "procedure": "Verify that relevant directory change and authentication events are being audited and retained according to policy.",
      "evidence": "Audit policy configuration and retention confirmation."
    }
  ]
});
