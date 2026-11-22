registerTarget({
  "id": "AD-ADV",
  "name": "Active Directory adversarial testing",
  "surface": "Authorized active validation of privileged access and authentication boundaries",
  "cases": [
    {
      "id": "AD-ADV-01",
      "category": "Privileged access",
      "reference": "CWE-269",
      "title": "Validate separation of administrative accounts",
      "level": "Advanced",
      "procedure": "Using designated test accounts, confirm that day-to-day user accounts cannot perform privileged directory operations and that administrative accounts are restricted to approved workstations or paths.",
      "evidence": "Access attempt results for standard vs administrative accounts on privileged operations."
    },
    {
      "id": "AD-ADV-02",
      "category": "Authentication boundaries",
      "reference": "CWE-287",
      "title": "Test account lockout and authentication policy enforcement",
      "level": "Intermediate",
      "procedure": "With owner-approved test accounts, exercise failed authentication attempts up to the documented lockout threshold and confirm that the account is locked and that subsequent legitimate attempts are handled as expected.",
      "evidence": "Authentication timeline showing failure count, lockout event, and recovery behavior."
    },
    {
      "id": "AD-ADV-03",
      "category": "Group membership",
      "reference": "CWE-284",
      "title": "Verify that privilege changes are audited and restricted",
      "level": "Advanced",
      "procedure": "Attempt to add a designated test account to a high-privilege group using an account that should not have that right. Confirm the operation is denied and that an audit event is generated.",
      "evidence": "Attempt result, error or success, and corresponding directory audit record."
    },
    {
      "id": "AD-ADV-04",
      "category": "Credential hygiene",
      "reference": "CWE-521",
      "title": "Confirm password policy is enforced on password changes",
      "level": "Intermediate",
      "procedure": "Using a designated test account, attempt password changes that violate the documented complexity or history policy and confirm they are rejected.",
      "evidence": "Password change attempts and the policy rejection messages or results."
    }
  ]
});
