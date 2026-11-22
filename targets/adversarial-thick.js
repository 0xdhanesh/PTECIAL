registerTarget({
  "id": "THICK-ADV",
  "name": "Thick-client adversarial testing",
  "surface": "Authorized active validation of local boundaries, update trust, and inter-process controls",
  "cases": [
    {
      "id": "THICK-ADV-01",
      "category": "Update trust",
      "reference": "CWE-494",
      "title": "Validate update authenticity and rollback protection",
      "level": "Advanced",
      "procedure": "Using owner-approved test builds, compare signature, version, and rollback behavior for legitimate, modified, and older packages. Verify that the client rejects unsigned or downgraded content before installation.",
      "evidence": "Package identity, signature verification result, version comparison, installation decision, and post-install state for each test package."
    },
    {
      "id": "THICK-ADV-02",
      "category": "Local boundaries",
      "reference": "CWE-269",
      "title": "Test local privilege and file-permission boundaries",
      "level": "Intermediate",
      "procedure": "With designated low-privilege test accounts, attempt access to configuration, credential, and log locations that should be restricted. Record whether the operating system or application enforces the expected permissions.",
      "evidence": "Account identity, target path or resource, permission result, and any audit or error event generated."
    },
    {
      "id": "THICK-ADV-03",
      "category": "Inter-process trust",
      "reference": "CWE-284",
      "title": "Validate named-pipe, socket, and IPC authorization",
      "level": "Advanced",
      "procedure": "Identify local communication endpoints used by the application. From a separate process running as a different user, attempt connection or message injection and record whether the endpoint authenticates the caller.",
      "evidence": "Endpoint identity, caller identity, connection or message result, and any authorization decision logged by the application."
    },
    {
      "id": "THICK-ADV-04",
      "category": "Debug and diagnostics",
      "reference": "CWE-489",
      "title": "Check exposure of debug and diagnostic interfaces",
      "level": "Intermediate",
      "procedure": "Review whether diagnostic ports, crash-dump locations, or remote-debug features are reachable on a production-like build. Confirm they are disabled or require explicit elevated approval.",
      "evidence": "Interface inventory, reachability result, and configuration or build flag that controls each interface."
    }
  ]
});
