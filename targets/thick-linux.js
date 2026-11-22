registerTarget({
  "id": "LIN",
  "name": "Linux thick clients",
  "surface": "Package trust, desktop integration and local permissions",
  "cases": [
    {
      "id": "LIN-01",
      "category": "Packaging",
      "reference": "CWE-494",
      "title": "Identify the supported package channel",
      "procedure": "Read the release URL for distribution, package name, architecture and signing identity.",
      "evidence": "Capture the supported channel and verification instructions.",
      "level": "Basic"
    },
    {
      "id": "LIN-02",
      "category": "Packaging",
      "reference": "CWE-347",
      "title": "Review package trust settings",
      "procedure": "Inspect the package repository definition and signing key scope on a test machine.",
      "evidence": "Match the key fingerprint to the owner-approved channel record.",
      "level": "Intermediate"
    },
    {
      "id": "LIN-03",
      "category": "Packaging",
      "reference": "CWE-494",
      "title": "Trace a package upgrade",
      "procedure": "Apply the approved update in a disposable desktop profile. Follow package verification, installed version and service restart events.",
      "evidence": "Link package digest and resulting executable version to the release manifest.",
      "level": "Advanced"
    },
    {
      "id": "LIN-04",
      "category": "Desktop boundaries",
      "reference": "CWE-250",
      "title": "Read sandbox permission declarations",
      "procedure": "At the package listing URL, read the advertised filesystem, device and desktop integration permissions.",
      "evidence": "Record permissions and the user feature claimed for each.",
      "level": "Basic"
    },
    {
      "id": "LIN-05",
      "category": "Desktop boundaries",
      "reference": "CWE-732",
      "title": "Review XDG file permissions",
      "procedure": "Inspect ownership and modes on application configuration, cache and state files created by a synthetic account.",
      "evidence": "Record effective read permissions for the account and other local users.",
      "level": "Intermediate",
      "exercise": {
        "setup": "Set STATE_FILE to an application-created synthetic profile file on the test host.",
        "steps": [
          "Inspect each parent directory and the file mode.",
          "Compare effective ACL entries with the approved profile boundary."
        ],
        "command": "namei -l \"$STATE_FILE\"\ngetfacl -- \"$STATE_FILE\"",
        "interpret": "Directory traversal rights and ACL masks affect effective access. Capture both."
      }
    },
    {
      "id": "LIN-06",
      "category": "Desktop boundaries",
      "reference": "CWE-862",
      "title": "Trace a privileged desktop action",
      "procedure": "Use a documented settings action in a disposable session. Review its D-Bus interface, policy decision and service audit event with the owner.",
      "evidence": "Connect the caller identity and approval decision to the resulting state change.",
      "level": "Advanced"
    },
    {
      "id": "LIN-07",
      "category": "Lifecycle",
      "reference": "CWE-1104",
      "title": "Inspect distribution support dates",
      "procedure": "Compare the advertised Linux package versions and maintenance dates on the release page.",
      "evidence": "Record stale package lines with their published support status.",
      "level": "Basic"
    },
    {
      "id": "LIN-08",
      "category": "Lifecycle",
      "reference": "CWE-532",
      "title": "Review journal exposure",
      "procedure": "Inspect journal entries from ordinary login and sync operations with synthetic data and compare journal access groups.",
      "evidence": "Save redacted examples and the effective reader set.",
      "level": "Intermediate"
    },
    {
      "id": "LIN-09",
      "category": "Lifecycle",
      "reference": "CWE-459",
      "title": "Trace profile removal",
      "procedure": "Populate an isolated profile, use the supported remove-account action and reopen the client. Inspect XDG state directories and keyring item names.",
      "evidence": "Identify cleared records and any retained artifacts with their documented purpose.",
      "level": "Advanced"
    },
    {
      "id": "LIN-10",
      "category": "Service isolation",
      "reference": "CWE-269",
      "title": "Inventory service prerequisites",
      "procedure": "Read the project installation URL for service accounts, group membership and required privileges.",
      "evidence": "Identify which requirements apply only during installation.",
      "level": "Basic"
    },
    {
      "id": "LIN-11",
      "category": "Service isolation",
      "reference": "CWE-250",
      "title": "Review service confinement",
      "procedure": "Inspect the shipped systemd unit for account, capabilities, filesystem access and writable directories.",
      "evidence": "Compare actual permissions with the documented service duties.",
      "level": "Intermediate",
      "exercise": {
        "setup": "Set UNIT to the installed application systemd unit.",
        "steps": [
          "Read effective user, sandbox and capability settings.",
          "Compare writable paths with the documented service responsibilities."
        ],
        "command": "systemctl show \"$UNIT\" -p User -p ProtectSystem -p ReadWritePaths -p CapabilityBoundingSet",
        "interpret": "Report effective configuration and identify drop-in overrides that explain deviations."
      }
    },
    {
      "id": "LIN-12",
      "category": "Service isolation",
      "reference": "CWE-732",
      "title": "Trace package-created permissions",
      "procedure": "Install and update the package in a clean test VM. Compare the owner and mode of its state directory, service socket and configuration after each operation.",
      "evidence": "Document installation defaults and any permission drift after upgrade.",
      "level": "Advanced"
    }
  ]
});
