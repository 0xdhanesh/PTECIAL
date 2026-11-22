registerTarget({
  "id": "WIN",
  "name": "Windows thick clients",
  "surface": "Installers, local state and Windows services",
  "cases": [
    {
      "id": "WIN-01",
      "category": "Release trust",
      "reference": "CWE-494",
      "title": "Identify the Windows publisher",
      "procedure": "At the download URL, compare the named publisher, package architecture and release version with the release notes.",
      "evidence": "Record the expected publisher and version for the installer review.",
      "level": "Basic"
    },
    {
      "id": "WIN-02",
      "category": "Release trust",
      "reference": "CWE-347",
      "title": "Inspect the installer signature",
      "procedure": "Use the package signature properties to review publisher, chain and timestamp on the supplied installer.",
      "evidence": "Attach the verification result and compare publisher identity with the release record.",
      "level": "Intermediate",
      "exercise": {
        "setup": "In PowerShell, set $Installer to the approved local package path.",
        "steps": [
          "Inspect the Authenticode verification result and signer thumbprint.",
          "Compare the signer with the release identity obtained through the publisher."
        ],
        "command": "Get-AuthenticodeSignature -FilePath $Installer | Select-Object Status, StatusMessage, SignerCertificate",
        "interpret": "Valid describes this host’s verification result. Compare signer identity and package version separately."
      }
    },
    {
      "id": "WIN-03",
      "category": "Release trust",
      "reference": "CWE-494",
      "title": "Trace a signed update",
      "procedure": "Update a disposable installation through the supported channel. Review updater verification events and the installed file versions.",
      "evidence": "Match old version, signed package identity, new version and updater decision.",
      "level": "Advanced"
    },
    {
      "id": "WIN-04",
      "category": "Local boundaries",
      "reference": "CWE-250",
      "title": "Read installation privilege requirements",
      "procedure": "At the support URL, compare documented rights for installation and ordinary use.",
      "evidence": "Record which operations require elevation and whether a standard-user workflow is documented.",
      "level": "Basic"
    },
    {
      "id": "WIN-05",
      "category": "Local boundaries",
      "reference": "CWE-732",
      "title": "Inspect service file permissions",
      "procedure": "Review effective permissions for the installed service binary, its parent directory and configuration using a standard account.",
      "evidence": "Document the owner and principals allowed to modify each location.",
      "level": "Intermediate",
      "exercise": {
        "setup": "In PowerShell, set $ServiceBinary to the installed service executable.",
        "steps": [
          "Inspect its ACL and the ACL of the containing directory.",
          "Resolve group membership for the normal user and record effective modify rights."
        ],
        "command": "Get-Acl -LiteralPath $ServiceBinary | Format-List Owner,AccessToString\nGet-Acl -LiteralPath (Split-Path $ServiceBinary) | Format-List Owner,AccessToString",
        "interpret": "Review inherited directory rights as well as permissions on the executable."
      }
    },
    {
      "id": "WIN-06",
      "category": "Local boundaries",
      "reference": "CWE-922",
      "title": "Trace sign-out cleanup",
      "procedure": "Sign into a disposable Windows profile, open a synthetic document and sign out. Inspect application cache, recent-document entries and credential inventory.",
      "evidence": "Record which artifacts remain and compare each with the retention policy.",
      "level": "Advanced"
    },
    {
      "id": "WIN-07",
      "category": "Diagnostics",
      "reference": "CWE-359",
      "title": "Review crash reporting disclosure",
      "procedure": "At the Windows support URL, read the crash-reporting notice and controls.",
      "evidence": "Record the listed recipients, default setting and collection scope.",
      "level": "Basic"
    },
    {
      "id": "WIN-08",
      "category": "Diagnostics",
      "reference": "CWE-532",
      "title": "Inspect diagnostic bundle contents",
      "procedure": "Generate an ordinary support bundle for a synthetic profile. Inventory event logs, configuration and paths before sharing.",
      "evidence": "Attach a sanitized manifest and note fields needing redaction.",
      "level": "Intermediate"
    },
    {
      "id": "WIN-09",
      "category": "Diagnostics",
      "reference": "CWE-359",
      "title": "Verify diagnostic consent over upgrade",
      "procedure": "Disable optional reports in a test profile, apply a supported update and trigger the built-in test report if available.",
      "evidence": "Compare consent before and after upgrade with the report delivery history.",
      "level": "Advanced"
    },
    {
      "id": "WIN-10",
      "category": "Windows integration",
      "reference": "CWE-319",
      "title": "Review supported connection modes",
      "procedure": "Read the client setup URL for server trust and supported encrypted connection options.",
      "evidence": "Record the documented default and certificate requirements.",
      "level": "Basic"
    },
    {
      "id": "WIN-11",
      "category": "Windows integration",
      "reference": "CWE-427",
      "title": "Inspect library load policy",
      "procedure": "Review dependency manifests and application-owned library directories in the supplied deployment. Check effective write permissions on search locations.",
      "evidence": "Record each library provider and its trusted installation boundary.",
      "level": "Intermediate"
    },
    {
      "id": "WIN-12",
      "category": "Windows integration",
      "reference": "CWE-862",
      "title": "Trace broker authorization",
      "procedure": "Use the owner’s standard and administrative QA accounts to request an approved service operation through the client. Compare broker audit decisions.",
      "evidence": "Capture caller identity class, service outcome and final configuration for both runs.",
      "level": "Advanced"
    }
  ]
});
