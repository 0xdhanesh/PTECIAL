registerTarget({
  "id": "RE",
  "name": "Reverse engineering",
  "surface": "Artifact provenance and static release review",
  "cases": [
    {
      "id": "RE-01",
      "category": "Artifact identity",
      "reference": "CWE-345",
      "title": "Establish the public release identity",
      "procedure": "Read the release URL for version, build flavor, signing identity and available checksums.",
      "evidence": "Record the expected artifact identifiers and unresolved provenance gaps.",
      "level": "Basic"
    },
    {
      "id": "RE-02",
      "category": "Artifact identity",
      "reference": "CWE-1104",
      "title": "Reconcile embedded components",
      "procedure": "Compare version metadata from a supplied binary and its bundled libraries with the release SBOM.",
      "evidence": "List matched component identities and unresolved version differences.",
      "level": "Intermediate",
      "exercise": {
        "setup": "Set BINARY to an approved local release executable and SBOM to its CycloneDX JSON manifest.",
        "steps": [
          "Record the binary digest and the named component versions.",
          "Compare the results with the signed release inventory and record unresolved components."
        ],
        "command": "shasum -a 256 \"$BINARY\"\njq -r '.components[] | [.name,.version] | @tsv' \"$SBOM\"",
        "interpret": "An SBOM lists claimed components. Require an artifact-bound build receipt to attribute them to this exact binary."
      }
    },
    {
      "id": "RE-03",
      "category": "Artifact identity",
      "reference": "CWE-353",
      "title": "Trace source to shipped binary",
      "procedure": "Select a released component and follow the source revision, build receipt, signed package and extracted component hash.",
      "evidence": "Attach the chain of identifiers and distinguish verified links from assumptions.",
      "level": "Advanced"
    },
    {
      "id": "RE-04",
      "category": "Release exposure",
      "reference": "CWE-215",
      "title": "Inspect the release file listing",
      "procedure": "Read the public release asset listing and identify public debug or symbol packages.",
      "evidence": "Capture intended audiences and publication status for each asset.",
      "level": "Basic"
    },
    {
      "id": "RE-05",
      "category": "Release exposure",
      "reference": "CWE-209",
      "title": "Review diagnostic strings",
      "procedure": "Review error-message resources in a supplied artifact for developer paths, internal service labels and personal identifiers.",
      "evidence": "Record redacted locations and classify which strings are reachable from documented UI flows.",
      "level": "Intermediate"
    },
    {
      "id": "RE-06",
      "category": "Release exposure",
      "reference": "CWE-489",
      "title": "Trace release configuration",
      "procedure": "Compare debug and release feature manifests with the corresponding signed artifacts. Validate one release-only setting using its supported status screen.",
      "evidence": "Correlate build flags, artifact identity and observed setting.",
      "level": "Advanced"
    },
    {
      "id": "RE-07",
      "category": "Data handling",
      "reference": "CWE-359",
      "title": "Inventory declared integrations",
      "procedure": "Review release documentation for analytics and crash-reporting integrations.",
      "evidence": "Record the declared recipients and choices available to the user.",
      "level": "Basic"
    },
    {
      "id": "RE-08",
      "category": "Data handling",
      "reference": "CWE-798",
      "title": "Review embedded credential references",
      "procedure": "Review owner-provided resource inventories and configuration for credential markers. Classify placeholders and identifiers with the release owner.",
      "evidence": "Record only the resource location and classification with a remediation owner.",
      "level": "Intermediate"
    },
    {
      "id": "RE-09",
      "category": "Data handling",
      "reference": "CWE-532",
      "title": "Trace a diagnostic field",
      "procedure": "Select a harmless diagnostic marker in the shipped resources. Follow its source reference and trigger the documented UI event in a disposable profile.",
      "evidence": "Match the static reference and emitted record, identifying fields removed by redaction.",
      "level": "Advanced"
    },
    {
      "id": "RE-10",
      "category": "Platform hardening",
      "reference": "CWE-1104",
      "title": "Identify supported runtime versions",
      "procedure": "Read the release notes for bundled runtime versions and the release that last updated them.",
      "evidence": "Capture the version claims for comparison with the artifact.",
      "level": "Basic"
    },
    {
      "id": "RE-11",
      "category": "Platform hardening",
      "reference": "CWE-693",
      "title": "Inspect executable hardening metadata",
      "procedure": "Inspect the supplied PE or ELF header for declared relocation and non-executable memory settings. Record applicability for each architecture.",
      "evidence": "Attach header fields and identify any architecture variant missing the expected build setting.",
      "level": "Intermediate",
      "exercise": {
        "setup": "Use a supplied ELF binary and GNU readelf.",
        "steps": [
          "Identify the file type and inspect program-header flags.",
          "Compare the GNU_STACK permissions with the approved architecture-specific build policy."
        ],
        "command": "readelf -h \"$BINARY\"\nreadelf -W -l \"$BINARY\"",
        "interpret": "Record the declared permissions. An absent header may have platform-specific semantics."
      }
    },
    {
      "id": "RE-12",
      "category": "Platform hardening",
      "reference": "CWE-353",
      "title": "Compare protection across releases",
      "procedure": "Compare build policy and executable metadata for two signed releases. Request a build receipt for each changed setting.",
      "evidence": "Link the difference to an approved compiler change or record the unexplained regression.",
      "level": "Advanced"
    }
  ]
});
