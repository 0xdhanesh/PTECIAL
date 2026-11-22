registerTarget({
  "id": "CICD",
  "name": "CI/CD & Jenkins",
  "surface": "Pipelines, build identities and release controls",
  "cases": [
    {
      "id": "CICD-01",
      "category": "Build identities",
      "reference": "CWE-200",
      "title": "Review the public build view",
      "procedure": "Open the supplied project or Jenkins URL as a signed-out visitor. Review only the visible job and artifact metadata.",
      "evidence": "Record exposed project identifiers and compare them with the intended public inventory.",
      "level": "Basic"
    },
    {
      "id": "CICD-02",
      "category": "Build identities",
      "reference": "CWE-250",
      "title": "Inspect Jenkinsfile credential scope",
      "procedure": "Review the Jenkinsfile and shared library calls for the stages that bind credentials. Compare credential scope with the stage purpose.",
      "evidence": "Record credential IDs only, their permitted jobs and the stage lifetime.",
      "level": "Intermediate",
      "exercise": {
        "setup": "From the repository root, inspect a supplied Jenkinsfile with ripgrep.",
        "steps": [
          "Locate credential binding sites and compare block boundaries with stage definitions.",
          "Inspect the corresponding shared-library method for bindings established outside the Jenkinsfile."
        ],
        "command": "rg -n \"withCredentials|credentialsId|environment *\\\\{\" Jenkinsfile",
        "interpret": "A matching line identifies a review location. Verify the credential’s effective scope using the job policy."
      }
    },
    {
      "id": "CICD-03",
      "category": "Build identities",
      "reference": "CWE-269",
      "title": "Trace a build identity rotation",
      "procedure": "Coordinate rotation of a disposable build credential. Run the approved smoke pipeline and inspect the credential audit trail.",
      "evidence": "Link revocation, new binding and successful build without recording credential values.",
      "level": "Advanced"
    },
    {
      "id": "CICD-04",
      "category": "Release integrity",
      "reference": "CWE-494",
      "title": "Locate artifact verification information",
      "procedure": "At the release URL, locate the checksum or signature and the documented verification identity.",
      "evidence": "Record where users obtain both the artifact and its expected identity.",
      "level": "Basic"
    },
    {
      "id": "CICD-05",
      "category": "Release integrity",
      "reference": "CWE-829",
      "title": "Review Jenkinsfile dependency pins",
      "procedure": "Inspect shared libraries, container images and build tool references for immutable revisions.",
      "evidence": "Record each mutable reference with its update owner and review mechanism.",
      "level": "Intermediate",
      "exercise": {
        "setup": "Use the reviewed pipeline revision and its dependency files.",
        "steps": [
          "Locate library and image references in the Jenkinsfile.",
          "Resolve each reference to a commit or image digest recorded by the build."
        ],
        "command": "rg -n \"@Library|docker.image|image \" Jenkinsfile",
        "interpret": "Classify each reference by actual immutability and whether changes require review."
      }
    },
    {
      "id": "CICD-06",
      "category": "Release integrity",
      "reference": "CWE-345",
      "title": "Trace one promoted artifact",
      "procedure": "Select a released build. Follow its reviewed commit, build identity, digest and promotion record through staging and production.",
      "evidence": "Compare the built and promoted digests and capture the approval identity.",
      "level": "Advanced"
    },
    {
      "id": "CICD-07",
      "category": "Isolation and audit",
      "reference": "CWE-532",
      "title": "Inspect a published build summary",
      "procedure": "Read a publicly visible build summary at the supplied URL. Review what build context the publisher exposes.",
      "evidence": "Save a redacted excerpt and flag sensitive environment details.",
      "level": "Basic"
    },
    {
      "id": "CICD-08",
      "category": "Isolation and audit",
      "reference": "CWE-732",
      "title": "Review workspace reuse",
      "procedure": "Compare the Jenkins agent allocation and post-build cleanup blocks with the executor configuration.",
      "evidence": "Show the workspace lifecycle and ownership boundary between jobs.",
      "level": "Intermediate"
    },
    {
      "id": "CICD-09",
      "category": "Isolation and audit",
      "reference": "CWE-862",
      "title": "Follow a release approval",
      "procedure": "Start an approved staging release with a disposable version, leave the gate pending, then approve it with the assigned reviewer.",
      "evidence": "Show no deployment before approval and match the deployment receipt to that approval.",
      "level": "Advanced"
    },
    {
      "id": "CICD-10",
      "category": "Branch trust and release artifacts",
      "reference": "CWE-345",
      "title": "Locate release provenance records",
      "procedure": "Read the released artifact listing for its build identity and attestation reference.",
      "evidence": "Record which published files can be linked to a build.",
      "level": "Basic"
    },
    {
      "id": "CICD-11",
      "category": "Branch trust and release artifacts",
      "reference": "CWE-78",
      "title": "Review Jenkinsfile parameter handling",
      "procedure": "Trace user-editable build parameters into shell steps. Inspect typed choices, validation and how arguments are passed to the build tool.",
      "evidence": "Record each shell boundary and the validation or fixed choice that constrains it.",
      "level": "Intermediate"
    },
    {
      "id": "CICD-12",
      "category": "Branch trust and release artifacts",
      "reference": "CWE-862",
      "title": "Trace an ordinary contribution build",
      "procedure": "Run a routine documentation change through the approved contribution workflow in a test project. Compare its actual runner and granted scopes with a release build.",
      "evidence": "Capture both identities and evidence that signing credentials are exclusive to the release job.",
      "level": "Advanced"
    }
  ]
});
