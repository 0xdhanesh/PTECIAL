registerTarget({
  "id": "FW-ADV",
  "name": "Firmware adversarial testing",
  "surface": "Authorized active validation of boot chain, update integrity, and debug interfaces",
  "cases": [
    {
      "id": "FW-ADV-01",
      "category": "Boot trust",
      "reference": "CWE-1268",
      "title": "Validate secure-boot chain and recovery behavior",
      "level": "Advanced",
      "procedure": "On a designated lab device, compare boot outcomes for a signed image, a modified image, and a recovery path. Verify that the device refuses to execute unsigned or tampered firmware.",
      "evidence": "Image hash or signature status, boot decision, recovery path taken, and any serial or log output captured."
    },
    {
      "id": "FW-ADV-02",
      "category": "Update integrity",
      "reference": "CWE-494",
      "title": "Test firmware update authenticity and anti-rollback",
      "level": "Advanced",
      "procedure": "Using owner-approved update packages, attempt installation of a correctly signed current image, an older signed image, and an unsigned image. Record whether anti-rollback and signature checks are enforced.",
      "evidence": "Package version and signature result, installation decision, and device version after each attempt."
    },
    {
      "id": "FW-ADV-03",
      "category": "Debug interfaces",
      "reference": "CWE-1191",
      "title": "Check exposure of debug and console interfaces",
      "level": "Intermediate",
      "procedure": "On a production-like device, identify UART, JTAG, or other debug interfaces and determine whether they are disabled, password-protected, or left open. Record the observed state without enabling persistent access.",
      "evidence": "Interface type, physical or logical reachability, authentication requirement, and configuration that controls it."
    },
    {
      "id": "FW-ADV-04",
      "category": "Credential storage",
      "reference": "CWE-798",
      "title": "Validate protection of device credentials and keys",
      "level": "Advanced",
      "procedure": "Review whether device identity keys or default credentials are stored in a protected region and whether they can be extracted from a normal firmware image or runtime memory dump on a lab device.",
      "evidence": "Storage location, protection mechanism observed, and result of any owner-approved extraction attempt."
    }
  ]
});
