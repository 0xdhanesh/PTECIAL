registerTarget({
  "id": "FW",
  "name": "Firmware analysis",
  "surface": "Image provenance, boot integrity and updates",
  "cases": [
    {
      "id": "FW-01",
      "category": "Image provenance",
      "reference": "CWE-345",
      "title": "Identify the hardware target",
      "procedure": "Read the firmware download URL for model, board revision, region and image version.",
      "evidence": "Record supported hardware and expected artifact identity.",
      "level": "Basic"
    },
    {
      "id": "FW-02",
      "category": "Image provenance",
      "reference": "CWE-1104",
      "title": "Reconcile the firmware inventory",
      "procedure": "Compare the provided image manifest and component version table with the supplied SBOM.",
      "evidence": "Record mismatched revisions and unsupported components with package paths.",
      "level": "Intermediate",
      "exercise": {
        "setup": "Set SBOM to the supplied firmware CycloneDX JSON inventory and IMAGE to the corresponding image.",
        "steps": [
          "Hash the image and compare its identity with the signed manifest.",
          "List component versions and compare them with the package manifest for this hardware revision."
        ],
        "command": "shasum -a 256 \"$IMAGE\"\njq -r '.components[] | [.name,.version] | @tsv' \"$SBOM\"",
        "interpret": "Record whether the signed manifest actually binds this SBOM to this digest."
      }
    },
    {
      "id": "FW-03",
      "category": "Image provenance",
      "reference": "CWE-347",
      "title": "Trace image signing",
      "procedure": "Follow a test release from build manifest to signature receipt, verification log and installed version on the matching evaluation board.",
      "evidence": "Attach digests, signer identity and device acceptance evidence.",
      "level": "Advanced"
    },
    {
      "id": "FW-04",
      "category": "Boot and recovery",
      "reference": "CWE-494",
      "title": "Locate the recovery image policy",
      "procedure": "Read the recovery instructions at the supplied URL for image provenance and supported recovery versions.",
      "evidence": "Capture the named source and version constraints.",
      "level": "Basic",
      "exercise": {
        "setup": "Use the supplied local recovery package and a published digest from the device vendor.",
        "steps": [
          "Record its SHA-256 and compare the target hardware revision.",
          "Check the version constraints in the recovery release record."
        ],
        "command": "shasum -a 256 \"$IMAGE\"",
        "interpret": "A matching digest identifies the file. It does not show the bootloader accepted it."
      }
    },
    {
      "id": "FW-05",
      "category": "Boot and recovery",
      "reference": "CWE-1328",
      "title": "Review rollback policy",
      "procedure": "Inspect the update policy and image metadata for monotonic version counters and documented recovery exceptions.",
      "evidence": "Record counter ownership, comparison point and authorization for exceptions.",
      "level": "Intermediate"
    },
    {
      "id": "FW-06",
      "category": "Boot and recovery",
      "reference": "CWE-755",
      "title": "Trace update recovery",
      "procedure": "Run the vendor-provided interrupted-update acceptance fixture on an evaluation board. Review slot selection and health reporting after restart.",
      "evidence": "Show the selected verified slot, retained settings and final device health.",
      "level": "Advanced"
    },
    {
      "id": "FW-07",
      "category": "Configuration and data",
      "reference": "CWE-1392",
      "title": "Read factory configuration guidance",
      "procedure": "Review the public quick-start for first-boot credentials and enrollment requirements.",
      "evidence": "Record user-visible initialization steps and any shared-default dependency.",
      "level": "Basic"
    },
    {
      "id": "FW-08",
      "category": "Configuration and data",
      "reference": "CWE-321",
      "title": "Review key provenance",
      "procedure": "Compare key inventory labels in the supplied manufacturing manifest with the provisioning design. Identify public anchors and device-unique secret references.",
      "evidence": "Record identifiers and ownership only, with evidence of per-device provisioning.",
      "level": "Intermediate"
    },
    {
      "id": "FW-09",
      "category": "Configuration and data",
      "reference": "CWE-226",
      "title": "Trace decommissioning",
      "procedure": "Provision a lab unit with synthetic data and run the documented erase workflow. Inspect the owner-approved post-reset inventory and enrollment record.",
      "evidence": "Link erase result, cleared user partitions and identity retirement to the device record.",
      "level": "Advanced"
    },
    {
      "id": "FW-10",
      "category": "Manufacturing and hardware boundaries",
      "reference": "CWE-1191",
      "title": "Read production debug policy",
      "procedure": "Read the board support page for production debug access and authorized service conditions.",
      "evidence": "Record which board revisions and lifecycle states the policy covers.",
      "level": "Basic"
    },
    {
      "id": "FW-11",
      "category": "Manufacturing and hardware boundaries",
      "reference": "CWE-1191",
      "title": "Inspect production provisioning records",
      "procedure": "Compare documented debug policy with the sanitized factory configuration receipt for a test board.",
      "evidence": "Match board identity, lifecycle state and declared interface lock settings.",
      "level": "Intermediate"
    },
    {
      "id": "FW-12",
      "category": "Manufacturing and hardware boundaries",
      "reference": "CWE-1188",
      "title": "Trace factory-to-field provisioning",
      "procedure": "Follow one test board through approved provisioning, outgoing inspection and first enrollment. Compare factory-only settings with the field manifest.",
      "evidence": "Attach the state transitions and evidence that release settings replaced manufacturing defaults.",
      "level": "Advanced"
    }
  ]
});
