registerTarget({
  "id": "IOT",
  "name": "IoT devices",
  "surface": "Enrollment, fleet operations and device retirement",
  "cases": [
    {
      "id": "IOT-01",
      "category": "Device identity",
      "reference": "CWE-1392",
      "title": "Read first-use credential guidance",
      "procedure": "At the device onboarding URL, identify how users establish the first owner identity.",
      "evidence": "Record whether credentials are unique per device and when ownership changes.",
      "level": "Basic",
      "exercise": {
        "setup": "Use the setup URL for one exact model and hardware revision.",
        "steps": [
          "Follow first-owner setup on paper from shipping state to claimed state. Identify where a per-device identity enters the flow.",
          "Record what a second owner must do during transfer and what evidence the first owner retains."
        ],
        "command": "",
        "interpret": "A unique serial number identifies a unit but does not establish possession. Record what the documentation actually promises about claiming."
      }
    },
    {
      "id": "IOT-02",
      "category": "Device identity",
      "reference": "CWE-287",
      "title": "Inspect enrollment binding",
      "procedure": "Review a sanitized enrollment record and the factory identity issuance policy.",
      "evidence": "Show how device identity, tenant and enrollment approval are bound.",
      "level": "Intermediate",
      "exercise": {
        "setup": "A sanitized enrollment receipt and public device certificate in PEM format. Set CERT to the certificate file.",
        "steps": [
          "Compute the certificate fingerprint and compare it with the enrolled identity in the fleet inventory.",
          "Follow that identity to a single hardware unit and tenant. Compare a second unit to check the factory process uses separate identities."
        ],
        "command": "openssl x509 -in \"$CERT\" -noout -serial -dates -fingerprint -sha256",
        "interpret": "Matching two fingerprints confirms the same certificate was observed. Establish tenant binding from the enrollment record, independent of the certificate subject."
      }
    },
    {
      "id": "IOT-03",
      "category": "Device identity",
      "reference": "CWE-672",
      "title": "Trace a device transfer",
      "procedure": "Transfer a test device between two lab tenants using the documented procedure. Review the device inventory and broker authorization receipts.",
      "evidence": "Capture old ownership removal, new enrollment and the timestamp of credential retirement.",
      "level": "Advanced",
      "exercise": {
        "setup": "One spare device, two disposable tenants and the vendor’s supported transfer workflow.",
        "steps": [
          "Record the last telemetry sequence visible to tenant A. Transfer to B and generate a new synthetic measurement.",
          "Compare both tenant dashboards and broker audit records. Check queued messages around the ownership change separately."
        ],
        "command": "",
        "interpret": "Pass when new data and control receipts belong to B and old access expires within policy. Classify late delivery by capture time and delivery time."
      }
    },
    {
      "id": "IOT-04",
      "category": "Fleet operation",
      "reference": "CWE-1104",
      "title": "Find the support lifetime",
      "procedure": "Read the product support URL for security update duration and supported hardware revisions.",
      "evidence": "Record the support end date or identify the missing commitment.",
      "level": "Basic",
      "exercise": {
        "setup": "Open the product support URL and select the exact board revision and sales region.",
        "steps": [
          "Locate the end of security updates and the last supported release for that revision.",
          "Compare the device’s advertised update channel with the support table and record conflicting dates."
        ],
        "command": "",
        "interpret": "An actively maintained product family can include retired boards. Use the revision-specific date or record it as unknown."
      }
    },
    {
      "id": "IOT-05",
      "category": "Fleet operation",
      "reference": "CWE-319",
      "title": "Review telemetry transport",
      "procedure": "Inspect the device-to-broker profile for encryption, trust anchors and certificate expiry behavior.",
      "evidence": "Attach a sanitized profile and the expected response to an expired identity.",
      "level": "Intermediate",
      "exercise": {
        "setup": "Obtain the public broker leaf certificate, intermediate chain and owner-approved root bundle. Set LEAF, CHAIN, ROOTS and BROKER to these local inputs and the expected DNS name.",
        "steps": [
          "Verify the supplied chain and hostname offline. Compare the approved anchors with those provisioned into the device profile.",
          "Check the firmware policy for clock synchronization at boot and for handling verification errors."
        ],
        "command": "openssl verify -purpose sslserver -verify_hostname \"$BROKER\" -CAfile \"$ROOTS\" -untrusted \"$CHAIN\" \"$LEAF\"",
        "interpret": "OK verifies this certificate against the supplied trust inputs at the host’s time. It does not demonstrate how the device handles a failed handshake."
      }
    },
    {
      "id": "IOT-06",
      "category": "Fleet operation",
      "reference": "CWE-494",
      "title": "Trace a fleet update",
      "procedure": "Apply a vendor-signed update to a designated lab device using the normal rollout channel. Compare controller status with the device-reported version.",
      "evidence": "Link package identity, verification event, reboot and final health status.",
      "level": "Advanced",
      "exercise": {
        "setup": "One canary device and an approved signed release. Set IMAGE to the local package and obtain its published digest.",
        "steps": [
          "Compare the local digest with the release record before scheduling the normal rollout.",
          "Follow download, on-device verification, boot slot and post-boot health confirmation. Record both controller version and device-reported version."
        ],
        "command": "shasum -a 256 \"$IMAGE\"",
        "interpret": "A matching hash covers artifact identity. Require the device verification event and successful health confirmation to pass the update workflow."
      }
    },
    {
      "id": "IOT-07",
      "category": "Privacy and reset",
      "reference": "CWE-359",
      "title": "Read sensor collection disclosures",
      "procedure": "Review the public setup guide for collection intervals, cloud destinations and disabling optional sensors.",
      "evidence": "Record the declared settings for one sensor.",
      "level": "Basic",
      "exercise": {
        "setup": "Use the privacy and setup URLs for one optional sensor.",
        "steps": [
          "Record collection cadence, destination, default setting and the control that disables the sensor.",
          "Distinguish local measurement, cloud transmission and historical retention in the published description."
        ],
        "command": "",
        "interpret": "Document each separately. A cloud-upload toggle may leave local sensing enabled by design."
      }
    },
    {
      "id": "IOT-08",
      "category": "Privacy and reset",
      "reference": "CWE-532",
      "title": "Review device support logs",
      "procedure": "Inspect a vendor diagnostic export generated from synthetic activity. Classify identifiers, network settings and sensor readings.",
      "evidence": "Capture a redacted inventory and compare fields with support requirements.",
      "level": "Intermediate",
      "exercise": {
        "setup": "A sanitized JSON support bundle manifest, stored locally as MANIFEST.",
        "steps": [
          "List top-level keys before viewing values. Select the metadata sections and compare them with the approved support schema.",
          "Record any user identifiers or network configuration categories without copying secrets into notes."
        ],
        "command": "jq -r 'keys[]' \"$MANIFEST\"",
        "interpret": "A field name flags a review target. Confirm sensitivity using a synthetic export and retention rules before reporting exposure."
      }
    },
    {
      "id": "IOT-09",
      "category": "Privacy and reset",
      "reference": "CWE-226",
      "title": "Trace factory reset",
      "procedure": "Set up a lab device with synthetic preferences and use the documented reset. Re-enroll it and review the fleet console and local setup state.",
      "evidence": "Show that previous ownership and user settings were cleared and identify separately retained fleet history.",
      "level": "Advanced",
      "exercise": {
        "setup": "A spare unit approved for reset, synthetic network settings and a test cloud tenant.",
        "steps": [
          "Record the device ID, enrollment, a local canary preference and a cloud-side history marker. Perform the documented reset.",
          "Review setup while offline, then re-enroll normally. Compare local settings and cloud history before enabling synchronization."
        ],
        "command": "",
        "interpret": "An erased local preference and a retained cloud record have distinct owners. Compare both with the advertised reset and decommissioning guarantees."
      }
    },
    {
      "id": "IOT-10",
      "category": "Offline behavior and consent",
      "reference": "CWE-755",
      "title": "Read offline operation limits",
      "procedure": "Read the device guide for behavior during a cloud outage and how the device signals degraded service.",
      "evidence": "Record expected local functions and the limits on queued telemetry.",
      "level": "Basic",
      "exercise": {
        "setup": "Open the offline operation guide for the selected model.",
        "steps": [
          "Identify the cloud-dependent actions and the guaranteed duration or size of local buffering.",
          "Record whether reconnect sends the original sampling time and how loss is signaled."
        ],
        "command": "",
        "interpret": "Use the documented bound to size a benign QA fixture. Absence of a bound is a specification gap."
      }
    },
    {
      "id": "IOT-11",
      "category": "Offline behavior and consent",
      "reference": "CWE-400",
      "title": "Inspect offline storage bounds",
      "procedure": "Review the firmware or gateway settings for message queue capacity, expiry and overflow policy.",
      "evidence": "Record byte or message limits and the prescribed drop behavior.",
      "level": "Intermediate",
      "exercise": {
        "setup": "An owner-exported queue profile. Set PROFILE to a sanitized JSON file and adjust the property names to match its documented schema.",
        "steps": [
          "Read capacity, expiry and overflow behavior and record their units.",
          "Compare capacity with the documented sample cadence and typical record size. Estimate how many hours of offline operation fit."
        ],
        "command": "jq '.queue | {maxBytes,maxMessages,ttlSeconds,overflowPolicy}' \"$PROFILE\"",
        "interpret": "Null values may mean the fields use different names or inherited defaults. Resolve the effective configuration before estimating the retention window."
      }
    },
    {
      "id": "IOT-12",
      "category": "Offline behavior and consent",
      "reference": "CWE-359",
      "title": "Trace sensor consent through reconnect",
      "procedure": "Disable optional collection in a lab device, perform a normal offline interval and reconnect. Check the broker event history for the test device.",
      "evidence": "Compare consent time with sensor event times and identify which queued records were delivered.",
      "level": "Advanced",
      "exercise": {
        "setup": "Use a test device on the vendor’s normal QA offline/reconnect fixture. Synchronize device and broker timestamps.",
        "steps": [
          "Capture an allowed measurement, disable collection, and let the device pass through an offline interval.",
          "Reconnect, export the test device’s event timeline and compare sample time, consent time and delivery time."
        ],
        "command": "",
        "interpret": "A pre-withdrawal sample can arrive after reconnect. A newly sampled value after withdrawal is a different result and needs its own evidence."
      }
    },
    {
      "id": "IOT-13",
      "category": "Fleet identity and recovery",
      "level": "Advanced",
      "reference": "CWE-672",
      "title": "Verify device certificate rotation at the broker",
      "procedure": "Correlate replacement credentials with a normal telemetry connection and retirement receipt.",
      "evidence": "Record old and new public fingerprints, broker identity and retirement time.",
      "exercise": {
        "setup": "Two public PEM certificates issued before and after an approved rotation. Set OLD_CERT and NEW_CERT.",
        "steps": [
          "Compare serials, fingerprints and validity intervals. Verify the replacement maps to the same device record.",
          "Trigger ordinary telemetry after rotation, then inspect the broker log for the certificate actually used and the old identity retirement event."
        ],
        "command": "openssl x509 -in \"$OLD_CERT\" -noout -serial -dates -fingerprint -sha256\nopenssl x509 -in \"$NEW_CERT\" -noout -serial -dates -fingerprint -sha256",
        "interpret": "A new certificate on disk does not prove the device selected it. Require the broker-side identity and old credential retirement record."
      }
    },
    {
      "id": "IOT-14",
      "category": "Fleet identity and recovery",
      "level": "Advanced",
      "reference": "CWE-494",
      "title": "Trace an unsuccessful update through fallback",
      "procedure": "Follow a vendor recovery fixture from rollout to the next healthy boot.",
      "evidence": "Link boot slot, verified version, device health and operator-visible result.",
      "exercise": {
        "setup": "A spare unit running the vendor’s recovery acceptance fixture and the known-good fallback image.",
        "steps": [
          "Record the starting slot, version and configuration. Run the vendor-supplied unsuccessful-update fixture and wait for normal boot recovery.",
          "Compare boot selection, retained enrollment, telemetry health and the controller’s rollout status."
        ],
        "command": "",
        "interpret": "The device should settle on the approved verified image within the documented recovery window. Treat a stale controller success message as a separate reporting defect."
      }
    },
    {
      "id": "IOT-15",
      "category": "Fleet identity and recovery",
      "level": "Advanced",
      "reference": "CWE-295",
      "title": "Measure trust decisions before clock synchronization",
      "procedure": "Inspect the order of clock recovery and protected telemetry.",
      "evidence": "Record boot, time sync, certificate decision and first successful message.",
      "exercise": {
        "setup": "Use a vendor QA clock fixture on an isolated device and a known-valid public certificate.",
        "steps": [
          "Record the expected validity window. Observe a cold boot with the documented unset-clock fixture and capture time-sync and connection decisions.",
          "Restore valid time and repeat. Compare the order of time acquisition, verification and first application message."
        ],
        "command": "openssl x509 -in \"$CERT\" -noout -startdate -enddate",
        "interpret": "A delayed handshake may be expected. Confirm the device recovers after time sync and that no protected telemetry was sent before verification."
      }
    },
    {
      "id": "IOT-16",
      "category": "Fleet authorization and messaging",
      "level": "Intermediate",
      "reference": "CWE-863",
      "title": "Reconcile site-scoped operator privileges",
      "procedure": "Compare the effective permissions of site and fleet operators.",
      "evidence": "Record role inheritance, target site and approval owner.",
      "exercise": {
        "setup": "A QA fleet export with pseudonymous device ID, site and support role assignments.",
        "steps": [
          "Select one site operator and one fleet administrator. Trace effective permissions for reading diagnostics and changing settings.",
          "Compare assignments with owner-approved site boundaries and expiry dates for temporary roles."
        ],
        "command": "",
        "interpret": "Report the specific excess capability, site and assignment source. Avoid putting real device identifiers in the report."
      }
    },
    {
      "id": "IOT-17",
      "category": "Fleet authorization and messaging",
      "level": "Advanced",
      "reference": "CWE-841",
      "title": "Measure duplicate effects after reconnect",
      "procedure": "Follow one device sequence through transport redelivery and business persistence.",
      "evidence": "Record repeated deliveries and the corresponding stored record counts.",
      "exercise": {
        "setup": "A synthetic event stream from one device with sequence and sample timestamps. Set EVENTS to an approved JSON Lines broker export.",
        "steps": [
          "Capture ten normal samples, use a supported reconnect, then collect ten more. Preserve sequence and delivery identifiers.",
          "Find repeated sequence values and compare how the downstream consumer handled each delivery."
        ],
        "command": "jq -s 'group_by(.sequence) | map(select(length > 1) | {sequence:.[0].sequence,deliveries:length})' \"$EVENTS\"",
        "interpret": "Repeated delivery can be expected under at-least-once transport. Count persistent business records before classifying a duplicate side effect."
      }
    },
    {
      "id": "IOT-18",
      "category": "Fleet authorization and messaging",
      "level": "Advanced",
      "reference": "CWE-672",
      "title": "Follow an expired device command",
      "procedure": "Trace expiry of a queued setting change when the device reconnects.",
      "evidence": "Match command ID and timestamps with the observed device setting.",
      "exercise": {
        "setup": "A physical lab unit and one harmless supported setting such as LED brightness.",
        "steps": [
          "Read initial state from the device and console. Apply one supported change while the device is offline and record its command expiry.",
          "Reconnect under the vendor QA fixture after expiry and compare pending, acknowledged and applied state across console and unit."
        ],
        "command": "",
        "interpret": "An acknowledgement of delivery is distinct from application. Record expiry, final device value and whether the console accurately reconciled it."
      }
    },
    {
      "id": "IOT-19",
      "category": "Radio and commissioning",
      "level": "Advanced",
      "reference": "CWE-287",
      "title": "Trace BLE commissioning window closure",
      "procedure": "Initiate commissioning through the documented physical control and complete setup with phone A. Record the closing event and elapsed time.",
      "evidence": "Advertising presence and permission to commission are different signals. Record whether a new ownership binding was accepted.",
      "exercise": {
        "setup": "A spare BLE-capable unit, the vendor companion app and two clean QA phones.",
        "steps": [
          "Initiate commissioning through the documented physical control and complete setup with phone A. Record the closing event and elapsed time.",
          "After the documented window, inspect the supported pairing view on phone B and device owner inventory. Repeat after a normal reboot."
        ],
        "command": "",
        "interpret": "Advertising presence and permission to commission are different signals. Record whether a new ownership binding was accepted."
      }
    },
    {
      "id": "IOT-20",
      "category": "Radio and commissioning",
      "level": "Advanced",
      "reference": "CWE-863",
      "title": "Verify broker subscription policy by device role",
      "procedure": "Map each device identity to its own telemetry and command topics. Enter the expected allow and deny combinations into the policy simulator.",
      "evidence": "Capture each decision with principal, operation, topic and rule ID. Treat a simulator/deployment version mismatch as inconclusive.",
      "exercise": {
        "setup": "Two synthetic devices, approved fleet topic inventory and broker policy simulator or offline policy evaluator.",
        "steps": [
          "Map each device identity to its own telemetry and command topics. Enter the expected allow and deny combinations into the policy simulator.",
          "Compare the returned policy decision and matched rule with the broker configuration version actually deployed to the lab."
        ],
        "command": "",
        "interpret": "Capture each decision with principal, operation, topic and rule ID. Treat a simulator/deployment version mismatch as inconclusive."
      }
    },
    {
      "id": "IOT-21",
      "category": "Fleet identity and recovery",
      "level": "Advanced",
      "reference": "CWE-347",
      "title": "Check secure boot evidence across board revisions",
      "procedure": "Record board revision, selected slot, first-stage measurement and verified firmware version for each boot.",
      "evidence": "A matching application hash cannot attest the earlier boot stages. Mark each boot-chain stage independently as verified or unobserved.",
      "exercise": {
        "setup": "Boot measurement receipts for two supported evaluation boards and the vendor-signed reference manifest for each.",
        "steps": [
          "Record board revision, selected slot, first-stage measurement and verified firmware version for each boot.",
          "Compare each measurement with its own revision’s approved manifest, then repeat following a supported signed update."
        ],
        "command": "",
        "interpret": "A matching application hash cannot attest the earlier boot stages. Mark each boot-chain stage independently as verified or unobserved."
      }
    },
    {
      "id": "IOT-22",
      "category": "Fleet authorization and messaging",
      "level": "Advanced",
      "reference": "CWE-778",
      "title": "Reconstruct a device action through gateway failover",
      "procedure": "Record the primary gateway receipt and device acknowledgement, then use the owner’s planned failover operation.",
      "evidence": "The standby should preserve attribution and produce exactly one final change for the new operation. Compare device state with the audit ledger.",
      "exercise": {
        "setup": "A paired QA gateway deployment and a harmless supported setting change.",
        "steps": [
          "Record the primary gateway receipt and device acknowledgement, then use the owner’s planned failover operation.",
          "Submit one new change after failover. Compare correlation IDs, actor, device, controller record and final physical state."
        ],
        "command": "",
        "interpret": "The standby should preserve attribution and produce exactly one final change for the new operation. Compare device state with the audit ledger."
      }
    }
  ]
});
