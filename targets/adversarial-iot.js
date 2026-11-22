registerTarget({
  "id": "IOT-ADV",
  "name": "IoT adversarial testing",
  "surface": "Authorized active validation of device, protocol, radio, and local interfaces",
  "cases": [
    {
      "id": "IOT-ADV-01",
      "category": "Device access",
      "reference": "CWE-1392",
      "title": "Test default and first-use credentials on local interfaces",
      "level": "Basic",
      "procedure": "Using the documented onboarding flow and a designated lab device, verify whether local administrative, service, and setup interfaces require a unique first-use identity and force ownership establishment before privileged use.",
      "evidence": "A local-interface inventory showing shipping-state access requirements, credential uniqueness, first-use transition, ownership binding, and post-enrollment access result."
    },
    {
      "id": "IOT-ADV-02",
      "category": "Commissioning",
      "reference": "CWE-287",
      "title": "Exercise BLE and local pairing controls",
      "level": "Intermediate",
      "procedure": "Observe an approved device through unclaimed, commissioning, claimed, timed-out, and reset states. Verify physical-presence requirements, pairing-window duration, peer authentication, ownership binding, and handling of concurrent commissioning attempts.",
      "evidence": "A commissioning-state timeline with device identity, initiating peer, user-presence signal, pairing decision, timeout, ownership result, and relevant device or controller events."
    },
    {
      "id": "IOT-ADV-03",
      "category": "Firmware lifecycle",
      "reference": "CWE-494",
      "title": "Verify firmware update authenticity and rollback protection",
      "level": "Advanced",
      "procedure": "Through the supported lab update workflow, compare acceptance of the approved release with owner-provided invalid, mismatched, expired, interrupted, and older-version test artifacts. Verify recovery and fleet reporting without modifying production devices.",
      "evidence": "An artifact-to-result matrix recording model and revision, release identity, verification decision, rollback counter or policy, boot result, recovery state, and controller status."
    },
    {
      "id": "IOT-ADV-04",
      "category": "Messaging authorization",
      "reference": "CWE-862 · https://book.hacktricks.xyz/network-services-pentesting/1883-pentesting-mqtt-mosquitto",
      "title": "Test MQTT authorization and subscription isolation",
      "level": "Advanced",
      "procedure": "With designated devices and tenants, exercise publish and subscribe operations across each documented topic class. Verify that device, tenant, role, retained-message, wildcard, and ownership-transfer boundaries are enforced by the broker.",
      "evidence": "A topic authorization matrix showing client identity, tenant, operation, requested topic class, broker decision, delivered message scope, and correlated audit record."
    },
    {
      "id": "IOT-ADV-05",
      "category": "Physical and debug interfaces",
      "reference": "CWE-1191",
      "title": "Check debug and local serial interface exposure",
      "level": "Intermediate",
      "procedure": "Inspect the designated hardware revision for documented and undocumented debug, console, test-pad, and local service interfaces. Verify the production-state access policy and whether sensitive output or privileged control is available without the approved service process.",
      "evidence": "Annotated interface locations and observed production-state behavior, including access prerequisite, data classification, privilege level, device state, and service documentation comparison."
    },
    {
      "id": "IOT-ADV-06",
      "category": "Command integrity",
      "reference": "CWE-294",
      "title": "Validate offline command replay and state consistency",
      "level": "Advanced",
      "procedure": "Using harmless lab commands, exercise duplicate, delayed, expired, reordered, and reconnect-delivered operations across device offline and online transitions. Reconcile device state with controller, broker, and audit records.",
      "evidence": "A command timeline with identity, freshness data, delivery state, device decision, authoritative final state, acknowledgement, duplicate handling, and audit correlation."
    },
    {
      "id": "IOT-ADV-07",
      "category": "Radio and protocol security",
      "reference": "CWE-306",
      "title": "Test radio and protocol-level authentication",
      "level": "Advanced",
      "procedure": "For each approved radio or local protocol, compare discovery, session establishment, command, and telemetry behavior for enrolled, unenrolled, revoked, and cross-tenant peers. Keep testing within the lab radio boundary and approved channels.",
      "evidence": "A protocol-state matrix showing peer identity, device state, authentication and freshness decision, permitted operation, observed data class, and rejection behavior."
    },
    {
      "id": "IOT-ADV-08",
      "category": "Local management",
      "reference": "CWE-862",
      "title": "Test local web and service authorization",
      "level": "Intermediate",
      "procedure": "Inventory local web, discovery, administration, and service interfaces on the designated network. Exercise documented functions with unauthenticated, owner, non-owner, and service identities and verify that interface discovery does not grant privileged access.",
      "evidence": "A service-to-role matrix with network context, identity, exposed metadata, authorization decision, resulting state, and applicable device log entry."
    },
    {
      "id": "IOT-ADV-09",
      "category": "Network privacy",
      "reference": "CWE-319",
      "title": "Validate sensitive-data protection on local networks",
      "level": "Intermediate",
      "procedure": "Capture owner-approved lab traffic during onboarding, normal operation, recovery, and update checks. Classify visible identifiers, telemetry, commands, credentials, and metadata and compare transport protection with the product design.",
      "evidence": "A flow inventory identifying endpoints, protocol, protection state, visible data classes, device lifecycle phase, certificate or peer identity, and retained sanitized capture references."
    },
    {
      "id": "IOT-ADV-10",
      "category": "Ownership lifecycle",
      "reference": "CWE-459",
      "title": "Validate reset, decommission, and ownership transfer",
      "level": "Advanced",
      "procedure": "Move a lab device through supported factory reset, decommission, resale, and re-enrollment workflows. Verify retirement of credentials, local data removal, tenant detachment, queued-message handling, and loss of access by the previous owner.",
      "evidence": "A before-and-after ownership record linking device identity, tenant inventories, local data canaries, credentials, queued data, prior-owner access, and new-owner enrollment."
    },
    {
      "id": "IOT-ADV-11",
      "category": "Device identity",
      "reference": "CWE-798",
      "title": "Validate per-device identity and credential rotation",
      "level": "Advanced",
      "procedure": "Compare identity material across designated devices and exercise the supported renewal, revocation, replacement, and recovery workflows. Verify that a retired identity cannot resume service or cross device and tenant boundaries.",
      "evidence": "A credential-lifecycle record showing unique device binding, issuer, activation and retirement times, rotation result, service decision, tenant association, and recovery audit trail."
    }
  ]
});
