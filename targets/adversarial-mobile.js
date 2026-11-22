registerTarget({
  "id": "MOB-ADV",
  "name": "Mobile adversarial testing",
  "surface": "Authorized active validation across Android and iOS application boundaries",
  "cases": [
    {
      "id": "MOB-ADV-01",
      "category": "External entry points",
      "reference": "CWE-926",
      "title": "Review exported component and intent surface",
      "level": "Intermediate",
      "procedure": "Inventory Android components and iOS extension or URL entry points that accept requests from outside the application. Compare their caller restrictions, accepted data, and business purpose with the approved integration design.",
      "evidence": "A platform-specific entry-point inventory showing exposure, required permissions or entitlements, intended callers, and the observed authorization decision."
    },
    {
      "id": "MOB-ADV-02",
      "category": "External entry points",
      "reference": "CWE-939",
      "title": "Test deep-link and universal-link authorization",
      "level": "Advanced",
      "procedure": "Exercise approved deep links, Android app links, and iOS universal links from unauthenticated, authenticated, and stale-session states. Verify that navigation parameters cannot replace server-side authorization or workflow prerequisites.",
      "evidence": "A link-to-destination matrix with session state, routing result, authorization result, final application state, and any unintended disclosure or action."
    },
    {
      "id": "MOB-ADV-03",
      "category": "Data protection",
      "reference": "CWE-922",
      "title": "Verify local storage and backup exclusion effectiveness",
      "level": "Intermediate",
      "procedure": "Create synthetic sensitive records through normal application workflows and review their presence in application storage, logs, caches, snapshots, and supported backup or device-transfer outputs. Compare observations with the documented protection policy.",
      "evidence": "A data-item inventory identifying each observed storage location, protection or exclusion control, lifecycle state, and confirmation that secret values were not retained in evidence."
    },
    {
      "id": "MOB-ADV-04",
      "category": "Transport security",
      "reference": "CWE-295",
      "title": "Test certificate pinning and trust-store behavior",
      "level": "Advanced",
      "procedure": "Using an authorized test service and device configuration, compare application behavior for the expected server identity, an untrusted identity, a user-added trust anchor, and documented certificate rotation states. Verify that failures do not silently downgrade transport security.",
      "evidence": "Connection outcomes and application diagnostics for each trust state, including platform, build, network path, certificate identity, and whether protected data was transmitted."
    },
    {
      "id": "MOB-ADV-05",
      "category": "Runtime resilience",
      "reference": "CWE-693",
      "title": "Exercise RASP and integrity response under instrumentation",
      "level": "Advanced",
      "procedure": "On a designated test device and build, observe application responses to owner-approved debugging, instrumentation, repackaging, and device-integrity conditions. Determine whether integrity signals are advisory, locally enforced, or verified by a trusted service.",
      "evidence": "A condition-to-response matrix covering detection source, user-visible behavior, server decision, audit event, recoverability, and false-positive impact."
    },
    {
      "id": "MOB-ADV-06",
      "category": "Authentication and keys",
      "reference": "CWE-305",
      "title": "Test biometric and keystore fallback paths",
      "level": "Advanced",
      "procedure": "Exercise biometric enrollment changes, device credential fallback, application reinstallation, account logout, and supported recovery paths with a disposable account. Verify that key use and high-risk actions retain the intended assurance level.",
      "evidence": "A lifecycle record linking authentication state, key availability, fallback path, protected operation result, and authoritative account or server state."
    },
    {
      "id": "MOB-ADV-07",
      "category": "Interprocess communication",
      "reference": "CWE-862",
      "title": "Check IPC and content-provider access controls",
      "level": "Intermediate",
      "procedure": "Review and exercise documented interprocess interfaces from an authorized companion test application. Verify caller identity, read and write separation, URI grant scope, data minimization, and revocation behavior.",
      "evidence": "An interface matrix showing caller identity, requested operation, permission or entitlement decision, returned data class, grant lifetime, and cleanup result."
    },
    {
      "id": "MOB-ADV-08",
      "category": "Account isolation",
      "reference": "CWE-668",
      "title": "Validate account isolation across profiles and work profiles",
      "level": "Advanced",
      "procedure": "Use approved personal, managed, and secondary profile configurations to verify separation of accounts, files, notifications, links, clipboard content, and application state. Include removal of the managed profile and transfer between profiles where supported.",
      "evidence": "A profile-boundary matrix showing test identities, data canaries, permitted sharing paths, denied paths, administrative policy, and post-removal state."
    },
    {
      "id": "MOB-ADV-09",
      "category": "Permissions and privacy",
      "reference": "CWE-250",
      "title": "Validate runtime permission enforcement and revocation",
      "level": "Intermediate",
      "procedure": "Exercise sensitive features before grant, after grant, after revocation, and after platform-managed permission reset. Confirm that background components and cached state follow the current permission decision.",
      "evidence": "A feature-to-permission matrix with lifecycle state, foreground or background context, user decision, observed access, and application recovery behavior."
    },
    {
      "id": "MOB-ADV-10",
      "category": "Embedded web content",
      "reference": "CWE-749",
      "title": "Test WebView and native-bridge trust boundaries",
      "level": "Advanced",
      "procedure": "Review approved embedded web flows for origin restrictions, navigation control, native bridge exposure, file access, and authentication context. Exercise only owner-controlled content and documented navigation paths.",
      "evidence": "A web-origin and bridge-method inventory showing allowed navigation, exposed native capabilities, caller validation, session boundary, and blocked untrusted origins."
    },
    {
      "id": "MOB-ADV-11",
      "category": "Data exposure",
      "reference": "CWE-200",
      "title": "Check screen, clipboard, and notification exposure",
      "level": "Intermediate",
      "procedure": "Create synthetic sensitive content and observe application switcher snapshots, screen capture behavior, clipboard lifecycle, lock-screen notifications, wearable relays, and accessibility announcements under the supported privacy settings.",
      "evidence": "A channel-by-state matrix showing the synthetic data class, device lock state, privacy setting, exposed representation, retention period, and expected product behavior."
    },
    {
      "id": "MOB-ADV-12",
      "category": "Session lifecycle",
      "reference": "CWE-613",
      "title": "Validate logout, reinstall, and device-transfer boundaries",
      "level": "Advanced",
      "procedure": "With a disposable account, compare session and local-key state after logout, force stop, operating-system restore, application reinstall, device transfer, password change, and remote account revocation where supported.",
      "evidence": "A lifecycle timeline showing local state, server session state, protected operation outcomes, residual data, notifications, and final cleanup for each transition."
    },
    {
      "id": "MOB-ADV-13",
      "category": "Platform integrations",
      "reference": "CWE-862",
      "title": "Test push-notification action authorization",
      "level": "Advanced",
      "procedure": "Exercise approved notification display and action workflows across locked, unlocked, signed-out, expired-session, and account-switched states. Verify that notification content and actions are bound to the current account and server authorization state.",
      "evidence": "Notification and action results by device and account state, including displayed data class, authentication requirement, server decision, resulting record, and audit event."
    }
  ]
});
