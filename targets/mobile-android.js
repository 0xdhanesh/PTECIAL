registerTarget({
  "id": "AND",
  "name": "Android",
  "surface": "Android storage, components and runtime protection",
  "cases": [
    {
      "id": "AND-01",
      "category": "Application identity",
      "reference": "CWE-345",
      "title": "Identify the distribution listing",
      "procedure": "Read the supplied store or release URL for publisher, package identity and supported OS versions.",
      "evidence": "Save the expected distribution identity for comparison with the installed build.",
      "level": "Basic",
      "exercise": {
        "setup": "Use the app’s public listing URL.",
        "steps": [
          "Open the developer contact and compare its domain with the organization’s release page.",
          "Record the package identifier in the listing URL and the date you reviewed it."
        ],
        "command": "",
        "interpret": "A matching display name is weak evidence. Use the package identifier to select the artifact for AND-03."
      }
    },
    {
      "id": "AND-02",
      "category": "Application identity",
      "reference": "CWE-926",
      "title": "Inspect exported components",
      "procedure": "Review the release manifest for exported activities, receivers and providers. Compare permissions with the integration specification.",
      "evidence": "Record each external entry point and the approved caller boundary.",
      "level": "Intermediate",
      "exercise": {
        "setup": "Android SDK Command-Line Tools and an owner-supplied release APK. Set APK to its local path.",
        "steps": [
          "Print the merged manifest. Make a row per exported component with its permission and business purpose.",
          "Check provider read and write permissions separately, including temporary URI grants."
        ],
        "command": "apkanalyzer manifest print \"$APK\"",
        "interpret": "An exported launcher activity is expected. An exported data provider with no documented caller restriction needs code-level review before assigning an outcome."
      }
    },
    {
      "id": "AND-03",
      "category": "Application identity",
      "reference": "CWE-347",
      "title": "Trace an Android signing transition",
      "procedure": "Follow a supported update on a test device. Compare the expected signing history with installed package metadata and retained app data.",
      "evidence": "Attach package identities before and after, installer result and data continuity evidence.",
      "level": "Advanced",
      "exercise": {
        "setup": "Two official APKs for consecutive supported versions and Android SDK Build Tools. Set OLD_APK and NEW_APK.",
        "steps": [
          "Verify both artifacts and save their signer fingerprints. Compare them against the release team’s signing record.",
          "Use the supported update path on a test device. Record whether the same synthetic profile survived."
        ],
        "command": "apksigner verify --verbose --print-certs \"$OLD_APK\"\napksigner verify --verbose --print-certs \"$NEW_APK\"",
        "interpret": "A changed fingerprint requires the approved signing lineage and a compatible device update result. A hash difference alone is normal."
      }
    },
    {
      "id": "AND-04",
      "category": "Data lifecycle",
      "reference": "CWE-359",
      "title": "Read the data safety declaration",
      "procedure": "At the listing URL, review data types, sharing purposes and the deletion route.",
      "evidence": "Record declared sensitive data and where a user can request deletion.",
      "level": "Basic",
      "exercise": {
        "setup": "Use the public store listing and linked privacy policy.",
        "steps": [
          "Choose a specific declared data type such as location. Record collection purpose and optionality.",
          "Locate the deletion link from the listing and record whether it identifies this app and data type."
        ],
        "command": "",
        "interpret": "Separate a missing disclosure from observed collection. The latter needs runtime evidence."
      }
    },
    {
      "id": "AND-05",
      "category": "Data lifecycle",
      "reference": "CWE-922",
      "title": "Inspect backup exclusions",
      "procedure": "Compare backup rules, included domains and locally cached account data in a provided test build.",
      "evidence": "Show that sensitive stores are excluded or protected under the approved design.",
      "level": "Intermediate",
      "exercise": {
        "setup": "Release APK and resolved backup-rule XML from the corresponding build.",
        "steps": [
          "Inspect the application element for allowBackup, fullBackupContent and dataExtractionRules.",
          "Trace each referenced file to its rules for cloud backup and device transfer. Compare database, shared preferences and file domains against the data inventory."
        ],
        "command": "apkanalyzer manifest print \"$APK\"\napkanalyzer files list \"$APK\"",
        "interpret": "A resource path proves only that rules were packaged. Record rule contents, applicable OS version and transport before concluding that a sensitive store is excluded."
      }
    },
    {
      "id": "AND-06",
      "category": "Data lifecycle",
      "reference": "CWE-359",
      "title": "Trace permission withdrawal",
      "procedure": "Grant a discretionary permission, complete its normal feature, revoke it in Android settings and repeat the feature.",
      "evidence": "Capture the fallback UI, OS permission state and cessation of new collection.",
      "level": "Advanced",
      "exercise": {
        "setup": "Use a disposable account on one QA device with a feature that requests location or camera access. Set PACKAGE to its application ID.",
        "steps": [
          "Capture the package permission state before and after withdrawal through Android Settings.",
          "Repeat the same feature and record its degraded behavior and any new synthetic telemetry event."
        ],
        "command": "adb shell dumpsys package \"$PACKAGE\"",
        "interpret": "The system grant should change and the feature should handle denial. Distinguish previously cached observations from new collection by their timestamps."
      }
    },
    {
      "id": "AND-07",
      "category": "Runtime application self-protection",
      "reference": "MASVS-RESILIENCE-1",
      "title": "Find the device integrity support policy",
      "procedure": "At the product support URL, locate the policy for unsupported Android device states.",
      "evidence": "Capture the stated protection scope and user recovery route, or record the documentation gap.",
      "level": "Basic",
      "exercise": {
        "setup": "Use the support URL for a feature gated by device integrity.",
        "steps": [
          "Identify which actions are protected and whether ordinary read access remains available.",
          "Record the documented recovery route for a supported device that receives a transient failure."
        ],
        "command": "",
        "interpret": "Report a missing support path as a documentation gap. Record enforcement separately in AND-09."
      }
    },
    {
      "id": "AND-08",
      "category": "Runtime application self-protection",
      "reference": "MASVS-RESILIENCE-1",
      "title": "Review Android RASP decisions",
      "procedure": "Review the release integration for device integrity verdicts, expiry and unavailable-service handling.",
      "evidence": "Record where a verdict is evaluated and the response prescribed for each state.",
      "level": "Intermediate",
      "exercise": {
        "setup": "Release policy matrix and sanitized backend decision samples. Set VERDICTS to an approved JSON Lines export with verdict and decision fields.",
        "steps": [
          "Compare valid, expired and unavailable service outcomes against the policy for the same action.",
          "Group the supplied samples and inspect any combination that diverges from the expected matrix."
        ],
        "command": "jq -s 'group_by([.verdict,.decision]) | map({verdict:.[0].verdict,decision:.[0].decision,count:length})' \"$VERDICTS\"",
        "interpret": "A missing row is a coverage gap. Check the backend decision and policy version before treating a client warning as enforcement."
      }
    },
    {
      "id": "AND-09",
      "category": "Runtime application self-protection",
      "reference": "MASVS-RESILIENCE-1",
      "title": "Trace a negative integrity verdict",
      "procedure": "Use the vendor-provided QA verdict fixture with a test account. Follow one protected operation from verdict receipt through the server decision to the device message.",
      "evidence": "Correlate policy version, refusal of the protected operation, audit event and normal recovery after a valid fixture.",
      "level": "Advanced",
      "exercise": {
        "setup": "Use the integrity provider’s QA verdicts and a disposable protected transaction.",
        "steps": [
          "Run a valid control transaction and save its receipt. Repeat with the documented negative verdict on a second test record.",
          "Compare backend decision, transaction ledger and user message. Restore the valid fixture and complete a fresh transaction."
        ],
        "command": "",
        "interpret": "Pass when the negative case creates no protected side effect and the positive controls succeed on both sides of it. An outage affecting all three runs is inconclusive."
      }
    },
    {
      "id": "AND-10",
      "category": "Network trust and app links",
      "reference": "CWE-939",
      "title": "Identify supported Android links",
      "procedure": "Read the public app-link guide for approved hosts and the expected user experience.",
      "evidence": "Record the declared domains and which links require a signed-in account.",
      "level": "Basic",
      "exercise": {
        "setup": "Open the published app-link documentation.",
        "steps": [
          "Choose one documented host and HTTPS route. Record the expected app destination and authentication condition.",
          "Open the ordinary link in a browser and capture the fallback destination."
        ],
        "command": "",
        "interpret": "A web fallback can be intentional. Assess the verified device association separately from routing."
      }
    },
    {
      "id": "AND-11",
      "category": "Network trust and app links",
      "reference": "CWE-295",
      "title": "Review Android trust configuration",
      "procedure": "Compare the release network security configuration with debug overrides and the approved CA inventory.",
      "evidence": "Attach release domain rules and show the build variant that selects them.",
      "level": "Intermediate",
      "exercise": {
        "setup": "Release and debug build outputs and the approved CA inventory.",
        "steps": [
          "Inspect both merged manifests and resolve the networkSecurityConfig resources from the corresponding build outputs.",
          "Compare trust anchors, cleartext exceptions and inherited domain rules. Verify the debuggable flag on the shipped APK."
        ],
        "command": "apkanalyzer manifest debuggable \"$APK\"\napkanalyzer manifest print \"$APK\"",
        "interpret": "Record the effective policy for each host. A debug-only anchor in source is insufficient evidence of release trust."
      }
    },
    {
      "id": "AND-12",
      "category": "Network trust and app links",
      "reference": "CWE-939",
      "title": "Trace a verified app link",
      "procedure": "Open a documented benign link on a clean Android test device, then follow its normal authentication flow. Inspect the OS domain verification status.",
      "evidence": "Match verified host, destination screen and account boundary.",
      "level": "Advanced",
      "exercise": {
        "setup": "An Android 12+ QA device with the release build installed and a documented benign HTTPS link.",
        "steps": [
          "Record domain verification state and user selections. Open the link from another app while signed out.",
          "After normal login, compare the destination and account context with the expected route."
        ],
        "command": "adb shell pm get-app-links \"$PACKAGE\"",
        "interpret": "Separate OS association failure, user-disabled handling and an incorrect in-app destination. Capture one observation at each layer."
      }
    },
    {
      "id": "AND-13",
      "category": "Build and platform boundaries",
      "level": "Intermediate",
      "reference": "CWE-489",
      "title": "Verify the shipped debug flag",
      "procedure": "Compare release and debug APK metadata against distribution policy.",
      "evidence": "Attach both flags with the release digest.",
      "exercise": {
        "setup": "Two APKs from the same release candidate, labeled debug and release.",
        "steps": [
          "Capture both build flags alongside their artifact hashes. Compare with the approved distribution channel.",
          "Confirm the file offered by release engineering matches the reviewed release digest."
        ],
        "command": "apkanalyzer manifest debuggable \"$DEBUG_APK\"\napkanalyzer manifest debuggable \"$RELEASE_APK\"\nshasum -a 256 \"$RELEASE_APK\"",
        "interpret": "A true result on the release artifact conflicts with a non-debuggable release policy. A false result establishes only this one setting."
      }
    },
    {
      "id": "AND-14",
      "category": "Build and platform boundaries",
      "level": "Advanced",
      "reference": "CWE-732",
      "title": "Measure the lifetime of a shared document grant",
      "procedure": "Follow a synthetic file through Android’s supported sharing workflow.",
      "evidence": "Record recipient, grant scope, expiry and post-expiry observation.",
      "exercise": {
        "setup": "Two test profiles, a synthetic document and a cooperating QA receiver with normal share support.",
        "steps": [
          "Share one test file using the Android picker. Record the receiver, grant lifetime and read/write flags from the QA instrumentation.",
          "Finish the documented session, reopen the receiver and check its normal document view. Distinguish a local copy from renewed access using a new revision."
        ],
        "command": "",
        "interpret": "A cached copy may legitimately survive. Evaluate continued access to new revisions against the grant contract."
      }
    },
    {
      "id": "AND-15",
      "category": "Build and platform boundaries",
      "level": "Intermediate",
      "reference": "CWE-250",
      "title": "Reconcile declared permissions with feature use",
      "procedure": "Trace new permissions to a specific feature and its denial behavior.",
      "evidence": "Record each new permission, requesting feature and owner.",
      "exercise": {
        "setup": "Set APK to a local release candidate. Have the approved permission list for the matching variant.",
        "steps": [
          "Print declared permissions and identify additions compared with the signed-off release list.",
          "For each addition, locate the first feature that requests it, its rationale and the fallback after denial."
        ],
        "command": "apkanalyzer manifest permissions \"$APK\"",
        "interpret": "A manifest declaration is distinct from an active grant. Report the declaration and observed request separately."
      }
    },
    {
      "id": "AND-16",
      "category": "Profile isolation and notifications",
      "level": "Advanced",
      "reference": "CWE-359",
      "title": "Trace data through a work-profile lock",
      "procedure": "Observe work and personal data on system surfaces during profile transitions.",
      "evidence": "Attach a state matrix for both profiles.",
      "exercise": {
        "setup": "Use a diagnostic build with a synthetic work profile and a personal test profile.",
        "steps": [
          "Create distinct canary records in each profile. Switch profiles normally and check notification previews, recents and document pickers.",
          "Lock the work profile, repeat the personal-profile observations, then unlock and confirm the work record returns."
        ],
        "command": "",
        "interpret": "Identify the exact surface, profile and state where a canary appeared. Redact notification text in the evidence."
      }
    },
    {
      "id": "AND-17",
      "category": "Runtime application self-protection",
      "level": "Advanced",
      "reference": "MASVS-RESILIENCE-1",
      "title": "Measure RASP behavior after verdict expiry",
      "procedure": "Exercise the documented grace period and recovery using provider fixtures.",
      "evidence": "Link verdict age, action class, decision and recovery event.",
      "exercise": {
        "setup": "QA build with the owner’s network-failure fixture for integrity checks. Agree the maximum cached-verdict age.",
        "steps": [
          "Capture a valid decision, use the fixture to make the provider unavailable and exercise the documented grace interval.",
          "Use a QA clock fixture to cross expiry. Compare the protected action with a read-only action and restore service."
        ],
        "command": "",
        "interpret": "Pass when the two actions follow their documented policies on both sides of expiry and normal service resumes. Record the backend decision time."
      }
    },
    {
      "id": "AND-18",
      "category": "Profile isolation and notifications",
      "level": "Advanced",
      "reference": "CWE-359",
      "title": "Follow push registration through sign-out",
      "procedure": "Distinguish lock-screen disclosure from delivery to a retired account binding.",
      "evidence": "Capture timestamps and redacted synthetic event identifiers.",
      "exercise": {
        "setup": "A test device with a release-like build, synthetic account and one notification-producing action.",
        "steps": [
          "Generate a uniquely named event. Compare unlocked, locked and hidden-content previews under the approved settings.",
          "Sign out, trigger a second event from the QA console and inspect delivery records and the visible notification list."
        ],
        "command": "",
        "interpret": "Distinguish a stale notification from a new delivery. The second event identifier establishes whether the prior account remained subscribed."
      }
    },
    {
      "id": "AND-19",
      "category": "Cryptography and account storage",
      "level": "Advanced",
      "reference": "MASVS-STORAGE-1",
      "title": "Measure offline cache expiry",
      "procedure": "Open both documents and record their initial cache status.",
      "evidence": "Compare file inventory, previews and access to the original bytes. A missing list entry alone does not demonstrate expiry.",
      "exercise": {
        "setup": "A QA clock fixture, disposable account and two synthetic documents with different retention settings.",
        "steps": [
          "Open both documents and record their initial cache status.",
          "Advance the fixture past only the shorter TTL, reopen offline and repeat after process restart."
        ],
        "command": "",
        "interpret": "Compare file inventory, previews and access to the original bytes. A missing list entry alone does not demonstrate expiry."
      }
    },
    {
      "id": "AND-20",
      "category": "Cryptography and account storage",
      "level": "Advanced",
      "reference": "MASVS-CRYPTO-2",
      "title": "Trace a device-bound key across reinstall",
      "procedure": "Create an encrypted synthetic record and capture the alias and reported security level without exporting key material.",
      "evidence": "Compare the newly provisioned alias identity and recovery path. Hardware-backed storage claims require the platform-reported security level.",
      "exercise": {
        "setup": "A disposable device, diagnostic build that reports key alias metadata, and a documented reinstall workflow.",
        "steps": [
          "Create an encrypted synthetic record and capture the alias and reported security level without exporting key material.",
          "Perform a supported reinstall on the disposable profile, restore its test data and observe recovery or reauthentication."
        ],
        "command": "",
        "interpret": "Compare the newly provisioned alias identity and recovery path. Hardware-backed storage claims require the platform-reported security level."
      }
    },
    {
      "id": "AND-21",
      "category": "Build and platform boundaries",
      "level": "Advanced",
      "reference": "CWE-939",
      "title": "Follow notification navigation across account changes",
      "procedure": "Deliver a private synthetic notification for A, switch normally to B and open the existing notification.",
      "evidence": "Bind the result to the destination account and message ID. A blocked network read can coexist with a stale preview.",
      "exercise": {
        "setup": "Two test accounts, one app installation and a QA push console.",
        "steps": [
          "Deliver a private synthetic notification for A, switch normally to B and open the existing notification.",
          "Record whether the destination requests the correct identity, what appears in the preview and which record the backend returns."
        ],
        "command": "",
        "interpret": "Bind the result to the destination account and message ID. A blocked network read can coexist with a stale preview."
      }
    },
    {
      "id": "AND-22",
      "category": "Runtime application self-protection",
      "level": "Advanced",
      "reference": "MASVS-RESILIENCE-1",
      "title": "Check integrity policy across an app update",
      "procedure": "Record decisions for a protected transaction on the old release, then update through the supported channel.",
      "evidence": "Attribute a regression to a release only when the accounts, verdict fixtures and policy versions match or their differences are accounted for.",
      "exercise": {
        "setup": "Two approved releases and a provider test account with deterministic verdicts.",
        "steps": [
          "Record decisions for a protected transaction on the old release, then update through the supported channel.",
          "Repeat valid and degraded QA verdicts on the new release and compare backend policy versions and decision receipts."
        ],
        "command": "",
        "interpret": "Attribute a regression to a release only when the accounts, verdict fixtures and policy versions match or their differences are accounted for."
      }
    }
  ]
});
