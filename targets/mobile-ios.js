registerTarget({
  "id": "IOS",
  "name": "iOS",
  "surface": "Entitlements, data protection and runtime protection",
  "cases": [
    {
      "id": "IOS-01",
      "category": "Identity and entitlements",
      "reference": "CWE-345",
      "title": "Identify the iOS seller and build",
      "procedure": "Read the App Store or enterprise release URL for seller, version and minimum OS.",
      "evidence": "Capture the expected identity and supported distribution channel.",
      "level": "Basic",
      "exercise": {
        "setup": "Open the supplied App Store listing and the developer’s release page.",
        "steps": [
          "Record the numeric store ID, seller and minimum OS. Locate the release history entry for the reviewed version.",
          "Compare the seller’s support domain with the organization that supplied the test build."
        ],
        "command": "",
        "interpret": "Use the matching version and distribution channel when requesting the signed artifact. A store display name alone cannot identify a build."
      }
    },
    {
      "id": "IOS-02",
      "category": "Identity and entitlements",
      "reference": "CWE-250",
      "title": "Inspect signed entitlements",
      "procedure": "Compare the release entitlements for app groups, keychain access and associated domains with the approved capability list.",
      "evidence": "Record unexpected groups or capabilities and the signing team identifier.",
      "level": "Intermediate",
      "exercise": {
        "setup": "On macOS, set APP to the supplied, unpacked .app bundle from the distribution archive.",
        "steps": [
          "Read entitlements from the signed app. Repeat for each included extension that uses shared data.",
          "Compare application identifier, keychain access groups and app groups with the approved sharing diagram."
        ],
        "command": "codesign -d --entitlements :- \"$APP\"",
        "interpret": "Approval applies to specific group identifiers. An entitlement authorizes access and does not prove that sensitive data entered a container."
      }
    },
    {
      "id": "IOS-03",
      "category": "Identity and entitlements",
      "reference": "CWE-862",
      "title": "Trace a shared-container handoff",
      "procedure": "Save synthetic content using the app and open it in its approved extension. Compare group membership and the resulting shared files.",
      "evidence": "Show the producing and consuming identities, container and intended data subset.",
      "level": "Advanced",
      "exercise": {
        "setup": "A QA device, an approved share extension and two synthetic documents.",
        "steps": [
          "Place one document in private app storage and share the other through the supported extension. Record the extension input and shared container inventory using owner diagnostics.",
          "Relaunch the extension and compare its visible documents with the approved sharing contract."
        ],
        "command": "",
        "interpret": "Match content by canary identifier. A thumbnail or cached filename is a separate exposure from access to document contents."
      }
    },
    {
      "id": "IOS-04",
      "category": "Privacy and storage",
      "reference": "CWE-359",
      "title": "Review privacy labels",
      "procedure": "Read the privacy label and linked policy at the product URL for tracking and linked data.",
      "evidence": "Capture the declared purposes and any inconsistent statements.",
      "level": "Basic",
      "exercise": {
        "setup": "Open the app listing and its linked privacy policy.",
        "steps": [
          "Choose one data type marked as linked to identity and one optional category. Record purpose, recipient and consent language for each.",
          "Follow the published route to change that choice and save the exact control or help section."
        ],
        "command": "",
        "interpret": "A declaration mismatch is a publication issue. Link runtime evidence separately when claiming actual transmission."
      }
    },
    {
      "id": "IOS-05",
      "category": "Privacy and storage",
      "reference": "CWE-922",
      "title": "Review file protection classes",
      "procedure": "Inspect file protection attributes and keychain accessibility on sample account records using an approved diagnostic build.",
      "evidence": "Compare observed classes with the need for access while locked.",
      "level": "Intermediate",
      "exercise": {
        "setup": "Physical QA device and owner diagnostics that report file protection and keychain accessibility without returning secret values.",
        "steps": [
          "Create synthetic records through the app and record their assigned protection classes.",
          "Lock the device, allow the protection transition to finish and use the supported background diagnostic to record success or the platform error. Repeat unlocked."
        ],
        "command": "",
        "interpret": "Compare results with the specified class and lifecycle state. A simulator or foreground-only observation cannot settle locked-device access."
      }
    },
    {
      "id": "IOS-06",
      "category": "Privacy and storage",
      "reference": "CWE-359",
      "title": "Trace logout and re-enrollment",
      "procedure": "Sign out of a synthetic account and enroll a second test account on the same device. Review caches, visible history and keychain item ownership.",
      "evidence": "Document separation between the two profiles and any permitted device-level settings.",
      "level": "Advanced",
      "exercise": {
        "setup": "Two disposable accounts A and B on one test device.",
        "steps": [
          "Create a distinct document and avatar for A, sign out normally and sign into B. Inspect recents, offline views and extension suggestions.",
          "Compare diagnostic keychain item ownership before and after sign-out without exporting values. Reopen B offline to check cached views."
        ],
        "command": "",
        "interpret": "Distinguish device preferences from A-owned data. Record the specific store or UI surface retaining an A canary."
      }
    },
    {
      "id": "IOS-07",
      "category": "Runtime application self-protection",
      "reference": "MASVS-RESILIENCE-1",
      "title": "Locate the device eligibility policy",
      "procedure": "Read the iOS support URL for device eligibility and recovery if protection checks fail.",
      "evidence": "Record the user-facing policy and its applicability to high-value actions.",
      "level": "Basic",
      "exercise": {
        "setup": "Start at the product’s iOS eligibility or support page.",
        "steps": [
          "Find the protected operation, the eligibility message and the user recovery instructions.",
          "Record whether an unsupported OS, transient attestation outage and rejected device state lead to different support paths."
        ],
        "command": "",
        "interpret": "Save a documentation gap separately from an enforcement finding. The protected transaction is tested in IOS-09."
      }
    },
    {
      "id": "IOS-08",
      "category": "Runtime application self-protection",
      "reference": "MASVS-RESILIENCE-1",
      "title": "Review iOS RASP integration",
      "procedure": "Inspect the owner-supplied integrity decision diagram and build configuration for release-only behavior and unavailable verdicts.",
      "evidence": "Capture build identity, decision owner and expected handling for each verdict.",
      "level": "Intermediate",
      "exercise": {
        "setup": "Set APP to the archived iOS release bundle. Obtain the server’s expected App Attest environment and fallback policy.",
        "steps": [
          "Read signed entitlements from the archived app. Compare the attestation environment with the release configuration.",
          "Trace one sanitized QA decision from attestation receipt to the relying service and identify who approves a fallback."
        ],
        "command": "codesign -d --entitlements :- \"$APP\"",
        "interpret": "Entitlement presence alone establishes configuration. Record server-side decisions separately, including unsupported-device behavior."
      }
    },
    {
      "id": "IOS-09",
      "category": "Runtime application self-protection",
      "reference": "MASVS-RESILIENCE-1",
      "title": "Trace an attestation failure",
      "procedure": "Use an approved test attestation response in the QA environment. Follow challenge issuance, failed validation and the user-visible outcome for a protected action.",
      "evidence": "Match challenge and audit identifiers, confirm no protected state change and verify recovery with a valid test response.",
      "level": "Advanced",
      "exercise": {
        "setup": "Vendor-supported QA responses and one disposable protected record per attempt.",
        "steps": [
          "Capture a valid baseline, then select the negative QA response and request the same protected operation on a new record.",
          "Compare the server decision with the record ledger and the app message. Restore the valid response and repeat on a fresh record."
        ],
        "command": "",
        "interpret": "Require a denial with zero protected state changes and a successful recovery control. Keep challenge identifiers and timestamps, excluding attestation tokens."
      }
    },
    {
      "id": "IOS-10",
      "category": "Transport and links",
      "reference": "CWE-939",
      "title": "Inventory advertised universal links",
      "procedure": "Read the public linking guide for supported hosts and destinations.",
      "evidence": "Record intended deep links and prerequisites for a private destination.",
      "level": "Basic",
      "exercise": {
        "setup": "Use the public universal-link guide and its linked website.",
        "steps": [
          "Select one supported public link and one private account link. Record expected web fallback and signed-out destination for each.",
          "Record all declared hosts, including any distinct production and testing subdomains."
        ],
        "command": "",
        "interpret": "These are expected routes. Validate them on an installed device in IOS-12."
      }
    },
    {
      "id": "IOS-11",
      "category": "Transport and links",
      "reference": "CWE-319",
      "title": "Inspect transport exceptions",
      "procedure": "Review the signed app’s App Transport Security configuration and compare every exception with its change approval.",
      "evidence": "List affected domains, business rationale and expiry date.",
      "level": "Intermediate",
      "exercise": {
        "setup": "Set APP to the unpacked production .app on macOS. Have the approved exception list.",
        "steps": [
          "Read NSAppTransportSecurity from the shipped Info.plist. Review broad allowances as well as per-domain entries and subdomain inheritance.",
          "Compare each effective exception with its approved recipient, business purpose and expiry date."
        ],
        "command": "plutil -extract NSAppTransportSecurity xml1 -o - \"$APP/Info.plist\"",
        "interpret": "An absent dictionary usually leaves platform defaults in effect. Record it as absent and review separately any networking stack outside ATS coverage."
      }
    },
    {
      "id": "IOS-12",
      "category": "Transport and links",
      "reference": "CWE-939",
      "title": "Trace a universal link handoff",
      "procedure": "Use a documented account link on a clean test device while signed out. Complete the supported sign-in and inspect the destination.",
      "evidence": "Show the associated domain, authentication step and final account context.",
      "level": "Advanced",
      "exercise": {
        "setup": "An installed device, a documented link and the matching signed app archive.",
        "steps": [
          "Review associated-domains entitlements and the published association file for the exact host.",
          "Open a documented link from Notes, observe the signed-out screen, then finish authentication. Record the final record and account context."
        ],
        "command": "codesign -d --entitlements :- \"$APP\"",
        "interpret": "Separate entitlement mismatch, association-file mismatch and app routing behavior. A user preference to open Safari can affect the observed result."
      }
    },
    {
      "id": "IOS-13",
      "category": "System surfaces and privacy",
      "level": "Intermediate",
      "reference": "CWE-359",
      "title": "Inspect app-switcher snapshots across transitions",
      "procedure": "Compare background previews with a private screen, modal and signed-out state.",
      "evidence": "Capture the preview for each transition and identify any visible synthetic marker.",
      "exercise": {
        "setup": "A physical device, synthetic account and an app screen that displays a private record.",
        "steps": [
          "Place a visible test marker on screen, send the app to the background and inspect its app-switcher card.",
          "Repeat with a modal open and after sign-out. Record OS version and whether the preview is masked in each state."
        ],
        "command": "",
        "interpret": "Report the specific transition that leaves the marker visible. Use redacted captures of synthetic data."
      }
    },
    {
      "id": "IOS-14",
      "category": "System surfaces and privacy",
      "level": "Intermediate",
      "reference": "CWE-359",
      "title": "Reconcile bundled privacy manifests",
      "procedure": "Match app and SDK privacy declarations with the released artifact.",
      "evidence": "Record each manifest path, owner and discrepancy.",
      "exercise": {
        "setup": "Set APP to a local release bundle and identify one SDK that declares data use.",
        "steps": [
          "Inventory packaged privacy manifests and read the app-level declaration when present.",
          "Compare the SDK’s declared collected-data categories and required-reason API entries with the release inventory."
        ],
        "command": "find \"$APP\" -name PrivacyInfo.xcprivacy -print",
        "interpret": "An embedded manifest belongs to its containing bundle. A missing app-level file alone does not establish a discrepancy in an SDK declaration."
      }
    },
    {
      "id": "IOS-15",
      "category": "System surfaces and privacy",
      "level": "Advanced",
      "reference": "CWE-359",
      "title": "Trace limited photo access after consent changes",
      "procedure": "Measure access and caching before and after changing the OS selection.",
      "evidence": "Document selected assets and cached previews separately.",
      "exercise": {
        "setup": "Use a physical QA device and a feature with an optional permission.",
        "steps": [
          "Choose limited access in the OS prompt and grant one synthetic item. Record the selected and unselected items visible in the app.",
          "Change the selection in Settings, relaunch and repeat after switching accounts. Check thumbnails as well as original content."
        ],
        "command": "",
        "interpret": "Determine whether a retained preview is an app cache or newly granted OS access. Match the update with the documented retention behavior."
      }
    },
    {
      "id": "IOS-16",
      "category": "Runtime application self-protection",
      "level": "Advanced",
      "reference": "MASVS-RESILIENCE-1",
      "title": "Follow attestation outage recovery",
      "procedure": "Measure retries and protected side effects during provider recovery.",
      "evidence": "Correlate provider availability, decisions and the final transaction count.",
      "exercise": {
        "setup": "Server test environment with a controllable App Attest service fixture and a documented retry schedule.",
        "steps": [
          "Record a successful baseline, then switch to the provider-unavailable fixture. Capture retry timing, user messaging and transaction state.",
          "Restore service while the pending request exists. Inspect whether the retry and any manual resubmission resolve to one business event."
        ],
        "command": "",
        "interpret": "A duplicate ledger entry is a separate failure from an integrity denial. Preserve correlation IDs for each attempt."
      }
    },
    {
      "id": "IOS-17",
      "category": "Identity and entitlements",
      "level": "Intermediate",
      "reference": "CWE-250",
      "title": "Compare app and extension capabilities",
      "procedure": "Identify entitlement differences that broaden extension access.",
      "evidence": "Record exact group identifiers and the intended consumers.",
      "exercise": {
        "setup": "Set APP and EXT to the signed app and one embedded extension. Use an approved capability list.",
        "steps": [
          "Compare the entitlement outputs side by side. Identify common keychain or app groups and the intended owner of each.",
          "Compare both targets with the approved access list for this specific extension role."
        ],
        "command": "codesign -d --entitlements :- \"$APP\"\ncodesign -d --entitlements :- \"$EXT\"",
        "interpret": "A shared team prefix alone does not grant shared item access. Compare the full group identifiers."
      }
    },
    {
      "id": "IOS-18",
      "category": "Privacy and storage",
      "level": "Advanced",
      "reference": "CWE-922",
      "title": "Separate restored files from re-synced data",
      "procedure": "Trace an offline document through supported backup and restore.",
      "evidence": "Capture file identity before backup, offline after restore and after sync.",
      "exercise": {
        "setup": "Owner diagnostics, a synthetic file marked for offline use and a disposable backup destination.",
        "steps": [
          "Record file location, backup exclusion flag and intended recovery behavior. Perform the supported encrypted backup and restore onto a QA device.",
          "Compare restored file inventory, authentication state and post-login rehydration using the file marker."
        ],
        "command": "",
        "interpret": "A file appearing after sync does not prove it was backed up. Capture the offline restore state before reconnecting."
      }
    },
    {
      "id": "IOS-19",
      "category": "Privacy and storage",
      "level": "Advanced",
      "reference": "MASVS-STORAGE-1",
      "title": "Measure temporary document retention after sharing",
      "procedure": "Record the diagnostic temporary-file inventory, open the share sheet and cancel before completing the handoff.",
      "evidence": "Track the unique file marker. Distinguish an intended receiver copy from a producer-side temporary file past its retention period.",
      "exercise": {
        "setup": "A synthetic PDF, a physical QA device and an allowed share extension.",
        "steps": [
          "Record the diagnostic temporary-file inventory, open the share sheet and cancel before completing the handoff.",
          "Compare inventory after cancellation, app restart and the documented cleanup deadline. Repeat with a successful share as a control."
        ],
        "command": "",
        "interpret": "Track the unique file marker. Distinguish an intended receiver copy from a producer-side temporary file past its retention period."
      }
    },
    {
      "id": "IOS-20",
      "category": "Identity and entitlements",
      "level": "Advanced",
      "reference": "MASVS-AUTH-2",
      "title": "Follow a biometric enrollment change",
      "procedure": "Enable the protected feature and record the normal authorization outcome and fallback flow.",
      "evidence": "Compare observed reauthentication with the product policy. Record the key access-control setting and OS result without capturing biometric data.",
      "exercise": {
        "setup": "A disposable physical device, test account and approved policy for biometric enrollment changes.",
        "steps": [
          "Enable the protected feature and record the normal authorization outcome and fallback flow.",
          "Change the enrolled biometric set in Settings with the device owner. Repeat the feature, then complete the supported re-enrollment."
        ],
        "command": "",
        "interpret": "Compare observed reauthentication with the product policy. Record the key access-control setting and OS result without capturing biometric data."
      }
    },
    {
      "id": "IOS-21",
      "category": "System surfaces and privacy",
      "level": "Advanced",
      "reference": "CWE-359",
      "title": "Verify widget state after account removal",
      "procedure": "Populate the widget for A, sign out and record the app state and widget timeline refresh.",
      "evidence": "Report whether A data persisted past the stated deadline and identify whether it came from the shared container or a rendered snapshot.",
      "exercise": {
        "setup": "A QA home screen with the product widget and two synthetic account aliases.",
        "steps": [
          "Populate the widget for A, sign out and record the app state and widget timeline refresh.",
          "Sign in as B and observe the widget before and after its documented refresh deadline, including while locked."
        ],
        "command": "",
        "interpret": "Report whether A data persisted past the stated deadline and identify whether it came from the shared container or a rendered snapshot."
      }
    },
    {
      "id": "IOS-22",
      "category": "Runtime application self-protection",
      "level": "Advanced",
      "reference": "MASVS-RESILIENCE-1",
      "title": "Trace integrity key registration after reinstall",
      "procedure": "Record the initial pseudonymous key identifier and a valid decision for a test action.",
      "evidence": "Capture the new registration and authorized receipt together. Reinstallation can change key identity without changing the business account.",
      "exercise": {
        "setup": "A QA device with supported App Attest registration and backend registration diagnostics.",
        "steps": [
          "Record the initial pseudonymous key identifier and a valid decision for a test action.",
          "Reinstall on the disposable profile, use the normal registration flow and repeat the action. Compare key lifecycle events, retry limits and account continuity."
        ],
        "command": "",
        "interpret": "Capture the new registration and authorized receipt together. Reinstallation can change key identity without changing the business account."
      }
    }
  ]
});
