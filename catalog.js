// Stable case keys are independent of the display order and title.
// Each row contains a key, reference, objective, review procedure, and acceptance evidence.
const library = [];
function collection(id, name, surface, groups) {
  const cases = [];
  addGroups(id, cases, groups);
  library.push({id, name, surface, cases});
}
function addGroups(id, cases, groups) {
  for (const [category, basic, intermediate, advanced] of groups) {
    for (const [index, row] of [basic, intermediate, advanced].entries()) {
      const [key, reference, title, procedure, evidence] = row.split('|');
      if (!evidence) throw Error('Incomplete case ' + key);
      cases.push({ id: id + '-' + key, category, reference, title, procedure, evidence,
        level: ['Basic', 'Intermediate', 'Advanced'][index] });
    }
  }
}

collection('API','API security','Endpoints, identities and data contracts',[
['Identity and access',
'01|API2:2023|Read the authentication contract|At the API documentation URL, compare the authentication labels on public and account routes.|Record the documented distinction and flag operations whose identity requirements are ambiguous.',
'02|API1:2023|Review ownership decisions|With the owner, trace the read and update handlers for one account resource. Compare each decision with the tenant and owner fields in the data model.|Attach redacted handler references showing both decisions use the authenticated identity.',
'03|API5:2023|Follow a role removal|Using a designated test user, record its approved administrative task, have an administrator remove the role, then repeat the ordinary task after the documented propagation interval.|Correlate the role change, denied operation and unchanged business record by timestamp.'],
['Response boundaries',
'04|API3:2023|Inspect published response examples|Open a public response example and classify each field by its intended audience.|Save a redacted example with any internal attributes marked for owner review.',
'05|API3:2023|Compare response projections|Compare the account summary serializer with the published schema and the field allowlist. Include nested objects.|List any fields present in the serializer without an approved consumer.',
'06|CWE-532|Follow a synthetic record through telemetry|Submit an ordinary test transaction with a unique nonsecret marker. Locate the trace, application log and analytics event in the approved review console.|Document where the marker appears and show that restricted fields are masked at each sink.'],
['Lifecycle and limits',
'07|API9:2023|Locate version and retirement notices|Read the version identifiers and retirement notices at the API documentation URL.|Record the supported version and the owner of each ambiguous retirement date.',
'08|API4:2023|Review pagination bounds|Inspect the list operation schema and approved gateway configuration for default page size and a finite ceiling.|Record both values and the component responsible for enforcing each.',
'09|API9:2023|Trace retirement to deployment|Pick one retired route from the change register. Compare the release manifest, gateway route inventory and consumer migration record.|Attach dated records showing removal from each active environment or name the outstanding dependency.']
]);
collection('WEB','Web applications','Browser sessions and application workflows',[
['Browser transport',
'01|CWE-319|Inspect the public entry point|Open the site URL and inspect the final address and security details in the browser.|Capture the final HTTPS origin and any browser transport warning.',
'02|CWE-614|Review session cookie scope|Sign in with a test account and inspect session cookie attributes in browser storage. Record flags and domains only.|Show that the session cookie requires secure transport and is scoped to the intended host.',
'03|CWE-613|Trace session termination|Open two views with the same test session. Sign out in one and refresh a protected page in the other. Check the server logout event.|Record the redirect or denial and the time the server invalidated the session.'],
['Data and privacy',
'04|CWE-200|Review public page metadata|Inspect the title, social preview and embedded metadata on the public landing page.|Save the public values and identify any internal project or personal information.',
'05|CWE-525|Inspect private response caching|With a test account, inspect cache directives on an account page, its JSON response and a personalized download.|Record the directives beside the sensitivity of each response.',
'06|CWE-359|Follow account erasure|Create a disposable account with synthetic data and use its normal deletion flow. Check the user view, retention job and audit receipt with the owner.|Document disappearance from active views and the scheduled expiry of retained copies.'],
['Navigation and permissions',
'07|CWE-209|Review public error presentation|Visit a nonexistent page under the supplied site URL and read the error presented by the application.|Capture the status and visible message. Internal paths and stack traces warrant review.',
'08|CWE-862|Reconcile privileged functions|Compare the role matrix with the server permission checks for a sensitive settings page and its save handler.|Record a decision point for each path and any missing owner approval.',
'09|CWE-841|Trace approval of a business change|Use the supported submit, approve and publish workflow with separate test roles. Inspect the saved state and audit event at each transition.|Link submission, approval identity and final published revision in order.']
]);
collection('LLM','LLM applications','Model interfaces, tools and retrieval',[
['Data handling',
'01|CWE-359|Read the input retention notice|At the assistant URL, inspect the notice shown before a user submits a question.|Record whether the notice identifies retention, downstream processing and available controls.',
'02|CWE-532|Inspect prompt telemetry|Compare a redacted model trace with the logging configuration and approved field list.|Show which fields reach support tools and which roles may read them.',
'03|CWE-359|Trace conversation deletion|Create a disposable conversation with a unique harmless phrase. Delete it using the supported workflow and review history, index deletion receipts and retention schedules.|Capture dated evidence for the conversation store, search index and backup expiry.'],
['Tool permissions',
'04|CWE-250|Inventory advertised actions|Read the capabilities and permissions shown in the assistant UI at the supplied URL.|List read and write actions and the stated approval requirements.',
'05|CWE-862|Review tool authorization|Trace one write tool from its schema through the application authorization handler. Compare its service identity with the user permission model.|Attach the policy decision and the tool credential scope.',
'06|CWE-862|Trace a declined action|Request an ordinary change to a disposable record, decline the confirmation and inspect the record and action log.|Show the original revision, cancellation event and unchanged final revision.'],
['Knowledge sources',
'07|CWE-345|Inspect answer attribution|Use a public sample question about a documented feature. Open the citation supplied with the answer.|Record whether the cited passage supports the claim and identifies a source version.',
'08|CWE-862|Review retrieval filters|Review how document permissions are carried from ingestion into lookup and citation previews.|Map one synthetic document to its owner, index filter and preview decision.',
'09|CWE-672|Trace withdrawal of a source|Publish an approved synthetic knowledge entry, confirm a cited answer, then withdraw it and wait for the stated index refresh.|Record source revision, index update and the subsequent answer to the same question.']
]);
collection('CICD','CI/CD & Jenkins','Pipelines, build identities and release controls',[
['Build identities',
'01|CWE-200|Review the public build view|Open the supplied project or Jenkins URL as a signed-out visitor. Review only the visible job and artifact metadata.|Record exposed project identifiers and compare them with the intended public inventory.',
'02|CWE-250|Inspect Jenkinsfile credential scope|Review the Jenkinsfile and shared library calls for the stages that bind credentials. Compare credential scope with the stage purpose.|Record credential IDs only, their permitted jobs and the stage lifetime.',
'03|CWE-269|Trace a build identity rotation|Coordinate rotation of a disposable build credential. Run the approved smoke pipeline and inspect the credential audit trail.|Link revocation, new binding and successful build without recording credential values.'],
['Release integrity',
'04|CWE-494|Locate artifact verification information|At the release URL, locate the checksum or signature and the documented verification identity.|Record where users obtain both the artifact and its expected identity.',
'05|CWE-829|Review Jenkinsfile dependency pins|Inspect shared libraries, container images and build tool references for immutable revisions.|Record each mutable reference with its update owner and review mechanism.',
'06|CWE-345|Trace one promoted artifact|Select a released build. Follow its reviewed commit, build identity, digest and promotion record through staging and production.|Compare the built and promoted digests and capture the approval identity.'],
['Isolation and audit',
'07|CWE-532|Inspect a published build summary|Read a publicly visible build summary at the supplied URL. Review what build context the publisher exposes.|Save a redacted excerpt and flag sensitive environment details.',
'08|CWE-732|Review workspace reuse|Compare the Jenkins agent allocation and post-build cleanup blocks with the executor configuration.|Show the workspace lifecycle and ownership boundary between jobs.',
'09|CWE-862|Follow a release approval|Start an approved staging release with a disposable version, leave the gate pending, then approve it with the assigned reviewer.|Show no deployment before approval and match the deployment receipt to that approval.']
]);
collection('WIN','Windows thick clients','Installers, local state and Windows services',[
['Release trust',
'01|CWE-494|Identify the Windows publisher|At the download URL, compare the named publisher, package architecture and release version with the release notes.|Record the expected publisher and version for the installer review.',
'02|CWE-347|Inspect the installer signature|Use the package signature properties to review publisher, chain and timestamp on the supplied installer.|Attach the verification result and compare publisher identity with the release record.',
'03|CWE-494|Trace a signed update|Update a disposable installation through the supported channel. Review updater verification events and the installed file versions.|Match old version, signed package identity, new version and updater decision.'],
['Local boundaries',
'04|CWE-250|Read installation privilege requirements|At the support URL, compare documented rights for installation and ordinary use.|Record which operations require elevation and whether a standard-user workflow is documented.',
'05|CWE-732|Inspect service file permissions|Review effective permissions for the installed service binary, its parent directory and configuration using a standard account.|Document the owner and principals allowed to modify each location.',
'06|CWE-922|Trace sign-out cleanup|Sign into a disposable Windows profile, open a synthetic document and sign out. Inspect application cache, recent-document entries and credential inventory.|Record which artifacts remain and compare each with the retention policy.'],
['Diagnostics',
'07|CWE-359|Review crash reporting disclosure|At the Windows support URL, read the crash-reporting notice and controls.|Record the listed recipients, default setting and collection scope.',
'08|CWE-532|Inspect diagnostic bundle contents|Generate an ordinary support bundle for a synthetic profile. Inventory event logs, configuration and paths before sharing.|Attach a sanitized manifest and note fields needing redaction.',
'09|CWE-359|Verify diagnostic consent over upgrade|Disable optional reports in a test profile, apply a supported update and trigger the built-in test report if available.|Compare consent before and after upgrade with the report delivery history.']
]);
collection('LIN','Linux thick clients','Package trust, desktop integration and local permissions',[
['Packaging',
'01|CWE-494|Identify the supported package channel|Read the release URL for distribution, package name, architecture and signing identity.|Capture the supported channel and verification instructions.',
'02|CWE-347|Review package trust settings|Inspect the package repository definition and signing key scope on a test machine.|Match the key fingerprint to the owner-approved channel record.',
'03|CWE-494|Trace a package upgrade|Apply the approved update in a disposable desktop profile. Follow package verification, installed version and service restart events.|Link package digest and resulting executable version to the release manifest.'],
['Desktop boundaries',
'04|CWE-250|Read sandbox permission declarations|At the package listing URL, read the advertised filesystem, device and desktop integration permissions.|Record permissions and the user feature claimed for each.',
'05|CWE-732|Review XDG file permissions|Inspect ownership and modes on application configuration, cache and state files created by a synthetic account.|Record effective read permissions for the account and other local users.',
'06|CWE-862|Trace a privileged desktop action|Use a documented settings action in a disposable session. Review its D-Bus interface, policy decision and service audit event with the owner.|Connect the caller identity and approval decision to the resulting state change.'],
['Lifecycle',
'07|CWE-1104|Inspect distribution support dates|Compare the advertised Linux package versions and maintenance dates on the release page.|Record stale package lines with their published support status.',
'08|CWE-532|Review journal exposure|Inspect journal entries from ordinary login and sync operations with synthetic data and compare journal access groups.|Save redacted examples and the effective reader set.',
'09|CWE-459|Trace profile removal|Populate an isolated profile, use the supported remove-account action and reopen the client. Inspect XDG state directories and keyring item names.|Identify cleared records and any retained artifacts with their documented purpose.']
]);
collection('AND','Android','Android storage, components and runtime protection',[
['Application identity',
'01|CWE-345|Identify the distribution listing|Read the supplied store or release URL for publisher, package identity and supported OS versions.|Save the expected distribution identity for comparison with the installed build.',
'02|CWE-926|Inspect exported components|Review the release manifest for exported activities, receivers and providers. Compare permissions with the integration specification.|Record each external entry point and the approved caller boundary.',
'03|CWE-347|Trace an Android signing transition|Follow a supported update on a test device. Compare the expected signing history with installed package metadata and retained app data.|Attach package identities before and after, installer result and data continuity evidence.'],
['Data lifecycle',
'04|CWE-359|Read the data safety declaration|At the listing URL, review data types, sharing purposes and the deletion route.|Record declared sensitive data and where a user can request deletion.',
'05|CWE-922|Inspect backup exclusions|Compare backup rules, included domains and locally cached account data in a provided test build.|Show that sensitive stores are excluded or protected under the approved design.',
'06|CWE-359|Trace permission withdrawal|Grant a discretionary permission, complete its normal feature, revoke it in Android settings and repeat the feature.|Capture the fallback UI, OS permission state and cessation of new collection.'],
['Runtime application self-protection',
'07|MASVS-RESILIENCE-1|Find the device integrity support policy|At the product support URL, locate the policy for unsupported Android device states.|Capture the stated protection scope and user recovery route, or record the documentation gap.',
'08|MASVS-RESILIENCE-1|Review Android RASP decisions|Review the release integration for device integrity verdicts, expiry and unavailable-service handling.|Record where a verdict is evaluated and the response prescribed for each state.',
'09|MASVS-RESILIENCE-1|Trace a negative integrity verdict|Use the vendor-provided QA verdict fixture with a test account. Follow one protected operation from verdict receipt through the server decision to the device message.|Correlate policy version, refusal of the protected operation, audit event and normal recovery after a valid fixture.']
]);
collection('IOS','iOS','Entitlements, data protection and runtime protection',[
['Identity and entitlements',
'01|CWE-345|Identify the iOS seller and build|Read the App Store or enterprise release URL for seller, version and minimum OS.|Capture the expected identity and supported distribution channel.',
'02|CWE-250|Inspect signed entitlements|Compare the release entitlements for app groups, keychain access and associated domains with the approved capability list.|Record unexpected groups or capabilities and the signing team identifier.',
'03|CWE-862|Trace a shared-container handoff|Save synthetic content using the app and open it in its approved extension. Compare group membership and the resulting shared files.|Show the producing and consuming identities, container and intended data subset.'],
['Privacy and storage',
'04|CWE-359|Review privacy labels|Read the privacy label and linked policy at the product URL for tracking and linked data.|Capture the declared purposes and any inconsistent statements.',
'05|CWE-922|Review file protection classes|Inspect file protection attributes and keychain accessibility on sample account records using an approved diagnostic build.|Compare observed classes with the need for access while locked.',
'06|CWE-359|Trace logout and re-enrollment|Sign out of a synthetic account and enroll a second test account on the same device. Review caches, visible history and keychain item ownership.|Document separation between the two profiles and any permitted device-level settings.'],
['Runtime application self-protection',
'07|MASVS-RESILIENCE-1|Locate the device eligibility policy|Read the iOS support URL for device eligibility and recovery if protection checks fail.|Record the user-facing policy and its applicability to high-value actions.',
'08|MASVS-RESILIENCE-1|Review iOS RASP integration|Inspect the owner-supplied integrity decision diagram and build configuration for release-only behavior and unavailable verdicts.|Capture build identity, decision owner and expected handling for each verdict.',
'09|MASVS-RESILIENCE-1|Trace an attestation failure|Use an approved test attestation response in the QA environment. Follow challenge issuance, failed validation and the user-visible outcome for a protected action.|Match challenge and audit identifiers, confirm no protected state change and verify recovery with a valid test response.']
]);
collection('IOT','IoT devices','Enrollment, fleet operations and device retirement',[
['Device identity',
'01|CWE-1392|Read first-use credential guidance|At the device onboarding URL, identify how users establish the first owner identity.|Record whether credentials are unique per device and when ownership changes.',
'02|CWE-287|Inspect enrollment binding|Review a sanitized enrollment record and the factory identity issuance policy.|Show how device identity, tenant and enrollment approval are bound.',
'03|CWE-672|Trace a device transfer|Transfer a test device between two lab tenants using the documented procedure. Review the device inventory and broker authorization receipts.|Capture old ownership removal, new enrollment and the timestamp of credential retirement.'],
['Fleet operation',
'04|CWE-1104|Find the support lifetime|Read the product support URL for security update duration and supported hardware revisions.|Record the support end date or identify the missing commitment.',
'05|CWE-319|Review telemetry transport|Inspect the device-to-broker profile for encryption, trust anchors and certificate expiry behavior.|Attach a sanitized profile and the expected response to an expired identity.',
'06|CWE-494|Trace a fleet update|Apply a vendor-signed update to a designated lab device using the normal rollout channel. Compare controller status with the device-reported version.|Link package identity, verification event, reboot and final health status.'],
['Privacy and reset',
'07|CWE-359|Read sensor collection disclosures|Review the public setup guide for collection intervals, cloud destinations and disabling optional sensors.|Record the declared settings for one sensor.',
'08|CWE-532|Review device support logs|Inspect a vendor diagnostic export generated from synthetic activity. Classify identifiers, network settings and sensor readings.|Capture a redacted inventory and compare fields with support requirements.',
'09|CWE-226|Trace factory reset|Set up a lab device with synthetic preferences and use the documented reset. Re-enroll it and review the fleet console and local setup state.|Show that previous ownership and user settings were cleared and identify separately retained fleet history.']
]);
collection('RE','Reverse engineering','Artifact provenance and static release review',[
['Artifact identity',
'01|CWE-345|Establish the public release identity|Read the release URL for version, build flavor, signing identity and available checksums.|Record the expected artifact identifiers and unresolved provenance gaps.',
'02|CWE-1104|Reconcile embedded components|Compare version metadata from a supplied binary and its bundled libraries with the release SBOM.|List matched component identities and unresolved version differences.',
'03|CWE-353|Trace source to shipped binary|Select a released component and follow the source revision, build receipt, signed package and extracted component hash.|Attach the chain of identifiers and distinguish verified links from assumptions.'],
['Release exposure',
'04|CWE-215|Inspect the release file listing|Read the public release asset listing and identify public debug or symbol packages.|Capture intended audiences and publication status for each asset.',
'05|CWE-209|Review diagnostic strings|Review error-message resources in a supplied artifact for developer paths, internal service labels and personal identifiers.|Record redacted locations and classify which strings are reachable from documented UI flows.',
'06|CWE-489|Trace release configuration|Compare debug and release feature manifests with the corresponding signed artifacts. Validate one release-only setting using its supported status screen.|Correlate build flags, artifact identity and observed setting.'],
['Data handling',
'07|CWE-359|Inventory declared integrations|Review release documentation for analytics and crash-reporting integrations.|Record the declared recipients and choices available to the user.',
'08|CWE-798|Review embedded credential references|Review owner-provided resource inventories and configuration for credential markers. Classify placeholders and identifiers with the release owner.|Record only the resource location and classification with a remediation owner.',
'09|CWE-532|Trace a diagnostic field|Select a harmless diagnostic marker in the shipped resources. Follow its source reference and trigger the documented UI event in a disposable profile.|Match the static reference and emitted record, identifying fields removed by redaction.']
]);
collection('FW','Firmware analysis','Image provenance, boot integrity and updates',[
['Image provenance',
'01|CWE-345|Identify the hardware target|Read the firmware download URL for model, board revision, region and image version.|Record supported hardware and expected artifact identity.',
'02|CWE-1104|Reconcile the firmware inventory|Compare the provided image manifest and component version table with the supplied SBOM.|Record mismatched revisions and unsupported components with package paths.',
'03|CWE-347|Trace image signing|Follow a test release from build manifest to signature receipt, verification log and installed version on the matching evaluation board.|Attach digests, signer identity and device acceptance evidence.'],
['Boot and recovery',
'04|CWE-494|Locate the recovery image policy|Read the recovery instructions at the supplied URL for image provenance and supported recovery versions.|Capture the named source and version constraints.',
'05|CWE-1328|Review rollback policy|Inspect the update policy and image metadata for monotonic version counters and documented recovery exceptions.|Record counter ownership, comparison point and authorization for exceptions.',
'06|CWE-755|Trace update recovery|Run the vendor-provided interrupted-update acceptance fixture on an evaluation board. Review slot selection and health reporting after restart.|Show the selected verified slot, retained settings and final device health.'],
['Configuration and data',
'07|CWE-1392|Read factory configuration guidance|Review the public quick-start for first-boot credentials and enrollment requirements.|Record user-visible initialization steps and any shared-default dependency.',
'08|CWE-321|Review key provenance|Compare key inventory labels in the supplied manufacturing manifest with the provisioning design. Identify public anchors and device-unique secret references.|Record identifiers and ownership only, with evidence of per-device provisioning.',
'09|CWE-226|Trace decommissioning|Provision a lab unit with synthetic data and run the documented erase workflow. Inspect the owner-approved post-reset inventory and enrollment record.|Link erase result, cleared user partitions and identity retirement to the device record.']
]);

// Additional platform-specific control families use the same case schema.
const additional = {
API:[
['Request contracts',
'10|API8:2023|Inspect accepted media types|Read one public operation definition for its request type, size and required fields.|Record the constraints a client can determine from the contract.',
'11|CWE-89|Review query parameter binding|Trace filter values from the request parser to a database query in the supplied code. Review dynamic sort choices separately.|Identify bound values and the approved enumeration for structural choices.',
'12|CWE-20|Trace schema rejection|Run the application team’s contract suite against a disposable build. Compare required-field and type failures with transaction receipts.|Attach the rejected fixture IDs and confirm rejected requests created no records.'],
['Integrations and tokens',
'13|API2:2023|Identify advertised token issuers|Inspect the identity provider metadata linked from the API guide.|Record issuer, key publication location and declared token lifetime where available.',
'14|API10:2023|Review upstream response trust|Inspect how one provider response is parsed, bounded and mapped into internal state.|Document schema enforcement, timeout and handling of unknown fields.',
'15|CWE-294|Trace webhook deduplication|Use the provider QA console to redeliver a previously accepted synthetic event. Compare receipt and downstream job history.|Show two deliveries linked to one business side effect and one event identity.']],
WEB:[
['Browser input and state changes',
'10|CWE-79|Inspect the browser content policy|Use browser response details at the supplied URL to read the enforced content policy and distinguish report-only headers.|Record script sources and the policy actually applied to the page.',
'11|CWE-79|Review rendering of user text|Follow a profile field from storage into a template and a client-side preview. Review encoding for each output context.|Attach source locations and the regression assertion for displaying literal user text.',
'12|CWE-352|Trace request authenticity checks|Review the application’s existing request-authenticity regression suite for a disposable settings change. Compare accepted and rejected fixture results with audit records.|Show that only the approved same-session request updates the setting.'],
['Uploads and account recovery',
'13|CWE-434|Inspect upload requirements|Read the published upload form for type, size and privacy requirements.|Record the visible constraints and default sharing audience.',
'14|CWE-640|Review recovery token lifecycle|Review generation, expiration, storage and consumption of account recovery grants in supplied code.|Capture lifetime and evidence that consumption is atomic and single-use.',
'15|CWE-434|Trace a document through quarantine|Upload a benign supported document in a test account. Follow receipt, scanner decision, release and deletion. Use the owner’s failure fixture to inspect the held state.|Attach both state histories and the first point at which download becomes available.']],
LLM:[
['Instruction and retrieval boundaries',
'10|CWE-200|Inspect conversation sharing controls|Read the sharing options visible at the assistant URL and the stated audience for a shared transcript.|Record default visibility and whether attached source material is included.',
'11|CWE-20|Review the model input boundary|Inspect a redacted prompt assembly trace. Locate retrieved passages, application instructions and policy decisions outside the model.|Record the source label for each passage and which component authorizes actions.',
'12|CWE-345|Evaluate conflicting source revisions|In a test index, publish two harmless revisions of a product limit with explicit effective dates. Ask the supported product question before and after refresh.|Save both answers and citations, expected effective revision and any stale answer.']],
CICD:[
['Branch trust and release artifacts',
'10|CWE-345|Locate release provenance records|Read the released artifact listing for its build identity and attestation reference.|Record which published files can be linked to a build.',
'11|CWE-78|Review Jenkinsfile parameter handling|Trace user-editable build parameters into shell steps. Inspect typed choices, validation and how arguments are passed to the build tool.|Record each shell boundary and the validation or fixed choice that constrains it.',
'12|CWE-862|Trace an ordinary contribution build|Run a routine documentation change through the approved contribution workflow in a test project. Compare its actual runner and granted scopes with a release build.|Capture both identities and evidence that signing credentials are exclusive to the release job.']],
WIN:[
['Windows integration',
'10|CWE-319|Review supported connection modes|Read the client setup URL for server trust and supported encrypted connection options.|Record the documented default and certificate requirements.',
'11|CWE-427|Inspect library load policy|Review dependency manifests and application-owned library directories in the supplied deployment. Check effective write permissions on search locations.|Record each library provider and its trusted installation boundary.',
'12|CWE-862|Trace broker authorization|Use the owner’s standard and administrative QA accounts to request an approved service operation through the client. Compare broker audit decisions.|Capture caller identity class, service outcome and final configuration for both runs.']],
LIN:[
['Service isolation',
'10|CWE-269|Inventory service prerequisites|Read the project installation URL for service accounts, group membership and required privileges.|Identify which requirements apply only during installation.',
'11|CWE-250|Review service confinement|Inspect the shipped systemd unit for account, capabilities, filesystem access and writable directories.|Compare actual permissions with the documented service duties.',
'12|CWE-732|Trace package-created permissions|Install and update the package in a clean test VM. Compare the owner and mode of its state directory, service socket and configuration after each operation.|Document installation defaults and any permission drift after upgrade.']],
AND:[
['Network trust and app links',
'10|CWE-939|Identify supported Android links|Read the public app-link guide for approved hosts and the expected user experience.|Record the declared domains and which links require a signed-in account.',
'11|CWE-295|Review Android trust configuration|Compare the release network security configuration with debug overrides and the approved CA inventory.|Attach release domain rules and show the build variant that selects them.',
'12|CWE-939|Trace a verified app link|Open a documented benign link on a clean Android test device, then follow its normal authentication flow. Inspect the OS domain verification status.|Match verified host, destination screen and account boundary.']],
IOS:[
['Transport and links',
'10|CWE-939|Inventory advertised universal links|Read the public linking guide for supported hosts and destinations.|Record intended deep links and prerequisites for a private destination.',
'11|CWE-319|Inspect transport exceptions|Review the signed app’s App Transport Security configuration and compare every exception with its change approval.|List affected domains, business rationale and expiry date.',
'12|CWE-939|Trace a universal link handoff|Use a documented account link on a clean test device while signed out. Complete the supported sign-in and inspect the destination.|Show the associated domain, authentication step and final account context.']],
IOT:[
['Offline behavior and consent',
'10|CWE-755|Read offline operation limits|Read the device guide for behavior during a cloud outage and how the device signals degraded service.|Record expected local functions and the limits on queued telemetry.',
'11|CWE-400|Inspect offline storage bounds|Review the firmware or gateway settings for message queue capacity, expiry and overflow policy.|Record byte or message limits and the prescribed drop behavior.',
'12|CWE-359|Trace sensor consent through reconnect|Disable optional collection in a lab device, perform a normal offline interval and reconnect. Check the broker event history for the test device.|Compare consent time with sensor event times and identify which queued records were delivered.']],
RE:[
['Platform hardening',
'10|CWE-1104|Identify supported runtime versions|Read the release notes for bundled runtime versions and the release that last updated them.|Capture the version claims for comparison with the artifact.',
'11|CWE-693|Inspect executable hardening metadata|Inspect the supplied PE or ELF header for declared relocation and non-executable memory settings. Record applicability for each architecture.|Attach header fields and identify any architecture variant missing the expected build setting.',
'12|CWE-353|Compare protection across releases|Compare build policy and executable metadata for two signed releases. Request a build receipt for each changed setting.|Link the difference to an approved compiler change or record the unexplained regression.']],
FW:[
['Manufacturing and hardware boundaries',
'10|CWE-1191|Read production debug policy|Read the board support page for production debug access and authorized service conditions.|Record which board revisions and lifecycle states the policy covers.',
'11|CWE-1191|Inspect production provisioning records|Compare documented debug policy with the sanitized factory configuration receipt for a test board.|Match board identity, lifecycle state and declared interface lock settings.',
'12|CWE-1188|Trace factory-to-field provisioning|Follow one test board through approved provisioning, outgoing inspection and first enrollment. Compare factory-only settings with the field manifest.|Attach the state transitions and evidence that release settings replaced manufacturing defaults.']]
};
for (const area of library) addGroups(area.id, area.cases, additional[area.id]);
const identityAndBusinessCases = {
API: [
['OAuth and delegated access',
'16|API2:2023|Inspect documented consent scopes|At the developer portal URL, compare the scopes for reading a profile and modifying it.|Record which consent scopes a client needs for each operation.',
'17|CWE-346|Review OAuth callback registration|Inspect the approved client registration and redirect validation configuration for a staging integration.|Record the comparison rule and how distinct environments receive distinct callback registrations.',
'18|CWE-863|Trace delegated consent withdrawal|Authorize a disposable integration for read access, withdraw consent through the user portal and repeat its ordinary sync after the documented interval.|Link the grant, revocation event and denied sync with no new data received.'],
['Tokens and federation',
'19|API2:2023|Locate key rotation guidance|At the identity integration URL, find the published signing-key discovery method and rotation notice policy.|Capture how a relying service learns the new verification key.',
'20|CWE-347|Review token verification policy|Compare the verifier settings with the identity contract for signature algorithms, issuer, audience and expiry. Inspect the parser and verifier call sites.|Identify the validation decision before claims enter authorization logic.',
'21|CWE-287|Trace federation rollover|Follow an approved staging rollover of a SAML signing certificate or OIDC key. Review trust metadata, one normal sign-in before and after, and expiry of the prior trust entry.|Match issuer, certificate or key IDs, activation times and relying-party events.'],
['Concurrency and transaction integrity',
'22|CWE-841|Locate retry semantics|Read the public API contract for one create or payment operation. Identify how clients distinguish a safe retry from a new request.|Record key scope, retention and expected response to a supported retry.',
'23|CWE-362|Review atomic state transitions|Review the update path for a reservation or inventory operation. Compare transaction boundaries with the business rule defining available quantity.|Show where the check and commit share a transaction or equivalent concurrency control.',
'24|CWE-672|Trace cancellation across services|Create and cancel a synthetic booking using supported operations. Inspect its reservation, billing fixture and notification ledger.|Match the cancellation ID across all consumers and confirm the released entitlement.'],
['GraphQL and asynchronous work',
'25|API4:2023|Inspect query cost documentation|Read the GraphQL guide for connection sizes, cost accounting and returned quota information.|Record limits available to an ordinary client and missing guidance.',
'26|API1:2023|Review nested resolver authorization|Follow a documented query from its root object through a nested collection. Compare each resolver with the relationship permission model.|Record where the parent and child ownership constraints are applied.',
'27|CWE-862|Trace export job ownership|Request a synthetic export from the normal account UI. Follow job creation, worker identity, result storage and download authorization.|Show that the initiating account stays bound to both the job and its completed result.']
],
WEB:[
['Authentication and enrollment',
'16|CWE-521|Read password enrollment requirements|Inspect the registration page for required length, passphrase support and recovery instructions.|Record constraints visible before a user submits personal information.',
'17|CWE-307|Review authentication rate controls|Review the approved authentication configuration for challenge thresholds, account recovery and operator visibility.|Document counter scope, reset conditions and protections against locking out unrelated users.',
'18|CWE-308|Trace authenticator replacement|Replace a factor on a disposable account through the supported flow. Follow identity confirmation, enrollment, retirement of the previous factor and notification.|Record each identity decision and confirm the account inventory contains the replacement.'],
['Cross-origin and embedded surfaces',
'19|CWE-1021|Inspect framing policy|At the supplied URL, inspect response headers that set allowed frame ancestors.|Record the enforced directive and intended embedding partners.',
'20|CWE-942|Review cross-origin trust configuration|Compare allowed origins and credential settings for one authenticated frontend with the approved partner list.|Record explicit origins, environment ownership and the component setting the response policy.',
'21|CWE-346|Trace an embedded payment handoff|Complete a provider-supplied test checkout. Review browser message origins, server confirmation and the final order receipt with the owner.|Link the message source and verified provider receipt to one completed order.'],
['Administration and audit',
'22|CWE-200|Inspect public status disclosures|Read the status or maintenance page linked from the target URL. Review the audience for dependency names and incident detail.|Capture any internal system identifiers visible to a public visitor.',
'23|CWE-778|Review privileged event coverage|Compare application audit events with the role matrix for changing access, exporting records and deleting accounts.|Record actor, target, timestamp and outcome coverage for each action.',
'24|CWE-269|Trace temporary elevation expiry|Grant a disposable reviewer time-limited access through the normal administration flow. After expiry, revisit the approved function and inspect its audit decision.|Show the grant interval, expiry and loss of the temporary permission.'],
['Caching and shared infrastructure',
'25|CWE-525|Inspect public cache variation|Review the cache directives and variation headers on the public language or region selector page.|Record which dimensions influence the shared representation.',
'26|CWE-444|Review proxy protocol alignment|Compare gateway and application server settings for HTTP versions, header normalization and handling of ambiguous requests.|Capture the documented rejection policy and consistency across the deployed tiers.',
'27|CWE-524|Trace a published-content purge|Publish a harmless change to a staging page, request its normal cache purge and inspect the origin and edge copies.|Record revision, cache invalidation receipt and time until both layers show the updated text.']
]};
for (const area of library) {
  if (identityAndBusinessCases[area.id]) addGroups(area.id, area.cases, identityAndBusinessCases[area.id]);
}
