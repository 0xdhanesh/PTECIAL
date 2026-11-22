registerTarget({
  "id": "API",
  "name": "API security",
  "surface": "Endpoints, identities and data contracts",
  "cases": [
    {
      "id": "API-01",
      "category": "Identity and access",
      "reference": "API2:2023",
      "title": "Read the authentication contract",
      "procedure": "At the API documentation URL, compare the authentication labels on public and account routes.",
      "evidence": "Record the documented distinction and flag operations whose identity requirements are ambiguous.",
      "level": "Basic"
    },
    {
      "id": "API-02",
      "category": "Identity and access",
      "reference": "API1:2023",
      "title": "Review ownership decisions",
      "procedure": "With the owner, trace the read and update handlers for one account resource. Compare each decision with the tenant and owner fields in the data model.",
      "evidence": "Attach redacted handler references showing both decisions use the authenticated identity.",
      "level": "Intermediate"
    },
    {
      "id": "API-03",
      "category": "Identity and access",
      "reference": "API5:2023",
      "title": "Follow a role removal",
      "procedure": "Using a designated test user, record its approved administrative task, have an administrator remove the role, then repeat the ordinary task after the documented propagation interval.",
      "evidence": "Correlate the role change, denied operation and unchanged business record by timestamp.",
      "level": "Advanced"
    },
    {
      "id": "API-04",
      "category": "Response boundaries",
      "reference": "API3:2023",
      "title": "Inspect published response examples",
      "procedure": "Open a public response example and classify each field by its intended audience.",
      "evidence": "Save a redacted example with any internal attributes marked for owner review.",
      "level": "Basic"
    },
    {
      "id": "API-05",
      "category": "Response boundaries",
      "reference": "API3:2023",
      "title": "Compare response projections",
      "procedure": "Compare the account summary serializer with the published schema and the field allowlist. Include nested objects.",
      "evidence": "List any fields present in the serializer without an approved consumer.",
      "level": "Intermediate"
    },
    {
      "id": "API-06",
      "category": "Response boundaries",
      "reference": "CWE-532",
      "title": "Follow a synthetic record through telemetry",
      "procedure": "Submit an ordinary test transaction with a unique nonsecret marker. Locate the trace, application log and analytics event in the approved review console.",
      "evidence": "Document where the marker appears and show that restricted fields are masked at each sink.",
      "level": "Advanced"
    },
    {
      "id": "API-07",
      "category": "Lifecycle and limits",
      "reference": "API9:2023",
      "title": "Locate version and retirement notices",
      "procedure": "Read the version identifiers and retirement notices at the API documentation URL.",
      "evidence": "Record the supported version and the owner of each ambiguous retirement date.",
      "level": "Basic",
      "exercise": {
        "setup": "Use an approved local OpenAPI JSON export. Set SPEC to its path.",
        "steps": [
          "Compare the declared version with the supported version table.",
          "Review deprecated operations and their owner-approved retirement dates."
        ],
        "command": "jq -r '.info.version, (.paths | keys[])' \"$SPEC\"",
        "interpret": "This describes the exported contract. Confirm deployment through the gateway inventory before marking a route retired."
      }
    },
    {
      "id": "API-08",
      "category": "Lifecycle and limits",
      "reference": "API4:2023",
      "title": "Review pagination bounds",
      "procedure": "Inspect the list operation schema and approved gateway configuration for default page size and a finite ceiling.",
      "evidence": "Record both values and the component responsible for enforcing each.",
      "level": "Intermediate",
      "exercise": {
        "setup": "Set SPEC to an approved OpenAPI 3 JSON contract and ROUTE to a list route with a GET operation.",
        "steps": [
          "Inspect parameter defaults and maximums. Resolve any schema references in the spec.",
          "Compare the published ceiling with the effective gateway policy."
        ],
        "command": "jq --arg path \"$ROUTE\" '.paths[$path].get.parameters' \"$SPEC\"",
        "interpret": "An absent inline maximum can be inherited or referenced. Record the resolved bound and enforcement point."
      }
    },
    {
      "id": "API-09",
      "category": "Lifecycle and limits",
      "reference": "API9:2023",
      "title": "Trace retirement to deployment",
      "procedure": "Pick one retired route from the change register. Compare the release manifest, gateway route inventory and consumer migration record.",
      "evidence": "Attach dated records showing removal from each active environment or name the outstanding dependency.",
      "level": "Advanced"
    },
    {
      "id": "API-10",
      "category": "Request contracts",
      "reference": "API8:2023",
      "title": "Inspect accepted media types",
      "procedure": "Read one public operation definition for its request type, size and required fields.",
      "evidence": "Record the constraints a client can determine from the contract.",
      "level": "Basic"
    },
    {
      "id": "API-11",
      "category": "Request contracts",
      "reference": "CWE-89",
      "title": "Review query parameter binding",
      "procedure": "Trace filter values from the request parser to a database query in the supplied code. Review dynamic sort choices separately.",
      "evidence": "Identify bound values and the approved enumeration for structural choices.",
      "level": "Intermediate"
    },
    {
      "id": "API-12",
      "category": "Request contracts",
      "reference": "CWE-20",
      "title": "Trace schema rejection",
      "procedure": "Run the application team’s contract suite against a disposable build. Compare required-field and type failures with transaction receipts.",
      "evidence": "Attach the rejected fixture IDs and confirm rejected requests created no records.",
      "level": "Advanced"
    },
    {
      "id": "API-13",
      "category": "Integrations and tokens",
      "reference": "API2:2023",
      "title": "Identify advertised token issuers",
      "procedure": "Inspect the identity provider metadata linked from the API guide.",
      "evidence": "Record issuer, key publication location and declared token lifetime where available.",
      "level": "Basic"
    },
    {
      "id": "API-14",
      "category": "Integrations and tokens",
      "reference": "API10:2023",
      "title": "Review upstream response trust",
      "procedure": "Inspect how one provider response is parsed, bounded and mapped into internal state.",
      "evidence": "Document schema enforcement, timeout and handling of unknown fields.",
      "level": "Intermediate"
    },
    {
      "id": "API-15",
      "category": "Integrations and tokens",
      "reference": "CWE-294",
      "title": "Trace webhook deduplication",
      "procedure": "Use the provider QA console to redeliver a previously accepted synthetic event. Compare receipt and downstream job history.",
      "evidence": "Show two deliveries linked to one business side effect and one event identity.",
      "level": "Advanced"
    },
    {
      "id": "API-16",
      "category": "OAuth and delegated access",
      "reference": "API2:2023",
      "title": "Inspect documented consent scopes",
      "procedure": "At the developer portal URL, compare the scopes for reading a profile and modifying it.",
      "evidence": "Record which consent scopes a client needs for each operation.",
      "level": "Basic"
    },
    {
      "id": "API-17",
      "category": "OAuth and delegated access",
      "reference": "CWE-346",
      "title": "Review OAuth callback registration",
      "procedure": "Inspect the approved client registration and redirect validation configuration for a staging integration.",
      "evidence": "Record the comparison rule and how distinct environments receive distinct callback registrations.",
      "level": "Intermediate"
    },
    {
      "id": "API-18",
      "category": "OAuth and delegated access",
      "reference": "CWE-863",
      "title": "Trace delegated consent withdrawal",
      "procedure": "Authorize a disposable integration for read access, withdraw consent through the user portal and repeat its ordinary sync after the documented interval.",
      "evidence": "Link the grant, revocation event and denied sync with no new data received.",
      "level": "Advanced"
    },
    {
      "id": "API-19",
      "category": "Tokens and federation",
      "reference": "API2:2023",
      "title": "Locate key rotation guidance",
      "procedure": "At the identity integration URL, find the published signing-key discovery method and rotation notice policy.",
      "evidence": "Capture how a relying service learns the new verification key.",
      "level": "Basic"
    },
    {
      "id": "API-20",
      "category": "Tokens and federation",
      "reference": "CWE-347",
      "title": "Review token verification policy",
      "procedure": "Compare the verifier settings with the identity contract for signature algorithms, issuer, audience and expiry. Inspect the parser and verifier call sites.",
      "evidence": "Identify the validation decision before claims enter authorization logic.",
      "level": "Intermediate"
    },
    {
      "id": "API-21",
      "category": "Tokens and federation",
      "reference": "CWE-287",
      "title": "Trace federation rollover",
      "procedure": "Follow an approved staging rollover of a SAML signing certificate or OIDC key. Review trust metadata, one normal sign-in before and after, and expiry of the prior trust entry.",
      "evidence": "Match issuer, certificate or key IDs, activation times and relying-party events.",
      "level": "Advanced"
    },
    {
      "id": "API-22",
      "category": "Concurrency and transaction integrity",
      "reference": "CWE-841",
      "title": "Locate retry semantics",
      "procedure": "Read the public API contract for one create or payment operation. Identify how clients distinguish a safe retry from a new request.",
      "evidence": "Record key scope, retention and expected response to a supported retry.",
      "level": "Basic"
    },
    {
      "id": "API-23",
      "category": "Concurrency and transaction integrity",
      "reference": "CWE-362",
      "title": "Review atomic state transitions",
      "procedure": "Review the update path for a reservation or inventory operation. Compare transaction boundaries with the business rule defining available quantity.",
      "evidence": "Show where the check and commit share a transaction or equivalent concurrency control.",
      "level": "Intermediate"
    },
    {
      "id": "API-24",
      "category": "Concurrency and transaction integrity",
      "reference": "CWE-672",
      "title": "Trace cancellation across services",
      "procedure": "Create and cancel a synthetic booking using supported operations. Inspect its reservation, billing fixture and notification ledger.",
      "evidence": "Match the cancellation ID across all consumers and confirm the released entitlement.",
      "level": "Advanced"
    },
    {
      "id": "API-25",
      "category": "GraphQL and asynchronous work",
      "reference": "API4:2023",
      "title": "Inspect query cost documentation",
      "procedure": "Read the GraphQL guide for connection sizes, cost accounting and returned quota information.",
      "evidence": "Record limits available to an ordinary client and missing guidance.",
      "level": "Basic"
    },
    {
      "id": "API-26",
      "category": "GraphQL and asynchronous work",
      "reference": "API1:2023",
      "title": "Review nested resolver authorization",
      "procedure": "Follow a documented query from its root object through a nested collection. Compare each resolver with the relationship permission model.",
      "evidence": "Record where the parent and child ownership constraints are applied.",
      "level": "Intermediate"
    },
    {
      "id": "API-27",
      "category": "GraphQL and asynchronous work",
      "reference": "CWE-862",
      "title": "Trace export job ownership",
      "procedure": "Request a synthetic export from the normal account UI. Follow job creation, worker identity, result storage and download authorization.",
      "evidence": "Show that the initiating account stays bound to both the job and its completed result.",
      "level": "Advanced"
    }
  ]
});
