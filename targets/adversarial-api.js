registerTarget({
  "id": "API-ADV",
  "name": "API adversarial testing",
  "surface": "Authorized active validation of API authorization, input boundaries, and abuse controls",
  "cases": [
    {
      "id": "API-ADV-01",
      "category": "Object authorization",
      "reference": "CWE-639 · https://book.hacktricks.xyz/pentesting-web/idor",
      "title": "Systematically test object-level authorization",
      "level": "Intermediate",
      "related": ["API-01"],
      "procedure": "Build an inventory of object identifiers across paths, queries, bodies, nested relationships, exports, and asynchronous operations. With designated accounts, compare owner, peer, cross-tenant, and unowned-object decisions for read and state-changing operations.",
      "evidence": "An object-operation matrix with account and tenant identity, object ownership, request location, authorization result, returned data class, and authoritative post-request state."
    },
    {
      "id": "API-ADV-02",
      "category": "Function authorization",
      "reference": "CWE-862 · https://book.hacktricks.xyz/pentesting-web/idor",
      "title": "Test function-level authorization across roles",
      "level": "Advanced",
      "related": ["API-02"],
      "procedure": "Map documented and observed operations to the approved role model. Exercise each privileged function with designated lower, adjacent, expired, and removed roles, including alternate API versions and equivalent operations where they are in scope.",
      "evidence": "A role-to-operation matrix showing required role, actual identity state, server decision, side effects, audit event, and consistency across equivalent interfaces."
    },
    {
      "id": "API-ADV-03",
      "category": "Request boundaries",
      "reference": "CWE-915 · https://book.hacktricks.xyz/pentesting-web/mass-assignment",
      "title": "Test mass assignment and unexpected fields",
      "level": "Intermediate",
      "related": ["API-03"],
      "procedure": "Compare published request schemas, client-generated requests, server models, and response fields. Submit benign unexpected or read-only fields through designated test records and verify explicit allowlisting, nested-object handling, and immutable ownership attributes.",
      "evidence": "Baseline and modified request results showing field classification, validation decision, stored authoritative values, response projection, and absence or presence of unintended state change."
    },
    {
      "id": "API-ADV-04",
      "category": "GraphQL controls",
      "reference": "CWE-770 · https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql",
      "title": "Validate GraphQL depth, batching, and introspection controls",
      "level": "Advanced",
      "procedure": "Where GraphQL is in scope, compare schema exposure and resource controls across unauthenticated and approved roles. Exercise owner-approved query depth, aliasing, batching, pagination, and cost boundaries below the agreed load ceiling.",
      "evidence": "A control matrix showing identity, query characteristic, measured cost or complexity, server decision, response scope, limit signal, and absence of service degradation."
    },
    {
      "id": "API-ADV-05",
      "category": "Abuse controls",
      "reference": "CWE-307",
      "title": "Test rate limits and abuse-control consistency",
      "level": "Intermediate",
      "procedure": "At an agreed low request ceiling, compare throttling and lockout behavior across authentication, recovery, search, export, mutation, and expensive operations. Review counter scope across accounts, sessions, tokens, source networks, identifier normalization, and equivalent routes.",
      "evidence": "A request timeline showing operation, identity and counter context, threshold, server response, retry guidance, cooldown, alternate-route behavior, and impact on unrelated users."
    },
    {
      "id": "API-ADV-06",
      "category": "Webhook integrity",
      "reference": "CWE-294",
      "title": "Validate webhook signatures and replay handling",
      "level": "Advanced",
      "procedure": "Using provider test facilities or owner-approved fixtures, compare valid, invalid, expired, duplicated, delayed, and out-of-order webhook deliveries. Verify signature coverage, key rotation, freshness, deduplication, and transaction ordering.",
      "evidence": "A delivery timeline with provider event identity, verification decision, freshness and deduplication outcome, business side effect, key state, acknowledgement, and audit correlation."
    },
    {
      "id": "API-ADV-07",
      "category": "Inventory and versions",
      "reference": "CWE-1059",
      "title": "Test deprecated and alternate API surfaces",
      "level": "Intermediate",
      "procedure": "Compare gateway routes, documentation, mobile or web clients, and owner inventory for versioned, deprecated, partner, administrative, and legacy operations. Verify that retired surfaces are removed or enforce current authentication and authorization policy.",
      "evidence": "A route inventory with version, environment, owner, retirement state, reachability, authentication requirement, authorization result, and discrepancy disposition."
    },
    {
      "id": "API-ADV-08",
      "category": "Transaction integrity",
      "reference": "CWE-362",
      "title": "Validate idempotency and concurrent state transitions",
      "level": "Advanced",
      "procedure": "For an approved reversible operation, compare retries, duplicate submissions, and a small owner-approved set of concurrent requests. Verify idempotency-key scope, state preconditions, transaction boundaries, and downstream side-effect consistency.",
      "evidence": "Timestamped request and response records linked to idempotency keys, authoritative final state, ledger or inventory changes, queued work, notifications, and audit events."
    }
  ]
});
