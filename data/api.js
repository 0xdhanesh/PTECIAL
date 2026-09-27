/*
 * API Pentest Checklist
 * Levels: basic | intermediate | advanced
 * Item IDs are stable identifiers used for saved progress and markdown import.
 * Aligned to the OWASP API Security Top 10:2023. Reference / checklist altitude.
 */
window.CHECKLISTS = window.CHECKLISTS || {};
window.CHECKLISTS.api = {
  id: "api",
  title: "API Pentest",
  ref: "OWASP API Security Top 10:2023",
  description: "REST / GraphQL API testing checklist, basics to advanced.",
  sections: [
    {
      id: "recon",
      title: "API Discovery & Documentation",
      wstg: "—",
      items: [
        { id: "API-RECON-01", l: "basic", t: "Collect API documentation and specs",
          d: "Gather OpenAPI/Swagger, GraphQL schema, Postman collections and vendor docs. Note versions and environments." },
        { id: "API-RECON-02", l: "basic", t: "Enumerate endpoints and methods",
          d: "Build a complete inventory of routes, methods, parameters and content types, including those absent from the docs." },
        { id: "API-RECON-03", l: "intermediate", t: "Discover undocumented and shadow endpoints",
          d: "Compare deployed routes against documentation; look for deprecated, internal or debug endpoints still reachable." },
        { id: "API-RECON-04", l: "intermediate", t: "Enumerate API versions",
          d: "Identify multiple concurrent versions (v1, v2, beta) and test older versions that may lack current controls." },
        { id: "API-RECON-05", l: "intermediate", t: "Introspect GraphQL schema",
          d: "Where enabled, use introspection to map types, queries, mutations and subscriptions and identify sensitive operations." }
      ]
    },
    {
      id: "authn",
      title: "Authentication (API2)",
      wstg: "API2:2023",
      items: [
        { id: "API-ATHN-01", l: "basic", t: "Test for missing authentication",
          d: "Confirm every non-public endpoint requires authentication, including undocumented and version variants." },
        { id: "API-ATHN-02", l: "basic", t: "Review API key handling",
          d: "Assess key transmission, scope, rotation and whether keys are exposed in client code or URLs." },
        { id: "API-ATHN-03", l: "intermediate", t: "Test token validation",
          d: "Review bearer/JWT signature verification, expiry, audience/issuer checks and handling of malformed tokens." },
        { id: "API-ATHN-04", l: "intermediate", t: "Test credential and token brute-force protection",
          d: "Assess rate limiting and lockout on token, login and refresh endpoints." },
        { id: "API-ATHN-05", l: "advanced", t: "Test OAuth2 / OIDC grant flows",
          d: "Review redirect validation, scope handling, token exchange and refresh-token rotation and revocation." }
      ]
    },
    {
      id: "jwt",
      title: "JWT / Token Handling",
      wstg: "API2:2023",
      items: [
        { id: "API-JWT-01", l: "basic", t: "Decode and inspect token structure",
          d: "Decode the header and payload to review the algorithm, key identifiers and claims (sub, role, scope, exp, aud, iss). Note anything the server appears to trust." },
        { id: "API-JWT-02", l: "basic", t: "Test expiry enforcement (exp)",
          d: "Confirm expired tokens are rejected and that removing or extending the exp claim does not extend a session." },
        { id: "API-JWT-03", l: "basic", t: "Confirm tokens are sent over TLS only",
          d: "Verify tokens are not exposed in URLs, logs or caches and only travel over encrypted channels." },
        { id: "API-JWT-04", l: "intermediate", t: "Test 'none' / unsigned algorithm acceptance",
          d: "Check whether the server accepts a token whose algorithm is set to none (or otherwise unsigned), bypassing signature verification." },
        { id: "API-JWT-05", l: "intermediate", t: "Test signature verification",
          d: "Modify payload claims and confirm the server rejects the token when the signature no longer matches — i.e. that it verifies rather than merely decodes." },
        { id: "API-JWT-06", l: "intermediate", t: "Test algorithm confusion (asymmetric to symmetric)",
          d: "Assess whether an RS/ES-signed scheme can be downgraded to an HMAC scheme so the public key is treated as the verification secret." },
        { id: "API-JWT-07", l: "intermediate", t: "Test weak HMAC signing secret",
          d: "Assess whether an HMAC-signed token uses a weak or default secret that permits offline recovery and forgery of valid tokens." },
        { id: "API-JWT-08", l: "intermediate", t: "Test claim tampering for authorization",
          d: "Alter identity and privilege claims (sub, role, scope, tenant) and confirm the server derives authorization from verified server-side state, not client-supplied claims." },
        { id: "API-JWT-09", l: "intermediate", t: "Test kid and header parameter handling",
          d: "Assess the kid (key id) and related header parameters for injection into key lookups (path, query or database) that could select an attacker-influenced key." },
        { id: "API-JWT-10", l: "advanced", t: "Test key-injection headers (jwk / jku / x5u)",
          d: "Assess whether embedded or referenced key headers cause the server to trust an attacker-supplied key or to fetch keys from an attacker-controlled URL (SSRF / key injection)." },
        { id: "API-JWT-11", l: "advanced", t: "Test audience and issuer validation",
          d: "Confirm the server validates aud and iss so that a token minted for a different audience or issuer is not accepted." },
        { id: "API-JWT-12", l: "advanced", t: "Test token revocation and replay",
          d: "Assess whether tokens can be revoked (logout, password change) and whether captured tokens can be replayed; review jti / denylist handling for stateless tokens." },
        { id: "API-JWT-13", l: "advanced", t: "Test refresh-token security",
          d: "Review refresh-token rotation, reuse detection, binding and revocation, and whether a leaked refresh token yields long-lived access." }
      ]
    },
    {
      id: "oauth",
      title: "OAuth 2.0 / OIDC",
      wstg: "API2:2023",
      items: [
        { id: "API-OAUTH-01", l: "basic", t: "Identify the grant type and flow in use",
          d: "Determine which flow the client uses (authorization code, code+PKCE, client credentials, device, legacy implicit/password) and assess whether it suits the client type." },
        { id: "API-OAUTH-02", l: "basic", t: "Review token transport and storage",
          d: "Confirm tokens travel only over TLS and are not exposed in URLs, referrers, logs or insecure client storage." },
        { id: "API-OAUTH-03", l: "intermediate", t: "Test redirect_uri validation",
          d: "Assess whether redirect_uri is strictly matched (no partial, wildcard or open-redirect bypass) so authorization responses cannot be diverted to an attacker." },
        { id: "API-OAUTH-04", l: "intermediate", t: "Test the state parameter (CSRF)",
          d: "Confirm state is present, unpredictable and validated on return so the authorization response cannot be forged onto a victim session." },
        { id: "API-OAUTH-05", l: "intermediate", t: "Test PKCE enforcement",
          d: "For public clients, confirm PKCE is required and the code_verifier is validated, preventing use of an intercepted authorization code." },
        { id: "API-OAUTH-06", l: "intermediate", t: "Test authorization code handling",
          d: "Confirm codes are single-use, short-lived and bound to the client and redirect_uri; test for reuse and cross-client redemption." },
        { id: "API-OAUTH-07", l: "intermediate", t: "Test scope handling and escalation",
          d: "Attempt to request or receive broader scopes than authorized, and confirm the resource server enforces granted scopes per request." },
        { id: "API-OAUTH-08", l: "advanced", t: "Test OIDC nonce and ID-token validation",
          d: "Confirm nonce is validated (replay protection) and the ID token's signature, iss, aud and exp are verified before the identity is trusted." },
        { id: "API-OAUTH-09", l: "advanced", t: "Test token audience / client confusion",
          d: "Assess whether a token issued to one client or audience is accepted by another resource, indicating missing audience binding." },
        { id: "API-OAUTH-10", l: "advanced", t: "Test social login / account-linking logic",
          d: "Review how external identities are linked to local accounts (e.g. email trust, unverified identifiers) for account-takeover paths and login CSRF." },
        { id: "API-OAUTH-11", l: "advanced", t: "Test deprecated flows and token leakage",
          d: "Where implicit or resource-owner-password flows remain, assess fragment-based token exposure and credential handling, and recommend migration." }
      ]
    },
    {
      id: "saml",
      title: "SAML & Session Tokens",
      wstg: "API2:2023",
      items: [
        { id: "API-SAML-01", l: "intermediate", t: "Review SAML response/assertion signing",
          d: "Confirm the response and/or assertion is signed and that the SP validates the signature against the trusted IdP certificate before trusting it." },
        { id: "API-SAML-02", l: "intermediate", t: "Test unsigned / signature-stripped assertions",
          d: "Assess whether the SP accepts an assertion with the signature removed or absent, which would allow arbitrary identity claims." },
        { id: "API-SAML-03", l: "advanced", t: "Test XML signature wrapping (XSW)",
          d: "Assess whether relocating or duplicating signed and unsigned elements causes the SP to validate one element but consume another." },
        { id: "API-SAML-04", l: "advanced", t: "Test assertion attribute / NameID tampering",
          d: "Attempt to modify identity attributes, NameID or group/role claims and confirm they cannot be altered without invalidating the signature." },
        { id: "API-SAML-05", l: "advanced", t: "Test recipient, audience and replay conditions",
          d: "Confirm the SP validates Recipient, Audience, InResponseTo and NotBefore/NotOnOrAfter, and rejects replayed or misdirected assertions." },
        { id: "API-SAML-06", l: "advanced", t: "Test XML parser exposure (XXE) in SAML/SSO",
          d: "Assess the SAML/XML processing path for external-entity handling that could disclose files or trigger server-side requests." },
        { id: "API-SESS-01", l: "basic", t: "Assess opaque session token strength",
          d: "For non-JWT session tokens, confirm they are unpredictable, sufficiently long and generated from a secure source." },
        { id: "API-SESS-02", l: "intermediate", t: "Test session lifecycle and revocation",
          d: "Confirm logout, expiry and privilege changes invalidate the token server-side and that it cannot be reused afterwards." },
        { id: "API-SESS-03", l: "intermediate", t: "Test session fixation and binding",
          d: "Confirm the session identifier is rotated on authentication and, where applicable, bound to client attributes to resist fixation and theft." }
      ]
    },
    {
      id: "bola",
      title: "Object-Level Authorization (API1)",
      wstg: "API1:2023",
      items: [
        { id: "API-BOLA-01", l: "basic", t: "Test BOLA / IDOR on object identifiers",
          d: "Substitute other users' object IDs across endpoints and confirm per-object ownership checks server-side." },
        { id: "API-BOLA-02", l: "intermediate", t: "Test nested and related object access",
          d: "Access child or related objects via parent endpoints and confirm authorization applies to the full object graph." },
        { id: "API-BOLA-03", l: "intermediate", t: "Test predictable and enumerable identifiers",
          d: "Assess whether sequential or guessable IDs enable enumeration of records." },
        { id: "API-BOLA-04", l: "advanced", t: "Test object access via alternate methods",
          d: "Compare authorization across GET/POST/PUT/PATCH/DELETE and bulk endpoints for the same object." }
      ]
    },
    {
      id: "bfla",
      title: "Function-Level Authorization (API5)",
      wstg: "API5:2023",
      items: [
        { id: "API-BFLA-01", l: "basic", t: "Test access to administrative functions",
          d: "Attempt privileged operations as a standard user and confirm role enforcement on the server." },
        { id: "API-BFLA-02", l: "intermediate", t: "Test method-based function access",
          d: "Try alternate HTTP methods on the same path to reach functions the UI does not expose to the role." },
        { id: "API-BFLA-03", l: "advanced", t: "Test group and role boundary logic",
          d: "Review complex role hierarchies and delegated permissions for gaps between defined and enforced access." }
      ]
    },
    {
      id: "propauthz",
      title: "Property-Level Authorization (API3)",
      wstg: "API3:2023",
      items: [
        { id: "API-PROP-01", l: "intermediate", t: "Test mass assignment / auto-binding",
          d: "Submit additional properties (e.g. role, verified, balance) to see if the API binds them without allow-listing." },
        { id: "API-PROP-02", l: "intermediate", t: "Test excessive data exposure",
          d: "Inspect responses for fields beyond what the client needs (internal flags, other users' data, PII)." },
        { id: "API-PROP-03", l: "advanced", t: "Test field-level authorization in GraphQL",
          d: "Confirm sensitive fields and mutations enforce authorization independently of the containing query." }
      ]
    },
    {
      id: "resources",
      title: "Resource Consumption (API4)",
      wstg: "API4:2023",
      items: [
        { id: "API-RES-01", l: "basic", t: "Test rate limiting and quotas",
          d: "Assess presence and effectiveness of rate limits per client, token and endpoint." },
        { id: "API-RES-02", l: "intermediate", t: "Test pagination and result-size limits",
          d: "Attempt oversized page sizes and unbounded queries that could exhaust resources." },
        { id: "API-RES-03", l: "advanced", t: "Test GraphQL query cost and depth",
          d: "Assess depth limiting, complexity analysis and aliasing/batching abuse that amplify server work." },
        { id: "API-RES-04", l: "advanced", t: "Test resource-intensive operations",
          d: "Review file processing, exports and integrations for cost controls against amplification abuse." }
      ]
    },
    {
      id: "input",
      title: "Input Validation & Injection",
      wstg: "—",
      items: [
        { id: "API-INPV-01", l: "basic", t: "Test injection in parameters and bodies",
          d: "Assess SQL/NoSQL/command/expression injection across query, path, header and JSON/XML body inputs." },
        { id: "API-INPV-02", l: "intermediate", t: "Test SSRF via URL parameters",
          d: "Identify server-side fetches driven by input and assess reach to internal services and metadata endpoints." },
        { id: "API-INPV-03", l: "intermediate", t: "Test content-type and parser handling",
          d: "Send unexpected content types and malformed bodies to probe parser behaviour and validation gaps." },
        { id: "API-INPV-04", l: "intermediate", t: "Test file upload endpoints",
          d: "Assess type/size validation and downstream processing of uploaded content." },
        { id: "API-INPV-05", l: "advanced", t: "Test deserialization of untrusted input",
          d: "Review endpoints that deserialize input for unsafe type handling." }
      ]
    },
    {
      id: "ssrf-inv",
      title: "Business Logic & Inventory",
      wstg: "API6/API9/API10:2023",
      items: [
        { id: "API-BIZ-01", l: "intermediate", t: "Test sensitive business flows (API6)",
          d: "Identify automatable high-value flows (purchase, transfer, signup) and assess anti-automation controls." },
        { id: "API-INV-01", l: "intermediate", t: "Assess inventory management (API9)",
          d: "Confirm old versions and non-production hosts are decommissioned; test any reachable staging/debug APIs." },
        { id: "API-CONS-01", l: "advanced", t: "Test safe consumption of third-party APIs (API10)",
          d: "Review how the API trusts and validates data from upstream services and integrations." }
      ]
    },
    {
      id: "transport",
      title: "Transport, Config & Data Protection",
      wstg: "API8:2023",
      items: [
        { id: "API-CONF-01", l: "basic", t: "Enforce transport security",
          d: "Confirm TLS is required, redirects to plaintext are absent and sensitive data is not sent unencrypted." },
        { id: "API-CONF-02", l: "basic", t: "Review CORS policy",
          d: "Assess allowed origins, credentials and methods for over-permissive cross-origin access." },
        { id: "API-CONF-03", l: "intermediate", t: "Review error handling and verbosity",
          d: "Trigger errors to check for stack traces, internal paths or data leakage in responses." },
        { id: "API-CONF-04", l: "intermediate", t: "Review caching of sensitive responses",
          d: "Confirm sensitive responses set appropriate cache controls and are not stored by shared caches." },
        { id: "API-CONF-05", l: "advanced", t: "Review logging and monitoring coverage",
          d: "Assess whether security-relevant events are logged sufficiently to detect abuse without leaking sensitive data." },
        { id: "API-CONF-06", l: "basic", t: "Strict-Transport-Security (HSTS) header",
          d: "Confirm HSTS is set with an adequate max-age so clients refuse plaintext connections to the API host. Complements transport enforcement (API-CONF-01)." },
        { id: "API-CONF-07", l: "basic", t: "X-Content-Type-Options: nosniff header",
          d: "Confirm the header is set so responses are not MIME-sniffed — important where JSON responses might otherwise be interpreted as HTML/script." },
        { id: "API-CONF-08", l: "intermediate", t: "Enforce and validate Content-Type",
          d: "Confirm responses declare the correct Content-Type (e.g. application/json) and the API rejects unexpected request content types, reducing content-confusion and XSS risk when responses are rendered." },
        { id: "API-CONF-09", l: "intermediate", t: "Remove server/framework version banners",
          d: "Flag version-disclosing response headers (Server, X-Powered-By, X-AspNet-Version) that aid targeted attacks and should be suppressed." },
        { id: "API-CONF-10", l: "intermediate", t: "Security headers on browser-facing responses",
          d: "For any HTML the API serves (API docs/Swagger UI, error pages, OAuth screens), confirm CSP, X-Frame-Options/frame-ancestors and X-Content-Type-Options are applied." }
      ]
    },
    {
      id: "reporting",
      title: "Reporting & Wrap-up",
      wstg: "—",
      items: [
        { id: "API-REP-01", l: "basic", t: "Record evidence and reproduction steps",
          d: "Capture requests, responses and clear, minimal reproduction steps for each finding." },
        { id: "API-REP-02", l: "basic", t: "Rate severity and business impact",
          d: "Assign severity and contextualise impact for the specific API and data handled." },
        { id: "API-REP-03", l: "basic", t: "Provide remediation guidance",
          d: "Give actionable, prioritised remediation mapped to the relevant OWASP API risk." },
        { id: "API-REP-04", l: "basic", t: "Clean up test artifacts",
          d: "Remove test data, tokens and accounts created during testing." }
      ]
    }
  ]
};
