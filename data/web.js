/*
 * Web Application Pentest Checklist
 * Levels: basic | intermediate | advanced
 * Item IDs are stable identifiers used for saved progress and markdown import.
 * Aligned to OWASP WSTG and the OWASP Top 10. Reference / checklist altitude.
 */
window.CHECKLISTS = window.CHECKLISTS || {};
window.CHECKLISTS.web = {
  id: "web",
  title: "Web Application Pentest",
  ref: "OWASP WSTG v4.2 / OWASP Top 10:2021",
  description: "Web application testing checklist, basics to advanced.",
  sections: [
    {
      id: "recon",
      title: "Reconnaissance & Information Gathering",
      wstg: "WSTG-INFO",
      items: [
        { id: "WEB-RECON-01", l: "basic", t: "Confirm scope and authorization",
          d: "Verify in-scope domains, IPs, environments, test accounts and testing windows. Confirm prohibited techniques and hold written authorization before starting." },
        { id: "WEB-RECON-02", l: "basic", t: "Enumerate subdomains and hosts",
          d: "Combine passive sources (certificate transparency, public datasets) with resolution and live-host probing to build the attack surface inventory." },
        { id: "WEB-RECON-03", l: "basic", t: "Fingerprint server, framework and components",
          d: "Identify web server, framework, CMS and client-side libraries with versions from headers, cookies and error pages. Record versions for known-vulnerability lookup." },
        { id: "WEB-RECON-04", l: "basic", t: "Review well-known and metadata files",
          d: "Inspect robots.txt, sitemap.xml, security.txt and other /.well-known resources for referenced or hidden endpoints." },
        { id: "WEB-RECON-05", l: "basic", t: "Search public sources for exposure",
          d: "Review search-engine results, code-hosting platforms and web archives for leaked endpoints, credentials or configuration references tied to the target." },
        { id: "WEB-RECON-06", l: "basic", t: "Crawl and map the application",
          d: "Spider authenticated and unauthenticated views to enumerate all functions, roles and entry points. Maintain a coverage map of the application." },
        { id: "WEB-RECON-07", l: "intermediate", t: "Content and directory discovery",
          d: "Enumerate paths, files and backup artifacts using context-aware wordlists. Note temporary, backup and editor swap files that may expose source or config." },
        { id: "WEB-RECON-08", l: "intermediate", t: "Analyse client-side JavaScript",
          d: "Extract routes, API endpoints, feature flags and references to secrets from JS bundles and any exposed source maps." },
        { id: "WEB-RECON-09", l: "intermediate", t: "Check for exposed source control and config",
          d: "Probe for exposed version-control directories and configuration/manifest files that may disclose source code, dependencies or secrets." },
        { id: "WEB-RECON-10", l: "intermediate", t: "Discover hidden parameters",
          d: "Identify undocumented query, body, header and cookie parameters that alter behaviour (e.g. debug or role toggles)." },
        { id: "WEB-RECON-11", l: "advanced", t: "Identify origin behind CDN/WAF",
          d: "Correlate historical DNS, certificate data and application artifacts to locate origin infrastructure that may bypass edge protections." },
        { id: "WEB-RECON-12", l: "advanced", t: "Map trust relationships and integrations",
          d: "Document third-party integrations, SSO/IdP relationships, webhooks and internal services that widen the trust boundary." }
      ]
    },
    {
      id: "config",
      title: "Configuration & Deployment Management",
      wstg: "WSTG-CONF",
      items: [
        { id: "WEB-CONF-01", l: "basic", t: "Review TLS configuration",
          d: "Check protocol versions, cipher suites, certificate validity and HSTS. Flag deprecated protocols and mixed content." },
        { id: "WEB-CONF-02", l: "basic", t: "Baseline security-header review",
          d: "Confirm the standard response-header baseline is present across pages and responses. See the Security Response Headers section for per-header checks and the issue each mitigates." },
        { id: "WEB-CONF-03", l: "basic", t: "Test HTTP methods",
          d: "Enumerate allowed methods per endpoint and check for unsafe or unintended methods (e.g. PUT, DELETE, TRACE) being accepted." },
        { id: "WEB-CONF-04", l: "intermediate", t: "Look for default and sample content",
          d: "Identify default credentials, sample apps, admin consoles and management interfaces left exposed after deployment." },
        { id: "WEB-CONF-05", l: "intermediate", t: "Review error handling and stack traces",
          d: "Trigger error conditions to check for verbose messages, stack traces or internal paths that disclose implementation details." },
        { id: "WEB-CONF-06", l: "intermediate", t: "Inspect cloud storage and metadata exposure",
          d: "Check for publicly accessible object storage and any reachable cloud metadata endpoints from server-side request contexts." },
        { id: "WEB-CONF-07", l: "advanced", t: "Review subdomain and DNS takeover risk",
          d: "Identify dangling DNS records pointing to unclaimed third-party services that could be claimed by an attacker." }
      ]
    },
    {
      id: "headers",
      title: "Security Response Headers",
      wstg: "WSTG-CONF-12",
      items: [
        { id: "WEB-HDR-01", l: "basic", t: "Content-Security-Policy (CSP) — XSS / injection / data exfiltration",
          d: "Check for a CSP that meaningfully restricts sources. Flag missing policy, 'unsafe-inline'/'unsafe-eval', wildcard or overly broad source lists, and missing object-src 'none' and base-uri. CSP is defence-in-depth for XSS (WEB-INPV-01/02/03)." },
        { id: "WEB-HDR-02", l: "basic", t: "X-Content-Type-Options: nosniff — MIME sniffing",
          d: "Confirm the header is set so browsers do not sniff response content types, preventing content-type confusion that can turn uploads or data into executable script." },
        { id: "WEB-HDR-03", l: "basic", t: "X-Frame-Options / CSP frame-ancestors — clickjacking",
          d: "Confirm framing is restricted via frame-ancestors (preferred) or X-Frame-Options on sensitive, state-changing pages. Ties to clickjacking testing (WEB-CLNT-02)." },
        { id: "WEB-HDR-04", l: "basic", t: "Strict-Transport-Security (HSTS) — TLS downgrade / SSL stripping",
          d: "Confirm HSTS is present with an adequate max-age and, where appropriate, includeSubDomains and preload, so clients refuse plaintext connections." },
        { id: "WEB-HDR-05", l: "basic", t: "Set-Cookie attributes — session theft / CSRF",
          d: "Confirm session cookies use Secure, HttpOnly and an appropriate SameSite value, and consider __Host-/__Secure- prefixes. Ties to session and CSRF testing (WEB-SESS-01/05)." },
        { id: "WEB-HDR-06", l: "intermediate", t: "Referrer-Policy — URL / token leakage",
          d: "Confirm a restrictive Referrer-Policy so sensitive URLs, tokens or identifiers are not leaked to third parties via the Referer header." },
        { id: "WEB-HDR-07", l: "intermediate", t: "Permissions-Policy — powerful browser features",
          d: "Confirm unused powerful features (camera, microphone, geolocation, payment, etc.) are disabled to reduce abuse surface if the page is compromised." },
        { id: "WEB-HDR-08", l: "intermediate", t: "Cache-Control on sensitive responses — data exposure via cache",
          d: "Confirm sensitive responses set no-store / no-cache (and appropriate Pragma/Expires) so credentials or PII are not retained by the browser or shared caches. Ties to WEB-CLNT-04." },
        { id: "WEB-HDR-09", l: "intermediate", t: "CORS headers — over-permissive cross-origin access",
          d: "Review Access-Control-Allow-Origin/Credentials/Methods for reflected or wildcard origins combined with credentials. Ties to CORS testing (WEB-CLNT-01)." },
        { id: "WEB-HDR-10", l: "intermediate", t: "Information-disclosure & legacy headers",
          d: "Flag version-disclosing headers (Server, X-Powered-By, X-AspNet-Version) for removal, and confirm the deprecated X-XSS-Protection is disabled (0) or absent rather than relied upon." },
        { id: "WEB-HDR-11", l: "advanced", t: "Cross-origin isolation (COOP / COEP / CORP) — XS-Leaks / side-channels",
          d: "For sensitive origins, assess Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy and Cross-Origin-Resource-Policy to limit cross-window and cross-origin leakage. Ties to WEB-CLNT-03." },
        { id: "WEB-HDR-12", l: "advanced", t: "Clear-Site-Data — incomplete logout",
          d: "Where used, confirm Clear-Site-Data on logout clears cookies, storage and cache so a shared or stolen device retains no authenticated state." },
        { id: "WEB-HDR-13", l: "advanced", t: "CSP reporting & Trusted Types — DOM XSS hardening",
          d: "Assess report-to/report-uri for policy monitoring and, for high-assurance apps, require-trusted-types-for 'script' to constrain dangerous DOM sinks. Ties to DOM XSS (WEB-INPV-03)." }
      ]
    },
    {
      id: "authn",
      title: "Authentication",
      wstg: "WSTG-ATHN",
      items: [
        { id: "WEB-ATHN-01", l: "basic", t: "Test for weak credential policy",
          d: "Assess password strength requirements, account creation and whether weak or common passwords are permitted." },
        { id: "WEB-ATHN-02", l: "basic", t: "Test transport of credentials",
          d: "Confirm credentials are only submitted over encrypted channels and never placed in URLs, logs or caches." },
        { id: "WEB-ATHN-03", l: "basic", t: "Test for username enumeration",
          d: "Compare responses and timing across login, registration and password-reset flows for signals that reveal valid accounts." },
        { id: "WEB-ATHN-04", l: "intermediate", t: "Test brute-force protections",
          d: "Evaluate rate limiting, lockout and throttling on authentication endpoints, including credential-stuffing resistance." },
        { id: "WEB-ATHN-05", l: "intermediate", t: "Test password reset and recovery",
          d: "Review reset token strength, expiry, single-use, host-header handling and whether reset flows can be abused to take over accounts." },
        { id: "WEB-ATHN-06", l: "intermediate", t: "Test multi-factor authentication",
          d: "Assess MFA enforcement, bypass paths, backup-code handling and whether verification can be skipped or replayed." },
        { id: "WEB-ATHN-07", l: "intermediate", t: "Test remember-me and persistent auth",
          d: "Review persistent login tokens for predictability, scope, revocation and secure storage." },
        { id: "WEB-ATHN-08", l: "advanced", t: "Test SSO / OAuth / OIDC flows",
          d: "Review redirect URI validation, state/nonce handling, token validation, scope grants and account-linking logic for authentication bypass." },
        { id: "WEB-ATHN-09", l: "advanced", t: "Test authentication in APIs and mobile backends",
          d: "Check that shared backends enforce authentication consistently across all client channels, including undocumented ones." }
      ]
    },
    {
      id: "session",
      title: "Session Management",
      wstg: "WSTG-SESS",
      items: [
        { id: "WEB-SESS-01", l: "basic", t: "Review session token generation",
          d: "Confirm tokens are unpredictable, sufficiently long and generated by a secure source. Check cookie flags." },
        { id: "WEB-SESS-02", l: "basic", t: "Test logout and session termination",
          d: "Confirm logout invalidates the session server-side and that tokens cannot be reused afterwards." },
        { id: "WEB-SESS-03", l: "intermediate", t: "Test session fixation",
          d: "Verify the session identifier is rotated on privilege change such as login." },
        { id: "WEB-SESS-04", l: "intermediate", t: "Test session timeout and concurrency",
          d: "Assess idle and absolute timeouts and how concurrent sessions are handled and revoked." },
        { id: "WEB-SESS-05", l: "intermediate", t: "Test CSRF protections",
          d: "Verify state-changing requests require an unpredictable, per-session token or equivalent, and that SameSite behaviour is correct." },
        { id: "WEB-SESS-06", l: "advanced", t: "Test JWT and stateless session handling",
          d: "Review signature verification, algorithm handling, expiry, audience/issuer checks and revocation for token-based sessions." }
      ]
    },
    {
      id: "authz",
      title: "Authorization & Access Control",
      wstg: "WSTG-ATHZ",
      items: [
        { id: "WEB-ATHZ-01", l: "basic", t: "Test vertical privilege escalation",
          d: "Attempt to access higher-privilege functions as a lower-privilege user and confirm server-side enforcement." },
        { id: "WEB-ATHZ-02", l: "basic", t: "Test horizontal access (IDOR)",
          d: "Manipulate object identifiers to access records belonging to other users and confirm per-object ownership checks." },
        { id: "WEB-ATHZ-03", l: "intermediate", t: "Test forced browsing to restricted resources",
          d: "Access admin or restricted URLs directly without navigating the UI to confirm enforcement independent of presentation." },
        { id: "WEB-ATHZ-04", l: "intermediate", t: "Test for insecure direct references in files/exports",
          d: "Check downloadable reports, invoices and exports for missing authorization on the underlying object." },
        { id: "WEB-ATHZ-05", l: "advanced", t: "Test multi-tenant isolation",
          d: "Confirm tenant scoping is enforced on every request so one tenant cannot read or modify another's data." },
        { id: "WEB-ATHZ-06", l: "advanced", t: "Test complex/role-derived authorization logic",
          d: "Review state-dependent and workflow-based permissions where authorization depends on prior steps or record state." }
      ]
    },
    {
      id: "input",
      title: "Input Validation & Injection",
      wstg: "WSTG-INPV",
      items: [
        { id: "WEB-INPV-01", l: "basic", t: "Test for reflected XSS",
          d: "Identify reflected inputs rendered without contextual encoding. Confirm impact within the response context." },
        { id: "WEB-INPV-02", l: "basic", t: "Test for stored XSS",
          d: "Identify persisted inputs rendered to other users without encoding. Track cross-user impact." },
        { id: "WEB-INPV-03", l: "intermediate", t: "Test for DOM-based XSS",
          d: "Trace client-side sinks that consume attacker-controllable sources without safe handling." },
        { id: "WEB-INPV-04", l: "basic", t: "Test for SQL injection",
          d: "Identify inputs reaching database queries. Confirm via error, boolean or time-based behaviour and assess parameterization." },
        { id: "WEB-INPV-05", l: "intermediate", t: "Test for NoSQL and ORM injection",
          d: "Test operator and structure injection in document-store and ORM-backed queries." },
        { id: "WEB-INPV-06", l: "intermediate", t: "Test for command injection",
          d: "Identify inputs passed to OS commands and confirm whether shell metacharacters are neutralised." },
        { id: "WEB-INPV-07", l: "intermediate", t: "Test for server-side template injection",
          d: "Detect user input evaluated by a server-side template engine leading to expression evaluation." },
        { id: "WEB-INPV-08", l: "intermediate", t: "Test for LDAP / XPath / header injection",
          d: "Assess injection into directory queries, XPath expressions and response headers (including CRLF)." },
        { id: "WEB-INPV-09", l: "intermediate", t: "Test for open redirect",
          d: "Check redirect parameters for unvalidated destinations that can be pointed off-site." },
        { id: "WEB-INPV-10", l: "advanced", t: "Test for SSRF",
          d: "Identify server-side fetches driven by user input and assess reachability of internal services and metadata endpoints." },
        { id: "WEB-INPV-11", l: "advanced", t: "Test for XXE and unsafe deserialization",
          d: "Assess XML parsers for external-entity handling and object deserialization paths for unsafe type handling." },
        { id: "WEB-INPV-12", l: "advanced", t: "Test for HTTP request smuggling",
          d: "Assess front-end/back-end parsing discrepancies in request framing that desynchronize the connection." },
        { id: "WEB-INPV-13", l: "advanced", t: "Test for prototype pollution",
          d: "Identify inputs that pollute object prototypes on client or server, leading to downstream impact." }
      ]
    },
    {
      id: "logic",
      title: "Business Logic",
      wstg: "WSTG-BUSL",
      items: [
        { id: "WEB-BUSL-01", l: "intermediate", t: "Test workflow and sequence bypass",
          d: "Attempt to skip, repeat or reorder steps in multi-step flows (checkout, onboarding, approvals)." },
        { id: "WEB-BUSL-02", l: "intermediate", t: "Test quantity, price and limit tampering",
          d: "Manipulate quantities, prices, discounts and negative/overflow values to detect missing server-side validation." },
        { id: "WEB-BUSL-03", l: "intermediate", t: "Test race conditions",
          d: "Send concurrent requests to state-changing actions to detect double-processing or limit bypass." },
        { id: "WEB-BUSL-04", l: "advanced", t: "Test abuse of intended functionality",
          d: "Identify features that can be abused at scale or in unintended combinations to cause harm or gain advantage." }
      ]
    },
    {
      id: "clientside",
      title: "Client-Side & Data Handling",
      wstg: "WSTG-CLNT",
      items: [
        { id: "WEB-CLNT-01", l: "basic", t: "Review CORS configuration",
          d: "Assess allowed origins, credentials and methods for over-permissive cross-origin access to sensitive endpoints." },
        { id: "WEB-CLNT-02", l: "intermediate", t: "Test clickjacking protections",
          d: "Confirm framing controls (frame-ancestors / X-Frame-Options) on sensitive, state-changing pages." },
        { id: "WEB-CLNT-03", l: "intermediate", t: "Test postMessage and web messaging",
          d: "Review origin validation on message handlers exchanging data across frames or windows." },
        { id: "WEB-CLNT-04", l: "intermediate", t: "Review sensitive data in client storage",
          d: "Check localStorage, sessionStorage, IndexedDB and caches for tokens or PII that should not persist client-side." },
        { id: "WEB-CLNT-05", l: "advanced", t: "Review third-party scripts and supply chain",
          d: "Assess included third-party scripts, subresource integrity and the risk of a compromised dependency." }
      ]
    },
    {
      id: "files",
      title: "File Handling & Uploads",
      wstg: "WSTG-BUSL-09",
      items: [
        { id: "WEB-FILE-01", l: "intermediate", t: "Test upload validation",
          d: "Assess type, extension, content and size validation and whether uploads can be stored or served as executable content." },
        { id: "WEB-FILE-02", l: "intermediate", t: "Test path traversal in file operations",
          d: "Assess download, include and storage operations for traversal into unintended locations." },
        { id: "WEB-FILE-03", l: "advanced", t: "Test upload processing side effects",
          d: "Review server-side processing (image, document, archive handling) for parser-level and extraction vulnerabilities." }
      ]
    },
    {
      id: "reporting",
      title: "Reporting & Wrap-up",
      wstg: "—",
      items: [
        { id: "WEB-REP-01", l: "basic", t: "Record evidence and reproduction steps",
          d: "Capture requests, responses and screenshots with clear, minimal reproduction steps for each finding." },
        { id: "WEB-REP-02", l: "basic", t: "Rate severity and business impact",
          d: "Assign severity using an agreed model and contextualise impact for the specific application and data." },
        { id: "WEB-REP-03", l: "basic", t: "Provide remediation guidance",
          d: "Give actionable, prioritised remediation and reference secure design guidance." },
        { id: "WEB-REP-04", l: "basic", t: "Clean up test artifacts",
          d: "Remove test accounts, uploaded files and injected data created during testing." }
      ]
    }
  ]
};
