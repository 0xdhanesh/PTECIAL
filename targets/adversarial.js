registerTarget({
  "id": "ADV",
  "name": "Adversarial testing",
  "surface": "Authorized active reconnaissance and exploit validation for web and API targets",
  "cases": [
    {
      "id": "ADV-01",
      "category": "Reconnaissance",
      "reference": "CWE-200",
      "title": "Enumerate domains and certificates",
      "level": "Basic",
      "procedure": "For the approved root domain, combine passive subdomain discovery and certificate-transparency records, deduplicate the results, and probe only hosts that are explicitly in scope. Record redirects and ownership boundaries before deeper testing.",
      "evidence": "A dated host inventory with source, resolved address, HTTP status, page title, certificate names, and an in-scope or out-of-scope decision for each host.",
      "exercise": {
        "setup": "Set DOMAIN to the approved root domain. Confirm wildcard and third-party hosting boundaries in the rules of engagement before probing.",
        "steps": [
          "Collect passive subdomain and certificate-transparency names.",
          "Deduplicate the names and remove assets outside the approved scope.",
          "Probe approved HTTP services and record redirects, titles, status codes, and technologies."
        ],
        "command": "subfinder -d \"$DOMAIN\" -silent | sort -u | httpx -silent -status-code -title -tech-detect -location",
        "interpret": "Prioritize unexpected environments, dangling records, administration surfaces, and hosts with different ownership. Passive discovery does not establish authorization to test a host."
      }
    },
    {
      "id": "ADV-02",
      "category": "Reconnaissance",
      "reference": "CWE-200",
      "title": "Fingerprint technologies and exposed API contracts",
      "level": "Basic",
      "procedure": "Inspect approved application responses, HTML, scripts, headers, error pages, and standard documentation locations for framework versions and exposed OpenAPI, Swagger, GraphQL, or developer interfaces. Compare discovered operations with the supplied inventory.",
      "evidence": "URLs and redacted response excerpts identifying technologies, versions, API specifications, GraphQL endpoints, or undocumented operations, with false-positive checks.",
      "exercise": {
        "setup": "Set BASE_URL to an approved origin. Use an unauthenticated request first, then a designated test account if the engagement permits it.",
        "steps": [
          "Capture response headers and visible technology indicators.",
          "Check common API-contract and GraphQL locations without brute forcing.",
          "Compare exposed routes and schemas with the owner-provided inventory."
        ],
        "command": "for path in /openapi.json /swagger.json /swagger-ui/ /api-docs /graphql; do curl -sS -o /dev/null -w \"%{http_code} %{content_type} $path\\n\" \"$BASE_URL$path\"; done",
        "interpret": "A successful response may be a generic application shell or access-denied page. Validate content before reporting a specification or console as exposed."
      }
    },
    {
      "id": "ADV-03",
      "category": "Reconnaissance",
      "reference": "CWE-538",
      "title": "Discover exposed files and administrative paths",
      "level": "Basic",
      "procedure": "Using a small engagement-approved path list, check for source-control metadata, environment files, backups, archives, debug endpoints, administration panels, and directory listings. Keep request volume within the agreed limit and do not download unnecessary sensitive content.",
      "evidence": "The exact URL, status, response signature, content type, size, and a minimally redacted excerpt proving exposure without retaining secrets unnecessarily.",
      "exercise": {
        "setup": "Set BASE_URL to the approved origin and PATHS to a short, reviewed wordlist. Avoid recursive discovery unless it is explicitly authorized.",
        "steps": [
          "Check high-signal paths at the agreed request rate.",
          "Distinguish real resources from custom 200 responses using length and content signatures.",
          "Stop after proof and notify the owner immediately if live credentials or private keys appear."
        ],
        "command": "ffuf -u \"$BASE_URL/FUZZ\" -w \"$PATHS\" -rate 5 -mc all -fc 404",
        "interpret": "Status alone is insufficient. Compare body signatures with a random nonexistent path and preserve only the minimum evidence needed."
      }
    },
    {
      "id": "ADV-04",
      "category": "Broken access control",
      "reference": "CWE-639",
      "title": "Test horizontal IDOR and BOLA",
      "level": "Intermediate",
      "procedure": "Identify object identifiers in approved requests, including path, query, body, and nested references. With two designated accounts at the same privilege level, replace account A identifiers with account B identifiers in read and write operations and verify server-side ownership decisions.",
      "evidence": "Redacted baseline and modified request/response pairs showing unauthorized access or the exact authorization rejection, plus object ownership and account identities.",
      "exercise": {
        "setup": "Create two disposable test accounts in the same test tenant and one object owned by each account.",
        "steps": [
          "Capture a successful owner request for each object.",
          "Replay account A's request with account B's object identifier in every relevant location.",
          "Repeat separately for read, update, delete, export, and nested-object operations that are in scope."
        ],
        "command": "curl -i \"$BASE_URL/api/objects/$ACCOUNT_B_OBJECT\" -H \"Authorization: Bearer $ACCOUNT_A_TOKEN\"",
        "interpret": "A secure response denies access without revealing object details. Confirm that failed writes caused no state change or asynchronous side effect."
      }
    },
    {
      "id": "ADV-05",
      "category": "Broken access control",
      "reference": "CWE-862",
      "title": "Test vertical privilege enforcement",
      "level": "Advanced",
      "procedure": "Map privileged functions from the UI and API contract. Using a designated low-privilege account, call the underlying operations directly, vary methods and content types, and test identifiers belonging to privileged roles without modifying production data.",
      "evidence": "A role-to-operation matrix with redacted direct requests, authorization outcomes, and proof that denied operations produced no state transition.",
      "exercise": {
        "setup": "Use disposable low-privilege and administrator accounts in an approved environment. Select reversible operations or dry-run endpoints.",
        "steps": [
          "Capture an administrator baseline and identify the server operation.",
          "Repeat with the low-privilege identity, independent of UI visibility.",
          "Test method and content-type variants, then verify the authoritative state and audit trail."
        ],
        "command": "curl -i -X POST \"$BASE_URL/api/admin/action\" -H \"Authorization: Bearer $USER_TOKEN\" -H \"Content-Type: application/json\" --data '{\"dryRun\":true}'",
        "interpret": "Hiding a control in the client is not authorization. The server must deny the operation before any durable or queued side effect."
      }
    },
    {
      "id": "ADV-06",
      "category": "Client-side injection",
      "reference": "CWE-79",
      "title": "Test reflected XSS across output contexts",
      "level": "Intermediate",
      "procedure": "Locate reflected input in HTML, attributes, script, JSON, and URL contexts. Begin with a unique inert marker, determine the encoding context, and use the smallest approved proof payload needed to confirm script execution. Record any browser or policy mitigation separately from application encoding.",
      "evidence": "The source request, response excerpt showing the output context, browser execution proof using a harmless marker, and applicable CSP or sanitization behavior.",
      "exercise": {
        "setup": "Use an approved test environment and a harmless proof action such as setting a local marker. Do not use payloads that read cookies, tokens, or user data.",
        "steps": [
          "Submit a unique alphanumeric marker and locate every reflection.",
          "Classify each reflection by parser and output context.",
          "Apply context-specific delimiter probes, then confirm only with a harmless execution marker."
        ],
        "command": "curl -sS -G \"$BASE_URL/search\" --data-urlencode \"q=PTECIAL_XSS_01\"",
        "interpret": "Reflection alone is not XSS. Demonstrate executable context and distinguish correct encoding from CSP-only containment."
      }
    },
    {
      "id": "ADV-07",
      "category": "Client-side injection",
      "reference": "CWE-79",
      "title": "Test stored and second-order XSS",
      "level": "Advanced",
      "procedure": "Place a unique inert marker in approved persistent fields and trace it through end-user, administrative, export, email-preview, and audit views. For unsafe renderings, use a harmless proof payload and verify execution under a separate designated viewer account.",
      "evidence": "The storage request, affected rendering context, viewer role, harmless execution proof, persistence duration, and cleanup confirmation.",
      "exercise": {
        "setup": "Use disposable author and viewer accounts and content that can be removed. Coordinate before testing staff-only or notification views.",
        "steps": [
          "Store a unique inert marker in each approved rich- or plain-text field.",
          "Inspect every downstream rendering surface with the viewer account.",
          "Use a minimal proof only where the marker reaches an unsafe context, then remove the test content."
        ],
        "command": "curl -i -X POST \"$BASE_URL/api/profile\" -H \"Authorization: Bearer $AUTHOR_TOKEN\" -H \"Content-Type: application/json\" --data '{\"displayName\":\"PTECIAL_STORED_01\"}'",
        "interpret": "Record the trust boundary crossed. A stored value can be safe in one view and executable in another due to context-specific rendering."
      }
    },
    {
      "id": "ADV-08",
      "category": "Server-side injection",
      "reference": "CWE-89",
      "title": "Test SQL and NoSQL injection entry points",
      "level": "Advanced",
      "procedure": "Inventory filter, search, sort, identifier, JSON, GraphQL, and authentication inputs. Use paired boolean, type-confusion, error, and bounded timing probes appropriate to the suspected data store, changing one input at a time and avoiding destructive statements or bulk extraction.",
      "evidence": "Paired control and probe requests with repeatable response, timing, or state differences; affected parameter and backend evidence; and proof that no destructive action occurred.",
      "exercise": {
        "setup": "Use an approved non-production dataset and establish latency baselines. Never use stacked, destructive, or data-extraction payloads for initial confirmation.",
        "steps": [
          "Map every input to its expected type and likely query role.",
          "Run paired true/false or valid/type-confused probes with identical surrounding requests.",
          "Repeat candidates to eliminate caching and normal timing variance, then stop at minimal proof."
        ],
        "command": "curl -sS -G \"$BASE_URL/api/search\" -H \"Authorization: Bearer $TOKEN\" --data-urlencode \"q=PTECIAL_PROBE\" -w '\\nstatus=%{http_code} time=%{time_total}\\n'",
        "interpret": "Errors and latency spikes are leads, not proof. Require a repeatable relationship between controlled input and query behavior."
      }
    },
    {
      "id": "ADV-09",
      "category": "Authentication and tokens",
      "reference": "CWE-347",
      "title": "Test JWT and session validation",
      "level": "Advanced",
      "procedure": "Inspect approved session tokens and verifier behavior for algorithm restrictions, signature enforcement, issuer, audience, expiry, key selection, token type, and logout revocation. Test one altered property at a time with non-sensitive claims and designated accounts.",
      "evidence": "Decoded redacted headers and claims, original and altered token outcomes, verifier configuration or error evidence, and logout or expiry behavior.",
      "exercise": {
        "setup": "Use a disposable account and redact token values from notebook evidence. Keep token mutations local to the approved verifier.",
        "steps": [
          "Record the expected issuer, audience, algorithm, token type, and lifetime.",
          "Alter payload, signature, expiry, audience, issuer, algorithm header, and key identifier separately.",
          "Verify logout, password change, and role change behavior against existing tokens."
        ],
        "command": "curl -i \"$BASE_URL/api/me\" -H \"Authorization: Bearer $ALTERED_TOKEN\"",
        "interpret": "Every invalid token should fail closed before authorization. Different error bodies can also expose token-validation details useful to an attacker."
      }
    },
    {
      "id": "ADV-10",
      "category": "Authentication and tokens",
      "reference": "CWE-308",
      "title": "Test MFA, recovery, and step-up bypass",
      "level": "Advanced",
      "procedure": "Exercise sign-in, recovery, remembered-device, factor replacement, and privileged step-up flows with disposable accounts. Attempt direct navigation, stale-session reuse, alternate API operations, and workflow reordering to determine whether the required factor is enforced server-side.",
      "evidence": "A state-transition record showing factor challenges, session identifiers or ages in redacted form, attempted bypass paths, notifications, and the final authoritative account state.",
      "exercise": {
        "setup": "Use a recoverable disposable account with two enrolled test factors. Coordinate notification and lockout testing with the owner.",
        "steps": [
          "Capture normal sign-in, recovery, factor replacement, and privileged-action baselines.",
          "Repeat protected operations using pre-challenge, remembered, recovered, and stale sessions.",
          "Reorder or omit workflow steps and verify server-side state plus user notification."
        ],
        "command": "curl -i \"$BASE_URL/api/security/factors\" -H \"Authorization: Bearer $PRE_CHALLENGE_TOKEN\"",
        "interpret": "A client-side prompt is not enforcement. Protected operations must verify the required assurance level and freshness on the server."
      }
    },
    {
      "id": "ADV-11",
      "category": "File handling",
      "reference": "CWE-434",
      "title": "Test malicious file upload controls",
      "level": "Advanced",
      "procedure": "Using benign canary files, test filename normalization, extension and MIME disagreement, duplicate extensions, archive handling, active content, retrieval headers, storage isolation, authorization, and scanner fail-open behavior. Do not upload live malware or executable server code.",
      "evidence": "Upload and retrieval request pairs, server-assigned name and location, validation or scanner decision, response headers, rendering behavior, access control, and cleanup proof.",
      "exercise": {
        "setup": "Prepare harmless text, image, SVG, HTML, and archive canaries with unique markers. Obtain approval before testing parser bombs or antivirus signatures.",
        "steps": [
          "Establish accepted type, size, name, and retrieval behavior with a valid file.",
          "Vary declared MIME type, extension, filename, internal signature, and archive contents one at a time.",
          "Test retrieval as owner, another user, and unauthenticated client, then delete every canary."
        ],
        "command": "curl -i -X POST \"$BASE_URL/api/uploads\" -H \"Authorization: Bearer $TOKEN\" -F \"file=@$CANARY;type=$DECLARED_TYPE\"",
        "interpret": "Extension blocking alone is weak. Validate content, store outside executable paths, assign server names, isolate access, and serve with safe headers."
      }
    },
    {
      "id": "ADV-12",
      "category": "Server-side request forgery",
      "reference": "CWE-918",
      "title": "Test SSRF and metadata protections",
      "level": "Advanced",
      "procedure": "Identify server-side URL fetchers such as webhooks, imports, previews, image processors, and PDF generators. Use an engagement-controlled callback endpoint to test protocol, redirect, DNS, IP-literal, and hostname validation. Test cloud metadata defenses only when explicitly approved.",
      "evidence": "The triggering request, unique callback correlation, source address and headers, redirect chain, blocked internal-address attempts, and egress-control behavior without captured credentials.",
      "exercise": {
        "setup": "Set CALLBACK_URL to a unique path on an approved interaction server. Obtain explicit approval before addressing private, loopback, link-local, or cloud metadata services.",
        "steps": [
          "Confirm a normal fetch to the unique callback URL.",
          "Test scheme restrictions and one-hop redirects to disallowed destinations.",
          "Under explicit approval, verify that loopback, private, link-local, and metadata ranges are blocked before and after DNS resolution."
        ],
        "command": "curl -i -X POST \"$BASE_URL/api/preview\" -H \"Authorization: Bearer $TOKEN\" -H \"Content-Type: application/json\" --data \"{\\\"url\\\":\\\"$CALLBACK_URL\\\"}\"",
        "interpret": "An application response is not enough; correlate the out-of-band request. Do not collect metadata credentials—prove reachability with a harmless path or documented block."
      }
    },
    {
      "id": "ADV-13",
      "category": "Business logic",
      "reference": "CWE-841",
      "title": "Test workflow and state-machine bypass",
      "level": "Advanced",
      "procedure": "Model a high-value workflow as states, transitions, actors, prerequisites, and invariants. With disposable records, attempt skipped, repeated, reordered, stale, cross-account, and direct API transitions while keeping monetary or irreversible effects disabled.",
      "evidence": "The expected and observed state diagrams, transition requests, actor identities, timestamps, authoritative records, and any invariant broken by an accepted transition.",
      "exercise": {
        "setup": "Choose an approved workflow such as checkout, approval, refund, invitation, or entitlement grant. Use sandbox values and reversible records.",
        "steps": [
          "Document normal states, actors, prerequisites, and one-time transitions.",
          "Attempt direct final-state calls, omitted prerequisites, replay, reordering, and stale-object transitions.",
          "Verify authoritative state, ledger, notifications, queued jobs, and audit records after each attempt."
        ],
        "command": "curl -i -X POST \"$BASE_URL/api/orders/$ORDER_ID/complete\" -H \"Authorization: Bearer $TOKEN\" -H \"Content-Type: application/json\" --data '{\"dryRun\":true}'",
        "interpret": "A secure workflow checks invariants at each server-side transition, not merely the presence of an earlier UI step."
      }
    },
    {
      "id": "ADV-14",
      "category": "Business logic",
      "reference": "CWE-362",
      "title": "Test race conditions and replay safety",
      "level": "Advanced",
      "procedure": "Select an approved one-time or limited operation and send a small, synchronized set of identical or conflicting requests. Test idempotency-key scope and retry semantics, then reconcile API responses with the authoritative database or ledger and downstream jobs.",
      "evidence": "Timestamped concurrent requests and responses, idempotency keys, final record or balance, job history, and proof of any duplicated or contradictory side effect.",
      "exercise": {
        "setup": "Use a sandbox operation with no real financial, inventory, messaging, or account impact. Agree on a low concurrency ceiling.",
        "steps": [
          "Establish the expected single-request transition and final state.",
          "Send the approved number of synchronized requests with the same key, then with distinct keys where appropriate.",
          "Reconcile responses, stored state, audit events, and asynchronous side effects."
        ],
        "command": "seq 1 5 | xargs -P5 -I{} curl -sS -o \"/tmp/ptecial-race-{}.out\" -w \"{} %{http_code} %{time_total}\\n\" -X POST \"$BASE_URL/api/test-operation\" -H \"Authorization: Bearer $TOKEN\" -H \"Idempotency-Key: $KEY\"",
        "interpret": "Multiple success responses are not necessarily a vulnerability if one logical effect occurs. Judge the authoritative state and all downstream effects."
      }
    },
    {
      "id": "ADV-15",
      "category": "Abuse controls",
      "reference": "CWE-307",
      "title": "Test rate-limit and lockout boundaries",
      "level": "Intermediate",
      "procedure": "At an agreed low request ceiling, test whether authentication, recovery, verification, search, export, and expensive operations enforce limits consistently across account, session, token, source address, endpoint aliases, and relevant normalized identifiers. Avoid distributed or production denial-of-service testing.",
      "evidence": "A request timeline showing limit thresholds, counter scope, response headers, cooldown and reset behavior, alternate-path results, and absence of lockout impact on unrelated accounts.",
      "exercise": {
        "setup": "Agree on request counts and cooldowns with the owner. Use disposable accounts and one source address; do not rotate infrastructure without explicit authorization.",
        "steps": [
          "Record baseline responses and advertised limit headers.",
          "Reach the agreed threshold on one operation and observe enforcement and recovery.",
          "Check only approved aliases, identifier normalization variants, and adjacent operations for shared counter behavior."
        ],
        "command": "for n in 1 2 3 4 5; do curl -sS -o /dev/null -D - \"$BASE_URL/api/limited-operation\" -H \"Authorization: Bearer $TOKEN\" | grep -Ei '^(HTTP/|Retry-After:|RateLimit-|X-RateLimit-)'; done",
        "interpret": "Rate limits should protect the resource without enabling cheap lockout of other users. Document counter dimensions and reset behavior, not just a single 429 response."
      }
    },
    {
      "id": "ADV-16",
      "category": "Caching and intermediaries",
      "reference": "CWE-444",
      "title": "Test cache poisoning and cache deception",
      "level": "Advanced",
      "procedure": "Where shared caching is confirmed, map the cache key and variation behavior using unique harmless markers. Test unkeyed request inputs, ambiguous routing headers, normalization differences, and deceptive path suffixes only on isolated test objects; never poison broadly used production content.",
      "evidence": "Paired priming and retrieval responses with cache-status and age headers, unique marker, cache-key dimensions, affected route, persistence window, and purge confirmation.",
      "exercise": {
        "setup": "Confirm a shared cache and obtain an isolated hostname, route, or test object. Set MARKER to a unique harmless value and arrange purge access.",
        "steps": [
          "Establish MISS and HIT behavior for the isolated object.",
          "Vary one candidate keyed or unkeyed input and retrieve from a clean client context.",
          "Test authenticated response caching and deceptive suffix handling, then purge and verify removal."
        ],
        "command": "curl -sS -D - -o /dev/null \"$BASE_URL/$TEST_PATH?marker=$MARKER\"",
        "interpret": "Require evidence that one request changes a representation served to another client or exposes private content. A reflected header on a cache miss is not sufficient."
      }
    }
  ]
});
