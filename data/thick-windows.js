/*
 * Thick Client (Windows) Pentest Checklist
 * Levels: basic | intermediate | advanced
 * Item IDs are stable identifiers used for saved progress and markdown import.
 * Reference / checklist altitude. Aligned to OWASP thick-client guidance and common Windows desktop app testing practice.
 */
window.CHECKLISTS = window.CHECKLISTS || {};
window.CHECKLISTS["thick-windows"] = {
  id: "thick-windows",
  title: "Thick Client — Windows",
  ref: "OWASP thick-client testing / Windows desktop apps",
  description: "Windows desktop (thick client) testing checklist, basics to advanced.",
  sections: [
    {
      id: "recon",
      title: "Information Gathering & App Profiling",
      wstg: "—",
      items: [
        { id: "TCW-RECON-01", l: "basic", t: "Confirm scope and authorization",
          d: "Confirm the application, versions, test hosts, accounts and backend endpoints in scope, and hold written authorization." },
        { id: "TCW-RECON-02", l: "basic", t: "Identify architecture (two-tier vs three-tier)",
          d: "Determine whether the client talks directly to a database (two-tier) or via application/API servers (three-tier). This shapes the whole test plan." },
        { id: "TCW-RECON-03", l: "basic", t: "Enumerate installed files and directories",
          d: "Map the install directory, config files, logs, data files and any bundled tools or drivers. Note file permissions on each." },
        { id: "TCW-RECON-04", l: "basic", t: "Identify frameworks and languages",
          d: "Determine the platform (.NET, C/C++, Java, Electron, Delphi, etc.) — this drives the decompilation and instrumentation approach." },
        { id: "TCW-RECON-05", l: "intermediate", t: "Enumerate loaded modules and dependencies",
          d: "List DLLs, third-party libraries and their versions for known-vulnerability lookup and to spot unsafe load paths." },
        { id: "TCW-RECON-06", l: "intermediate", t: "Identify backend endpoints and protocols",
          d: "Discover the servers, ports, protocols (HTTP(S), TCP, named pipes, RPC, database) the client communicates with." }
      ]
    },
    {
      id: "static",
      title: "Binary & Static Analysis",
      wstg: "—",
      items: [
        { id: "TCW-STAT-01", l: "basic", t: "Inspect binary metadata and strings",
          d: "Review file metadata, embedded strings and resources for endpoints, credentials, comments and version data." },
        { id: "TCW-STAT-02", l: "intermediate", t: "Decompile / disassemble managed and native code",
          d: "Recover logic from .NET/Java bytecode or native binaries to review sensitive routines, validation and secrets handling." },
        { id: "TCW-STAT-03", l: "intermediate", t: "Search for hardcoded secrets",
          d: "Look for embedded credentials, API keys, connection strings, tokens and encryption keys in code, config and resources." },
        { id: "TCW-STAT-04", l: "intermediate", t: "Review binary protections",
          d: "Check for signing, ASLR/DEP, control-flow protections, anti-tamper and obfuscation, and assess whether they are effective." },
        { id: "TCW-STAT-05", l: "advanced", t: "Review update mechanism integrity",
          d: "Assess how updates are fetched and verified (signature, transport) and whether a malicious update could be delivered." }
      ]
    },
    {
      id: "storage",
      title: "Local Storage, Config & Registry",
      wstg: "—",
      items: [
        { id: "TCW-STOR-01", l: "basic", t: "Review config files for sensitive data",
          d: "Inspect app config, INI, XML and JSON files for credentials, keys and connection strings, and check their access permissions." },
        { id: "TCW-STOR-02", l: "basic", t: "Review the Windows Registry",
          d: "Examine registry keys the app creates or reads for sensitive values, weak ACLs or configuration that alters trust." },
        { id: "TCW-STOR-03", l: "intermediate", t: "Assess sensitive data at rest",
          d: "Check local databases, cache, temp files and user-profile data for unencrypted sensitive information." },
        { id: "TCW-STOR-04", l: "intermediate", t: "Review use of DPAPI / credential storage",
          d: "Assess whether secrets rely on the current-user context appropriately and cannot be trivially recovered by another local user." },
        { id: "TCW-STOR-05", l: "intermediate", t: "Review logging for sensitive data",
          d: "Check application and debug logs for credentials, tokens, PII or other sensitive data written in clear text." },
        { id: "TCW-STOR-06", l: "advanced", t: "Assess custom encryption of stored data",
          d: "Where the app encrypts stored data itself, review algorithm choice, key management and whether keys are recoverable locally." }
      ]
    },
    {
      id: "network",
      title: "Network & Backend Communication",
      wstg: "—",
      items: [
        { id: "TCW-NET-01", l: "basic", t: "Intercept HTTP(S) traffic",
          d: "Proxy application HTTP(S) traffic to review requests, responses, endpoints and parameters." },
        { id: "TCW-NET-02", l: "intermediate", t: "Capture non-HTTP / raw TCP traffic",
          d: "Where the client uses raw TCP or custom protocols, capture and analyse the traffic to understand the message format." },
        { id: "TCW-NET-03", l: "intermediate", t: "Test transport security and cert validation",
          d: "Confirm TLS is enforced and that certificate/host validation cannot be bypassed (including pinning behaviour)." },
        { id: "TCW-NET-04", l: "intermediate", t: "Test server-side controls via the client",
          d: "Apply web/API testing (authz, injection, IDOR, business logic) to the backend endpoints the client uses." },
        { id: "TCW-NET-05", l: "advanced", t: "Test two-tier direct database access",
          d: "Where the client connects directly to a database, assess the credentials used, their privileges and whether queries can be manipulated." }
      ]
    },
    {
      id: "dynamic",
      title: "Runtime & Dynamic Analysis",
      wstg: "—",
      items: [
        { id: "TCW-DYN-01", l: "intermediate", t: "Test client-side control enforcement",
          d: "Determine whether validation, limits and access decisions made in the UI are re-enforced server-side or can be bypassed." },
        { id: "TCW-DYN-02", l: "intermediate", t: "Runtime instrumentation and hooking",
          d: "Attach to or instrument the running process to observe and modify function calls, arguments and return values during testing." },
        { id: "TCW-DYN-03", l: "intermediate", t: "Manipulate application memory",
          d: "Inspect process memory for secrets and assess whether in-memory values that gate behaviour can be altered." },
        { id: "TCW-DYN-04", l: "advanced", t: "Bypass anti-debugging / integrity checks",
          d: "Assess the strength of anti-debug, anti-tamper and root/VM-detection controls and whether they meaningfully impede testing." }
      ]
    },
    {
      id: "ipc",
      title: "IPC, DLLs & Local Attack Surface",
      wstg: "—",
      items: [
        { id: "TCW-IPC-01", l: "intermediate", t: "Test DLL search-order / hijacking exposure",
          d: "Identify libraries loaded from writable or relative paths that a local user could plant to influence execution." },
        { id: "TCW-IPC-02", l: "intermediate", t: "Review IPC mechanisms",
          d: "Assess named pipes, COM/DCOM, shared memory, sockets and window messages for missing authentication or input validation." },
        { id: "TCW-IPC-03", l: "intermediate", t: "Review installed services and scheduled tasks",
          d: "Check services, drivers and scheduled tasks created by the app for weak permissions or unquoted/writable paths." },
        { id: "TCW-IPC-04", l: "advanced", t: "Assess local privilege escalation paths",
          d: "Combine writable install paths, weak service ACLs and auto-elevation behaviour to assess local escalation risk." }
      ]
    },
    {
      id: "authz",
      title: "Authentication, Authorization & Logic",
      wstg: "—",
      items: [
        { id: "TCW-AUTH-01", l: "basic", t: "Test authentication handling",
          d: "Review how the client authenticates users and stores/handles the resulting session or token." },
        { id: "TCW-AUTH-02", l: "intermediate", t: "Test authorization and privileged features",
          d: "Attempt to unlock or invoke privileged features that the UI hides, confirming enforcement is server-side where relevant." },
        { id: "TCW-AUTH-03", l: "intermediate", t: "Test licensing / feature-flag controls",
          d: "Assess whether licensing or feature gates enforced only in the client can be bypassed, and whether that has security impact." },
        { id: "TCW-AUTH-04", l: "advanced", t: "Test business logic across the trust boundary",
          d: "Identify decisions the client is trusted to make that should be validated by the backend, and test for abuse." }
      ]
    },
    {
      id: "reporting",
      title: "Reporting & Wrap-up",
      wstg: "—",
      items: [
        { id: "TCW-REP-01", l: "basic", t: "Record evidence and reproduction steps",
          d: "Capture requests, configs, screenshots and clear, minimal reproduction steps for each finding." },
        { id: "TCW-REP-02", l: "basic", t: "Rate severity and business impact",
          d: "Assign severity and contextualise impact for the application, its data and its deployment environment." },
        { id: "TCW-REP-03", l: "basic", t: "Provide remediation guidance",
          d: "Give actionable, prioritised remediation for each finding." },
        { id: "TCW-REP-04", l: "basic", t: "Clean up test artifacts",
          d: "Restore modified files, registry keys and configs, and remove test data and accounts created during testing." }
      ]
    }
  ]
};
