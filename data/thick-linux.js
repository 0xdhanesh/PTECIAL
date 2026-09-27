/*
 * Thick Client (Linux) Pentest Checklist
 * Levels: basic | intermediate | advanced
 * Item IDs are stable identifiers used for saved progress and markdown import.
 * Reference / checklist altitude. Aligned to OWASP thick-client guidance and common Linux desktop app testing practice.
 */
window.CHECKLISTS = window.CHECKLISTS || {};
window.CHECKLISTS["thick-linux"] = {
  id: "thick-linux",
  title: "Thick Client — Linux",
  ref: "OWASP thick-client testing / Linux desktop apps",
  description: "Linux desktop (thick client) testing checklist, basics to advanced.",
  sections: [
    {
      id: "recon",
      title: "Information Gathering & App Profiling",
      wstg: "—",
      items: [
        { id: "TCL-RECON-01", l: "basic", t: "Confirm scope and authorization",
          d: "Confirm the application, versions, test hosts, accounts and backend endpoints in scope, and hold written authorization." },
        { id: "TCL-RECON-02", l: "basic", t: "Identify architecture (two-tier vs three-tier)",
          d: "Determine whether the client talks directly to a database or via application/API servers. This shapes the whole test plan." },
        { id: "TCL-RECON-03", l: "basic", t: "Enumerate installed files and packaging",
          d: "Map the install layout and packaging (native binary, package manager, AppImage, Snap, Flatpak, Electron) and note file ownership and permissions." },
        { id: "TCL-RECON-04", l: "basic", t: "Identify frameworks and languages",
          d: "Determine the platform (C/C++, Java, Electron, Python, Go, etc.) to drive the analysis and instrumentation approach." },
        { id: "TCL-RECON-05", l: "intermediate", t: "Enumerate shared libraries and dependencies",
          d: "List linked libraries and their versions for known-vulnerability lookup and to spot unsafe load paths (RPATH/RUNPATH, LD_LIBRARY_PATH)." },
        { id: "TCL-RECON-06", l: "intermediate", t: "Identify backend endpoints and protocols",
          d: "Discover the servers, ports and protocols (HTTP(S), TCP, D-Bus, sockets, database) the client communicates with." }
      ]
    },
    {
      id: "static",
      title: "Binary & Static Analysis",
      wstg: "—",
      items: [
        { id: "TCL-STAT-01", l: "basic", t: "Inspect binary metadata and strings",
          d: "Review ELF metadata, embedded strings and resources for endpoints, credentials, comments and version data." },
        { id: "TCL-STAT-02", l: "intermediate", t: "Decompile / disassemble the application",
          d: "Recover logic from bytecode or native ELF binaries to review sensitive routines, validation and secrets handling." },
        { id: "TCL-STAT-03", l: "intermediate", t: "Search for hardcoded secrets",
          d: "Look for embedded credentials, API keys, connection strings, tokens and encryption keys in binaries, scripts and config." },
        { id: "TCL-STAT-04", l: "intermediate", t: "Review binary hardening flags",
          d: "Check ELF protections (RELRO, stack canaries, NX, PIE, fortify) and assess whether mitigations are enabled and effective." },
        { id: "TCL-STAT-05", l: "advanced", t: "Review update mechanism integrity",
          d: "Assess how updates are fetched and verified (signature, transport, package trust) and whether a malicious update is feasible." }
      ]
    },
    {
      id: "storage",
      title: "Local Storage & Configuration",
      wstg: "—",
      items: [
        { id: "TCL-STOR-01", l: "basic", t: "Review config files for sensitive data",
          d: "Inspect config under the install dir, /etc and the user's home (dotfiles, XDG dirs) for secrets and check file permissions." },
        { id: "TCL-STOR-02", l: "basic", t: "Assess file and directory permissions",
          d: "Check ownership and mode of app files, config and data for world-readable/writable secrets or writable executable paths." },
        { id: "TCL-STOR-03", l: "intermediate", t: "Assess sensitive data at rest",
          d: "Check local databases, caches, temp files and user data for unencrypted sensitive information." },
        { id: "TCL-STOR-04", l: "intermediate", t: "Review keyring / secret storage usage",
          d: "Assess whether secrets use the platform keyring appropriately and cannot be trivially recovered by another local user or process." },
        { id: "TCL-STOR-05", l: "intermediate", t: "Review logging for sensitive data",
          d: "Check application logs, syslog/journal output and debug files for credentials, tokens or PII in clear text." },
        { id: "TCL-STOR-06", l: "advanced", t: "Assess custom encryption of stored data",
          d: "Where the app encrypts stored data itself, review algorithm choice, key management and whether keys are recoverable locally." }
      ]
    },
    {
      id: "network",
      title: "Network & Backend Communication",
      wstg: "—",
      items: [
        { id: "TCL-NET-01", l: "basic", t: "Intercept HTTP(S) traffic",
          d: "Proxy application HTTP(S) traffic to review requests, responses, endpoints and parameters." },
        { id: "TCL-NET-02", l: "intermediate", t: "Capture non-HTTP / raw socket traffic",
          d: "Where the client uses raw TCP, UNIX sockets or custom protocols, capture and analyse traffic to understand the message format." },
        { id: "TCL-NET-03", l: "intermediate", t: "Test transport security and cert validation",
          d: "Confirm TLS is enforced and that certificate/host validation cannot be bypassed (including pinning behaviour)." },
        { id: "TCL-NET-04", l: "intermediate", t: "Test server-side controls via the client",
          d: "Apply web/API testing (authz, injection, IDOR, business logic) to the backend endpoints the client uses." },
        { id: "TCL-NET-05", l: "advanced", t: "Test two-tier direct database access",
          d: "Where the client connects directly to a database, assess the credentials used, their privileges and whether queries can be manipulated." }
      ]
    },
    {
      id: "dynamic",
      title: "Runtime & Dynamic Analysis",
      wstg: "—",
      items: [
        { id: "TCL-DYN-01", l: "intermediate", t: "Test client-side control enforcement",
          d: "Determine whether validation, limits and access decisions made in the UI are re-enforced server-side or can be bypassed." },
        { id: "TCL-DYN-02", l: "intermediate", t: "Runtime instrumentation and hooking",
          d: "Attach to or instrument the running process to observe and modify function calls, arguments and return values during testing." },
        { id: "TCL-DYN-03", l: "intermediate", t: "Manipulate application memory",
          d: "Inspect process memory for secrets and assess whether in-memory values that gate behaviour can be altered." },
        { id: "TCL-DYN-04", l: "advanced", t: "Assess environment and preload influence",
          d: "Assess whether environment variables or library preloading can alter behaviour or load attacker-controlled code." }
      ]
    },
    {
      id: "ipc",
      title: "IPC & Local Attack Surface",
      wstg: "—",
      items: [
        { id: "TCL-IPC-01", l: "intermediate", t: "Review library load paths",
          d: "Identify libraries loaded from writable or relative paths (RPATH/RUNPATH, working dir) that a local user could plant." },
        { id: "TCL-IPC-02", l: "intermediate", t: "Review IPC mechanisms",
          d: "Assess D-Bus interfaces, UNIX sockets, shared memory and named pipes for missing authentication or input validation." },
        { id: "TCL-IPC-03", l: "intermediate", t: "Review services, units and cron",
          d: "Check systemd units, init scripts and cron jobs created by the app for weak permissions or writable executable paths." },
        { id: "TCL-IPC-04", l: "advanced", t: "Assess SUID/privilege and escalation paths",
          d: "Assess SUID/SGID binaries, sudo rules, capabilities and writable privileged paths introduced by the app for local escalation." }
      ]
    },
    {
      id: "authz",
      title: "Authentication, Authorization & Logic",
      wstg: "—",
      items: [
        { id: "TCL-AUTH-01", l: "basic", t: "Test authentication handling",
          d: "Review how the client authenticates users and stores/handles the resulting session or token." },
        { id: "TCL-AUTH-02", l: "intermediate", t: "Test authorization and privileged features",
          d: "Attempt to unlock or invoke privileged features the UI hides, confirming enforcement is server-side where relevant." },
        { id: "TCL-AUTH-03", l: "intermediate", t: "Test licensing / feature-flag controls",
          d: "Assess whether licensing or feature gates enforced only in the client can be bypassed, and whether that has security impact." },
        { id: "TCL-AUTH-04", l: "advanced", t: "Test business logic across the trust boundary",
          d: "Identify decisions the client is trusted to make that should be validated by the backend, and test for abuse." }
      ]
    },
    {
      id: "reporting",
      title: "Reporting & Wrap-up",
      wstg: "—",
      items: [
        { id: "TCL-REP-01", l: "basic", t: "Record evidence and reproduction steps",
          d: "Capture requests, configs, screenshots and clear, minimal reproduction steps for each finding." },
        { id: "TCL-REP-02", l: "basic", t: "Rate severity and business impact",
          d: "Assign severity and contextualise impact for the application, its data and its deployment environment." },
        { id: "TCL-REP-03", l: "basic", t: "Provide remediation guidance",
          d: "Give actionable, prioritised remediation for each finding." },
        { id: "TCL-REP-04", l: "basic", t: "Clean up test artifacts",
          d: "Restore modified files and configs, and remove test data and accounts created during testing." }
      ]
    }
  ]
};
