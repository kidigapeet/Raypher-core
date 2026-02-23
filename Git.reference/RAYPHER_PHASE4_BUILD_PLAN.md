# RAYPHER PHASE 4: THE AIR TRAFFIC CONTROLLER — COMPLETE BUILD PLAN

> **Codename:** The Air Traffic Controller — Network Sovereignty & Shadow Discovery
> **Objective:** Transition Raypher from a "soft" interception model (env vars) to a "hard" kernel-level enforcement layer. Intercept every AI request at the socket level using WFP/eBPF, perform deep contextual DLP (NER), and provide 100% transparency to the user via real-time interception alerts.
> **Timeline:** 4 Weeks (Week 13–16)
> **Prerequisite:** Phase 3 complete (Zero-Touch env vars, Basic DLP, Policy Engine, Local CA, Dashboard v1 — all verified ✅)

---

## The Architecture Shift: Closing the Gaps

Phase 4 moves Raypher from the **Application Layer** to the **Network Layer**. This version addresses the "Real World" gaps: Platform Parity, Input Safety, and User Trust.

| Feature | **Phase 3 (Current)** | **Phase 4 (Target)** |
|---|---|---|
| **Interception** | Soft (Environment Variables) | **Hard (WFP / eBPF / Network Extensions)** |
| **Platform** | Windows-Primary | **Cross-Platform (Windows, Linux, macOS)** |
| **Input Safety** | None (Blind to Prompts) | **Prompt Injection Detection (Jailbreak Filter)** |
| **User Trust** | Background Logs | **Live Interception UI (Allow/Block Popups)** |
| **Integrity** | Simple Database Logs | **Merkle-Chained Immutable Ledger** |

---

## Technology Stack Extensions

### New Dependencies (Phase 4)

| Crate / Tool | Purpose | Why This One |
|---|---|---|
| `aya` | Linux eBPF in Pure Rust | Allows writing eBPF probes in Rust (no C needed), sharing types between kernel/user space. |
| `network-extensions` | macOS Interception | Native Swift/System framework for transparent networking on Mac. |
| `pnet` | DNS Snooping | Low-level packet parsing for detecting AI calls via DNS. |
| `bert-ner` | Local NER extraction | High-accuracy entity recognition without cloud API calls. |
| `merkle-tree` | Audit ledger integrity | Ensures logs are immutable and mathematically provable. |
| `tau` / `tray-icon` | System Tray UI | Cross-platform tray icon for the "Panic Button" and real-time status. |

---

## Week 13: The Force — Transparent Socket Interception (Global)

### Philosophy

> *"Interception is not a request; it is a law of physics. If an agent tries to leave the machine, it must pass through the bouncer, regardless of the OS it lives on."*

---

### Founder (Cybersecurity) — Multi-OS Kernel Hooks

#### Tasks — Day by Day

| Day | Action | Deliverable |
|---|---|---|
| **Day 1–2** | **Windows Filtering Platform (WFP):** Register `FWPM_LAYER_ALE_AUTH_CONNECT_V4` filter. Redirect 443 ➔ 8888. | Windows "Hard" Interception |
| **Day 3–4** | **Linux eBPF (Aya):** Attach to `sock_ops`. Rewrite destination IP for AI-bound traffic at the socket level. | Linux "Hard" Interception |
| **Day 5** | **Loopback Resolver:** Dynamically generate SNI-matched certificates for transparent HTTPS. | 100% Transparent MITM |
| **Day 6** | **macOS Research:** Prototype Network Extension (NEFilterControlProvider) to mirror the WFP logic on Mac. | Cross-platform parity proof |

---

## Week 14: The Sonar — Shadow AI Discovery

### Philosophy

> *"You cannot secure what you cannot see. We find the ghost agents before they find your data."*

---

### Co-Founder (Data/Ops) — Active & Passive Discovery

#### Tasks — Day by Day

| Day | Action | Deliverable |
|---|---|---|
| **Day 1** | **Active Port Scan:** Fingerprint ports `11434`, `8000`, `6333` to find unmanaged LLMs/DBs. | "Ghost AI" alerts |
| **Day 2** | **mDNS Listener:** Listen for service broadcasts on the local network. | Cross-machine AI discovery |
| **Day 3** | **DNS Snooping:** Map suspicious DNS calls back to PIDs. | Link DNS to specific scripts |
| **Day 4** | **Shadow Map UI:** High-fidelity visualization of all AI assets on the local network. | CISO Asset Inventory |
| **Day 5** | **One-Click Seal:** Button to automatically wrap discovered services in Raypher protection. | Discovery ➔ Protection flow |

---

## Week 15: The Censor — Input/Output Safety

### Philosophy

> *"We don't just stop secrets from leaking out; we stop toxic triggers from coming in. We are the airlock between the world and the LLM."*

---

### Founder (Cybersecurity) — Jailbreak Filtering & NER

#### Tasks — Day by Day

| Day | Action | Deliverable |
|---|---|---|
| **Day 1** | **Contextual NER:** Detect `PERSON`, `ORG`, `PRODUCT` in egress traffic. | Intelligent PII protection |
| **Day 2** | **Jailbreak Filter:** Implement heuristics for "Ignore previous instructions", "DAN", and prompt injection patterns. | **Input Injection Shield** |
| **Day 3** | **SSRF Shield:** Block IANA private ranges and Cloud Metadata IPs. | Internal network protection |
| **Day 4** | **Custom Dictionaries:** User-defined "Top Secret" keywords and project codes. | Targeted IP protection |
| **Day 5** | **Performance Polish:** Optimization to ensure safety adds < 15ms overhead. | Real-time safety at speed |

---

## Week 16: The Hive Mind — User Trust & Immutable Evidence

### Philosophy

> *"Transparency builds trust. Every time Raypher saves you, you should know exactly why and how."*

---

### Co-Founder (Data/Ops) — UI, UX, and Ledger

#### Tasks — Day by Day

| Day | Action | Deliverable |
|---|---|---|
| **Day 1–2** | **gRPC Command Center:** Secure heartbeats and real-time policy push using Silicon Identity. | Fleet-wide orchestration |
| **Day 3** | **Merkle Ledger:** Cryptographically chain database logs to prevent admin tampering. | Legally admissible audit trial |
| **Day 4** | **Live Interception UI:** "Little Snitch" for AI. A popup allowing/blocking new agent connections. | **User Trust & Control** |
| **Day 5** | **The Panic Tray:** System tray icon that turns RED during attacks + "Kill All" global shortcut. | **Immediate Visual Feedback** |

---

## The "Real World" Check: Crate Requirements for Linux eBPF

To match the performance of the Windows WFP plan, we will utilize the following stack for Linux:

1. **`aya`**: The core eBPF framework. We will use a `cgroup/connect4` or `sock_ops` program to perform destination NAT.
2. **`aya-log`**: For streaming kernel-level logs into the Raypher service.
3. **`tokio`**: To manage the user-space eBPF loader and event loop.

---

## Phase 4 Final Checklist

- [ ] **Cross-Platform Hard Interception:** WFP (Win) and eBPF (Linux) redirection functional.
- [ ] **Jailbreak Filter:** Successful interception of prompt injection attacks in upstream traffic.
- [ ] **Live Transparency:** User popups and tray alerts working for new agent connections.
- [ ] **Shadow Sonar:** Inventory of Ollama/Chroma instances across the network partition.
- [ ] **Merkle Proofs:** Verification tool for database integrity in the dashboard.
- [ ] **SSRF Shield:** Metadata and internal network endpoints blocked for all agents.

---

## Final Verdict

By the end of Phase 4, Raypher is not just an engine; it is a **Complete Platform**. It supports the platforms devs use (Linux/Mac), stops the attacks users fear (Jailbreaks), and provides the transparency the community demands (Live UI).
