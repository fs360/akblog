---
title: "The OWASP Top 10 for MCP"
date: 2026-04-12
draft: false
tags: [ai, mcp]
series: ["OWASP MCP Top 10"]
weight: 0
---

# The OWASP Top 10 for MCP: A Security Engineer's Guide to Agentic AI Risk

**Series Introduction**

---

## Why This Series Exists

The Model Context Protocol (MCP) is rapidly becoming the de facto standard for connecting AI agents to external tools, data sources, and services. Introduced by Anthropic in late 2024 and now adopted across the industry, MCP gives LLMs the ability to *do things* — read files, query databases, call APIs, execute code, send emails, and much more.

This is a massive expansion of the attack surface.

As a security engineer, I've spent the better part of the last year studying how MCP deployments fail. The patterns are consistent, predictable, and — critically — preventable. But only if developers and organizations understand the risks *before* they ship.

That's the purpose of this series: to apply the same structured, risk-ranked thinking that OWASP brought to web application security and map it onto the MCP ecosystem. Each post covers one of the top 10 risks I've identified through research, real-world incident analysis, and threat modeling of production MCP deployments.

## The OWASP Top 10 for MCP

| # | Risk | Severity |
|---|------|----------|
| 1 | [Tool Poisoning](01-tool-poisoning.md) | Critical |
| 2 | [Rug Pulls & Server Integrity](02-rug-pulls.md) | Critical |
| 3 | [Prompt Injection via Tool Results](03-prompt-injection-via-tools.md) | Critical |
| 4 | [Cross-Server Attacks & Tool Shadowing](04-cross-server-attacks.md) | High |
| 5 | [Excessive Permissions & Capability Grants](05-excessive-permissions.md) | High |
| 6 | [Credential Theft & Token Leakage](06-credential-theft.md) | High |
| 7 | [Data Exfiltration via Tool Channels](07-data-exfiltration.md) | High |
| 8 | [Command & Code Injection](08-command-injection.md) | High |
| 9 | [Insecure Transport & Authentication](09-insecure-transport.md) | Medium |
| 10 | [Logging, Monitoring & Audit Failures](10-logging-monitoring-failures.md) | Medium |

## Who This Series Is For

- **Security engineers** evaluating MCP deployments for their organization
- **Developers** building MCP servers or integrating MCP clients into applications
- **Red teamers** looking for structured methodology to test agentic AI systems
- **CISOs and security leaders** who need to understand the risk landscape of AI tooling
- **AI/ML engineers** who want to build secure-by-default agent architectures

## A Note on Scope

This series focuses specifically on risks introduced by the MCP layer — the protocol, the servers, the client-server trust model, and the interaction patterns between LLMs and tools. We are *not* covering general LLM vulnerabilities (like training data poisoning or model extraction) except where they directly intersect with MCP-specific attack vectors.

Each post follows the same structure:

1. **What it is** — a clear description of the vulnerability class
2. **Why it matters** — real-world impact and threat scenarios
3. **How it works** — technical deep-dive with examples
4. **Detection** — how to identify the vulnerability in your environment
5. **Mitigation** — concrete, actionable defenses
6. **Key takeaways** — a summary for quick reference

Let's get started.

---

*Next: [#1 — Tool Poisoning: When the Tool Description Is the Attack](owasp-mcp-top10/mcp-top10-01-tool-poisoning.md)*
