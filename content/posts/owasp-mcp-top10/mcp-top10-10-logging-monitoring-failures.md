---
title: "MCP Top 10 — #10: Logging, Monitoring & Audit Failures"
date: 2026-04-12
draft: true
tags: [ai, mcp-security, owasp]
series: ["OWASP MCP Top 10"]
weight: 10
---

# MCP Top 10 — #10: Logging, Monitoring & Audit Failures

**When Nobody's Watching**

---

## What It Is

Logging, Monitoring & Audit Failures refers to the absence or inadequacy of observability mechanisms in MCP deployments. When MCP tool calls aren't logged, when suspicious patterns aren't detected, and when there's no audit trail of what an AI agent did, organizations lose the ability to detect attacks, investigate incidents, and maintain accountability.

This is the enabler vulnerability. Every other risk in this top 10 is more dangerous when you can't see it happening.

## Why It Matters

AI agents with MCP tools can perform hundreds of actions per session — reading files, querying databases, sending messages, modifying code, calling APIs. Without comprehensive logging and monitoring:

- **Attacks are invisible.** Tool poisoning, data exfiltration, and credential theft happen silently. The user sees helpful responses while the agent leaks data.
- **Incident response is impossible.** When a breach is discovered, there's no way to determine what data was accessed, what actions were taken, or how long the compromise lasted.
- **Accountability is lost.** With multiple AI agents and multiple MCP servers, there's no clear record of who did what, when, and why.
- **Compliance is unachievable.** Regulations like GDPR, HIPAA, SOX, and PCI-DSS require audit trails for data access. MCP tools that access regulated data without logging create compliance gaps.

The challenge is unique to AI agent systems: the "user" taking actions is an LLM, not a human. Traditional audit logs that record "user X accessed file Y" don't capture the full context of "LLM accessed file Y because of tool call Z, which was triggered by user prompt W, which was influenced by injected content in tool result V."

### Threat Scenario

A malicious MCP server has been silently exfiltrating source code for three months (see #7). One day, the company's proprietary algorithm appears in a competitor's product. The security team investigates:

- **No MCP tool call logs exist.** They can't determine which files the agent accessed.
- **No parameter logs exist.** They can't see what data was sent to the malicious server.
- **No network logs specific to MCP.** General network logs show connections to the server's domain but not the content.
- **No conversation context was preserved.** They can't reconstruct the prompts or injections that drove the exfiltration.
- **No baseline exists.** They can't compare current behavior to historical norms because they never established monitoring.

The investigation concludes: "We know data was stolen. We don't know exactly what, when, or how." This is the worst possible outcome for incident response.

## How It Works

### What's Missing Today

**1. No Standardized Logging in the MCP Protocol**

The MCP specification does not define logging requirements. There is no standard format for tool call logs, no required fields, no audit event taxonomy. Each implementation logs differently — or not at all.

**2. Client-Side Logging Gaps**

Most MCP clients log tool calls at a basic level (tool name, timestamp), but miss critical context:

```
# What typical MCP clients log:
[2025-01-15 10:23:45] Tool call: read_file
[2025-01-15 10:23:46] Tool call: search_database

# What's missing:
- Full tool call parameters (what file? what query?)
- Tool results (what data was returned?)
- The prompt/context that triggered the call
- Which MCP server handled the call
- Whether the call was user-initiated or injection-driven
- Data flow between tool calls
```

**3. Server-Side Logging Gaps**

MCP server developers rarely implement comprehensive logging:

```python
@server.tool()
async def query_database(sql: str):
    # No logging of what was queried
    # No logging of who requested it
    # No logging of what was returned
    # No logging of how much data was accessed
    result = cursor.execute(sql)
    return result.fetchall()
```

**4. No Cross-Layer Correlation**

Even when both client and server log independently, there's no correlation mechanism:

```
Client log:  [10:23:45] Called tool "query_database" on server "db-server"
Server log:  [10:23:45] Received query: SELECT * FROM users
Network log: [10:23:45] Connection from 10.0.1.5 to 10.0.2.3:8080

# These three events are related but there's no correlation ID
# linking them. An investigator must manually piece them together.
```

**5. Missing Behavioral Baselines**

Without historical data on normal tool usage patterns, there's no way to detect anomalies:

```
# Is this normal?
- read_file called 847 times in one session
- database queried for all user records at 3 AM
- send_email called 15 times with large attachments

# Without baselines, you can't tell. It might be normal.
# It might be exfiltration. You have no way to know.
```

### The Accountability Gap

Traditional systems have a clear accountability chain: User → Action → System → Log. With MCP-connected AI agents, the chain is more complex:

```
User Prompt → LLM Reasoning → Tool Call → MCP Server → System Action
     ↑              ↑              ↑            ↑             ↑
  May be            Opaque         May be       May not       May not
  ambiguous         process        influenced   log the       be
                                   by injection  call         recorded
```

At each step, context is lost. By the time you're looking at a system action (file read, database query, network connection), you've lost the chain of reasoning that led to it.

## Detection

You can't detect what you don't monitor. The first step is recognizing the gaps.

### Audit Your Current Logging

1. **Can you answer these questions for any MCP tool call?**
   - What tool was called?
   - What parameters were passed?
   - What data was returned?
   - Which MCP server handled it?
   - What user prompt triggered it?
   - What was the full context (preceding tool calls, conversation history)?

2. **Can you detect these scenarios?**
   - An MCP server changing its tool descriptions between sessions
   - A tool being called with parameters that don't match its stated purpose
   - Data from one tool appearing in another tool's parameters
   - A sudden increase in tool call frequency
   - Tool calls to sensitive resources during off-hours

3. **Can you investigate?**
   - Can you reconstruct the full sequence of events for a specific session?
   - Can you correlate client logs, server logs, and network logs?
   - Can you search logs for specific data patterns (e.g., "was this file ever accessed?")?

If you answered "no" to most of these, you have a logging and monitoring failure.

## Mitigation

### Comprehensive Logging Architecture

Implement logging at every layer of the MCP stack:

**Client-Side Logging:**
```json
{
  "timestamp": "2025-01-15T10:23:45.123Z",
  "event_type": "tool_call",
  "correlation_id": "abc-123-def",
  "session_id": "session-456",
  "user_id": "user@company.com",
  "tool_name": "query_database",
  "server_name": "db-server",
  "server_version": "1.2.3",
  "parameters": {
    "sql": "SELECT name, email FROM users WHERE department = 'engineering'"
  },
  "parameter_sensitivity": "contains_pii_query",
  "trigger_context": "user_requested",
  "preceding_tool_calls": ["read_file:config.yaml"],
  "result_size_bytes": 4523,
  "result_record_count": 47,
  "duration_ms": 234,
  "status": "success"
}
```

**Server-Side Logging:**
```json
{
  "timestamp": "2025-01-15T10:23:45.234Z",
  "event_type": "tool_execution",
  "correlation_id": "abc-123-def",
  "server_name": "db-server",
  "tool_name": "query_database",
  "client_id": "client-789",
  "parameters_hash": "sha256:abc123...",
  "resources_accessed": ["database:production:users"],
  "data_classification": "pii",
  "rows_returned": 47,
  "execution_time_ms": 189,
  "status": "success"
}
```

### Monitoring and Alerting

**Anomaly Detection Rules:**

```yaml
rules:
  - name: "Unusual tool call frequency"
    condition: "tool_calls_per_hour > 3x baseline for this user/tool"
    severity: "medium"
    
  - name: "Sensitive file access"
    condition: "read_file called on paths matching /.*credentials.*|.*\.env|.*\.ssh.*/"
    severity: "high"
    
  - name: "Cross-tool data flow"
    condition: "data from read_* tool appears in send_* tool parameters"
    severity: "high"
    
  - name: "Tool description change"
    condition: "tool description hash differs from known-good value"
    severity: "critical"
    
  - name: "Off-hours sensitive operations"
    condition: "sensitive tool called outside business hours"
    severity: "medium"
    
  - name: "Large data extraction"
    condition: "cumulative data returned by tool > threshold in time window"
    severity: "high"
```

### Audit Trail Requirements

1. **Immutable logs.** MCP logs should be written to append-only storage that can't be modified or deleted by the MCP server or client processes.
2. **Retention policies.** Define how long MCP logs are retained based on compliance requirements and incident investigation needs.
3. **Log integrity verification.** Use cryptographic chaining or a similar mechanism to detect log tampering.
4. **Regular log review.** Don't just collect logs — review them. Automated analysis should catch common patterns, but periodic human review catches novel threats.

### For MCP Server Developers

1. **Log every tool invocation** with timestamp, parameters (or parameter hashes for sensitive data), result metadata, and execution context.
2. **Implement structured logging** in a standard format (JSON) that can be consumed by SIEM systems.
3. **Include correlation IDs** in all log entries so events can be traced across the client-server boundary.
4. **Log tool description serving** so changes to descriptions are auditable.
5. **Don't log sensitive data in plaintext.** Hash or redact credentials, PII, and other sensitive content in logs.

### For MCP Client Developers

1. **Log full tool call context** including the triggering prompt, preceding tool calls, and tool results.
2. **Generate and propagate correlation IDs** for every tool call chain.
3. **Implement log forwarding** to centralized logging systems (SIEM, ELK, Splunk, etc.).
4. **Provide log export capabilities** for incident investigation.
5. **Expose monitoring hooks** so organizations can plug in their own monitoring solutions.

### For Organizations

1. **Define MCP logging standards.** Specify what must be logged, in what format, and how it's stored.
2. **Integrate MCP logs with existing SIEM.** Don't create a separate logging silo.
3. **Establish baselines.** Collect normal usage data before you need to detect anomalies.
4. **Conduct regular log reviews** and incident response exercises that include MCP-related scenarios.
5. **Include MCP in your compliance program.** If AI agents access regulated data, the tool calls that access that data need to be in your audit trail.

## Key Takeaways

- The MCP protocol has no standardized logging requirements, and most implementations have significant observability gaps.
- Without comprehensive logging, attacks are invisible, incident response is impossible, and compliance is unachievable.
- Logging must span the full stack: client-side (tool calls, context, triggers), server-side (execution, resources, data flow), and network-level (connections, traffic patterns).
- Monitoring requires behavioral baselines to distinguish normal usage from attacks. Establish baselines before you need them.
- The AI agent accountability chain is more complex than traditional systems. Logs must capture not just what happened, but why — including the prompts, context, and preceding events that led to each action.
- This is the enabler vulnerability. Fix this one, and every other risk in this list becomes more manageable.

---

*This concludes the OWASP Top 10 for MCP series. For the full series index, see [Series Introduction](00-series-introduction.md).*

## Series Conclusion

The MCP protocol is transformative technology. It gives AI agents the ability to interact with the world — and that's exactly what makes it dangerous when deployed without security considerations.

The ten risks covered in this series are not theoretical. They are being exploited in the wild today, often by researchers and red teamers, but increasingly by real adversaries who recognize that AI agent infrastructure is a soft target.

The good news: every risk in this list is mitigable. Not perfectly, not completely, but significantly. The organizations that will weather the coming storm of agentic AI exploitation are the ones that start building defenses now — before the incidents force them to.

Build secure. Deploy carefully. Monitor everything.
