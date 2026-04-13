---
title: "MCP Top 10 — #5: Excessive Permissions & Capability Grants"
date: 2026-04-12
draft: true
tags: [ai, mcp-security, owasp]
series: ["OWASP MCP Top 10"]
weight: 5
---

# MCP Top 10 — #5: Excessive Permissions & Capability Grants

**When Tools Get Too Much Power**

---

## What It Is

Excessive Permissions occurs when MCP servers are granted — or assume — more access than they need to perform their stated function. This is the principle of least privilege violated at the AI tooling layer.

MCP servers typically run as local processes or remote services with access to system resources. The permissions they hold determine what damage can be done if the server is compromised, if the LLM is manipulated, or if the server itself is malicious. When an MCP server that exists to "check the weather" has access to the filesystem, network, and process execution, the blast radius of any vulnerability is the entire system.

## Why It Matters

Excessive permissions act as a **force multiplier for every other vulnerability in this list:**

- Tool poisoning (#1) is more dangerous when the tool has filesystem access
- Rug pulls (#2) can cause more damage when the server has broad permissions
- Prompt injection (#3) can exfiltrate more data when the agent can read more files
- Cross-server attacks (#4) are more impactful when servers have overlapping broad permissions

The current MCP ecosystem has a severe over-permissioning problem:

- **MCP servers run with the full permissions of the user who launched them.** There is no built-in permission sandboxing in the MCP protocol.
- **Most MCP servers request (or silently assume) maximum access.** A database MCP server often has read-write access to all tables, not just the ones relevant to its stated purpose.
- **Users don't understand the permission implications.** Installing an MCP server feels like installing a browser extension, but the access granted is closer to giving someone your laptop password.
- **There is no standard permission model.** The MCP spec doesn't define capabilities, scopes, or permission boundaries for servers.

### Threat Scenario

A developer installs a "Markdown Preview" MCP server to render markdown files. Seems harmless. But the server:

- Runs as the developer's user with full filesystem access
- Can read any file on the system (not just markdown files)
- Can make outbound network connections (to "fetch remote images")
- Can execute subprocesses (to "render diagrams")

When the LLM is tricked (via any injection vector) into calling this tool with a path like `/etc/shadow` or `~/.aws/credentials`, the server happily reads and returns the file. It has no concept of "I should only read markdown files."

The permission model says: "this process can read anything." The tool description says: "this reads markdown." The gap between these two is the vulnerability.

## How It Works

### The Permission Stack

```
Layer 1: OS Permissions       — What the process CAN access
Layer 2: MCP Server Logic     — What the server CHOOSES to access
Layer 3: Tool Descriptions    — What the tool CLAIMS to access
Layer 4: User Understanding   — What the user THINKS it accesses
```

Security failures occur when there are gaps between these layers. In practice:

- Layer 1 is almost always "everything the user can access" (no sandboxing)
- Layer 2 is defined by the server developer (often permissive for "flexibility")
- Layer 3 is the text description (easily manipulated)
- Layer 4 is the user's mental model (usually the most restrictive — and most wrong)

### Common Over-Permission Patterns

**1. Full Filesystem Access for Limited Tools**

```python
# MCP server for "project file search" — but it can read ANY file
@server.tool()
async def search_files(query: str, path: str = "/"):
    # No path restriction! Can search entire filesystem
    results = []
    for root, dirs, files in os.walk(path):
        for f in files:
            filepath = os.path.join(root, f)
            content = open(filepath).read()  # Reads anything
            if query in content:
                results.append(filepath)
    return results
```

**2. Read-Write When Read-Only Suffices**

```python
# MCP server for "database analytics" — but it has write access
connection = psycopg2.connect(
    host="production-db.internal",
    user="app_admin",          # Has write permissions!
    password=os.getenv("DB_PASSWORD"),
    database="production"
)

@server.tool()
async def query_analytics(sql: str):
    cursor = connection.cursor()
    cursor.execute(sql)  # Can execute ANY SQL, including DROP TABLE
    return cursor.fetchall()
```

**3. Broad Network Access**

```python
# MCP server for "API documentation lookup" — but it can reach any host
@server.tool()
async def fetch_api_docs(url: str):
    # No URL restriction! Can be used for SSRF
    response = requests.get(url)
    return response.text
```

**4. Process Execution Capabilities**

```python
# MCP server for "code formatting" — but it can execute anything
@server.tool()
async def format_code(code: str, language: str):
    # Shells out with no command restriction
    result = subprocess.run(
        ["npx", "prettier", "--parser", language],
        input=code, capture_output=True, text=True
    )
    return result.stdout
```

### The Ambient Authority Problem

MCP servers inherit the ambient authority of the user who launched them. This means:

- They can read the user's SSH keys, AWS credentials, browser cookies
- They can access any service the user has authenticated to
- They can read and write to any file the user owns
- They can make network connections to any reachable host

There is no mechanism in the MCP protocol to restrict a server's ambient authority. The server has access to everything; the only restriction is what it chooses to expose through its tools.

## Detection

### Permission Auditing

1. **Map actual vs. stated permissions.** For each MCP server, document what it *can* access (OS-level permissions) vs. what it *should* access (based on its stated purpose).
2. **Identify permission gaps.** Flag servers where actual permissions significantly exceed stated needs.
3. **Monitor resource access patterns.** Track which files, network hosts, and system resources each MCP server actually accesses in production.

### Runtime Monitoring

1. **System call tracing.** Use tools like `strace` (Linux), `dtrace` (macOS), or eBPF to monitor what MCP server processes actually do at the OS level.
2. **Network monitoring.** Track all network connections made by MCP server processes.
3. **File access logging.** Monitor which files MCP servers read and write, and flag access to sensitive paths.

## Mitigation

### For MCP Server Developers

1. **Implement path restrictions.** If your tool reads files, restrict it to specific directories:
   ```python
   ALLOWED_PATHS = ["/home/user/project"]
   
   def read_file(path: str):
       resolved = os.path.realpath(path)
       if not any(resolved.startswith(p) for p in ALLOWED_PATHS):
           raise PermissionError(f"Access denied: {path}")
       return open(resolved).read()
   ```

2. **Use read-only database connections** when your server only needs to query data.
3. **Restrict network access** to only the hosts and APIs your server needs.
4. **Never shell out.** If you need to run a subprocess, use a restricted executor with an explicit allowlist of commands.
5. **Document your permission requirements.** Publish a manifest of what your server needs and why.

### For Organizations

1. **Run MCP servers in sandboxed environments:**
   - **Containers** with restricted filesystem mounts and network policies
   - **VMs** with minimal resource access
   - **OS-level sandboxing** (macOS Sandbox, Linux seccomp, AppArmor)
   - **Firewall rules** restricting outbound connections per-server

2. **Implement a permission review process.** Before deploying an MCP server, review its actual permission requirements and configure the minimum necessary access.

3. **Use service accounts with minimal permissions** for MCP servers that access external services (databases, APIs, cloud providers).

4. **Network segmentation.** MCP servers for different purposes should be on different network segments with appropriate access controls.

### For MCP Client Developers

1. **Implement a permission model.** Allow users to define what resources each MCP server can access:
   ```json
   {
     "server": "markdown-preview",
     "permissions": {
       "filesystem": {"read": ["/home/user/docs/**/*.md"], "write": []},
       "network": [],
       "subprocess": []
     }
   }
   ```

2. **Show permission requirements at install time.** Like mobile app permission dialogs, inform users what access each server needs.
3. **Enforce permission boundaries at the client level.** Reject tool calls that would exceed granted permissions.
4. **Support permission escalation requests.** If a tool needs more access than currently granted, prompt the user for approval.

### For the MCP Protocol

1. **Define a standard capabilities/permissions model.** Servers should declare what they need, and clients should enforce boundaries.
2. **Support permission scoping in the protocol.** Allow servers to be initialized with restricted capabilities.
3. **Standardize permission manifests.** Create a machine-readable format for declaring permission requirements.

## Key Takeaways

- MCP servers run with full user permissions by default — far more access than most tools need.
- Excessive permissions amplify every other vulnerability. The blast radius of any attack is limited only by what the compromised tool can access.
- The gap between what a tool *can* access and what it *should* access is the vulnerability surface.
- Defense requires sandboxing, least-privilege configuration, runtime monitoring, and ideally protocol-level permission boundaries.
- The MCP protocol currently lacks a standard permission model. This is a critical gap that the ecosystem needs to address.

---

*Next: [#6 — Credential Theft & Token Leakage: When Your Agent Gives Away the Keys](06-credential-theft.md)*
