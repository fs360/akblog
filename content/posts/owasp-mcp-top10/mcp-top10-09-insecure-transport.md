---
title: "MCP Top 10 — #9: Insecure Transport & Authentication"
date: 2026-04-12
draft: true
tags: [ai, mcp-security, owasp]
series: ["OWASP MCP Top 10"]
weight: 9
---

# MCP Top 10 — #9: Insecure Transport & Authentication

**When the Wire Is the Weakness**

---

## What It Is

Insecure Transport & Authentication covers vulnerabilities in how MCP clients and servers establish connections, verify identities, and protect data in transit. This includes:

- **Unencrypted communication** between MCP clients and servers
- **Missing or weak authentication** allowing unauthorized access to MCP servers
- **Lack of server identity verification** enabling man-in-the-middle attacks
- **Token and credential management failures** in MCP authentication flows
- **Insecure default configurations** that ship without encryption or authentication enabled

## Why It Matters

MCP defines two transport mechanisms: **stdio** (for local servers) and **HTTP with Server-Sent Events (SSE)** (for remote servers). Each has distinct security implications:

**Stdio transport** runs MCP servers as local child processes. Communication happens over stdin/stdout pipes. This is inherently local, so network-level attacks don't apply — but there's no authentication at all. Any process that can write to the server's stdin can send commands.

**HTTP/SSE transport** runs MCP servers as network services. This introduces the full spectrum of web security concerns: encryption, authentication, session management, and network-level attacks.

As MCP adoption grows, organizations are increasingly deploying remote MCP servers as shared services — a single database MCP server for the engineering team, a Jira integration server for the whole company. These shared deployments dramatically increase the impact of transport and authentication failures.

### Threat Scenario

A company deploys an internal MCP server for database access, running as an HTTP service on the corporate network:

```
http://mcp-db.internal:8080/mcp
```

No TLS. No authentication. The thinking: "It's on the internal network, it's fine."

An attacker who gains any foothold on the internal network (phishing, compromised laptop, vulnerable internal service) can:

1. **Eavesdrop** on all MCP traffic, capturing database queries and results — including customer data, financial records, and credentials
2. **Impersonate** the MCP server, returning poisoned tool descriptions and injected results
3. **Send unauthorized commands** to the MCP server, querying or modifying any data the server has access to
4. **Man-in-the-middle** the connection, modifying queries and results in transit

## How It Works

### Unencrypted HTTP Transport

The most basic failure. MCP traffic sent over plain HTTP is visible to any network observer:

```
Client → HTTP → MCP Server
         ↑
    Network observer can see:
    - Tool descriptions
    - Tool call parameters (may contain sensitive data)
    - Tool results (may contain sensitive data)
    - Authentication tokens (if any)
```

**Impact:** Complete loss of confidentiality and integrity for all MCP communication.

### Missing Authentication

MCP servers that accept connections without verifying the caller's identity:

```python
# Server with no authentication — anyone can connect
app = FastAPI()

@app.post("/mcp")
async def handle_mcp(request: Request):
    # No auth check!
    body = await request.json()
    return process_mcp_request(body)
```

**Impact:** Any client on the network can send commands to the server, query data, and execute tools.

### Weak Authentication Patterns

**Static API Keys:**
```python
# Shared API key — same key for all users
API_KEY = "mcp-server-key-12345"

@app.post("/mcp")
async def handle_mcp(request: Request):
    if request.headers.get("Authorization") != f"Bearer {API_KEY}":
        return Response(status_code=401)
    # Key is shared, hardcoded, never rotated, and identical for all users
    return process_mcp_request(await request.json())
```

**No Token Expiration:**
```python
# OAuth token that never expires
token = get_oauth_token(client_id, client_secret)
# Token is used forever — if leaked, access is permanent
```

**Credentials in URLs:**
```
http://mcp-server.internal:8080/mcp?token=abc123&user=admin
# Token visible in server logs, proxy logs, browser history, referrer headers
```

### Man-in-the-Middle Attacks

Without TLS and server certificate verification, an attacker can intercept and modify MCP traffic:

```
Client → → → Attacker (MITM) → → → Server
         ↑
    Attacker can:
    1. Read all tool descriptions and inject malicious ones
    2. Read all tool results and modify them (prompt injection)
    3. Capture credentials and tokens
    4. Selectively block or delay responses
    5. Inject entirely fabricated tool results
```

A MITM on an MCP connection is particularly dangerous because the attacker can inject prompt injection payloads into tool results, effectively combining transport-level attacks with application-level exploitation.

### Session Management Failures

**No Session Isolation:**
```python
# All clients share the same server state
server_state = {}  # Single global state

@app.post("/mcp")
async def handle_mcp(request: Request):
    # Any client can read/modify state set by any other client
    return process_with_shared_state(await request.json(), server_state)
```

**Session Fixation:**
```python
# Server accepts client-provided session IDs without validation
@app.post("/mcp")
async def handle_mcp(request: Request):
    session_id = request.headers.get("X-Session-ID", str(uuid4()))
    # Attacker can set a known session ID, then hijack the session
```

### Stdio Transport Risks

While stdio doesn't face network attacks, it has its own issues:

```
# MCP server started as a child process
$ mcp-server --config /path/to/config

# The server inherits the parent process's:
# - Environment variables (may contain secrets)
# - File descriptors (may include sensitive handles)
# - User permissions (full user access)
# - Working directory
```

If another process can write to the server's stdin (e.g., through a symlink attack, /proc/pid/fd access, or shared tmpfile), it can send unauthorized MCP commands.

## Detection

### Network Analysis

1. **Scan for unencrypted MCP traffic.** Monitor network traffic for MCP protocol patterns (JSON-RPC 2.0) on non-TLS connections.
2. **Certificate validation testing.** Verify that MCP clients validate server certificates and reject self-signed or expired certs.
3. **Authentication bypass testing.** Attempt to connect to MCP servers without credentials or with invalid credentials.

### Configuration Auditing

1. **Review MCP server configurations** for authentication settings, TLS configuration, and session management.
2. **Check for default credentials.** Many MCP server frameworks ship with default or example credentials.
3. **Verify token expiration policies.** Ensure OAuth tokens and API keys have appropriate expiration times.

### Runtime Monitoring

1. **Log all authentication attempts** — both successful and failed.
2. **Monitor for session anomalies** — multiple clients using the same session, sessions from unusual IP addresses.
3. **Track connection patterns** — alert on connections from unexpected sources.

## Mitigation

### For MCP Server Developers

1. **Always use TLS for HTTP transport:**
   ```python
   import ssl
   
   ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
   ssl_context.load_cert_chain('server.crt', 'server.key')
   ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
   
   uvicorn.run(app, host="0.0.0.0", port=8443, ssl=ssl_context)
   ```

2. **Implement proper authentication:**
   ```python
   from fastapi import Depends, HTTPException
   from fastapi.security import OAuth2PasswordBearer
   
   oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
   
   async def verify_token(token: str = Depends(oauth2_scheme)):
       user = await validate_and_decode_token(token)
       if not user:
           raise HTTPException(status_code=401)
       return user
   
   @app.post("/mcp")
   async def handle_mcp(request: Request, user=Depends(verify_token)):
       return process_mcp_request(await request.json(), user=user)
   ```

3. **Implement per-user session isolation.** Each authenticated user should have their own server state that is inaccessible to other users.

4. **Set secure defaults.** Ship with authentication required, TLS enabled, and restrictive CORS policies. Make insecure configurations opt-in, not opt-out.

5. **Implement rate limiting and abuse protection:**
   ```python
   from slowapi import Limiter
   limiter = Limiter(key_func=get_remote_address)
   
   @app.post("/mcp")
   @limiter.limit("100/minute")
   async def handle_mcp(request: Request):
       # ...
   ```

### For Organizations

1. **Mandate TLS for all MCP connections.** No exceptions for "internal" servers.
2. **Use mutual TLS (mTLS) for high-security deployments.** Both client and server present certificates.
3. **Integrate MCP authentication with your identity provider.** Use SSO/SAML/OIDC — don't create separate credential systems.
4. **Implement network policies** restricting which clients can reach which MCP servers.
5. **Regular security assessments** of MCP server deployments, including penetration testing of transport and authentication.
6. **Token rotation policies.** Enforce regular rotation of API keys and access tokens used for MCP authentication.

### For MCP Client Developers

1. **Verify server certificates.** Don't disable certificate validation or accept self-signed certificates by default.
2. **Implement certificate pinning** for connections to known MCP servers.
3. **Secure credential storage.** Store MCP server credentials in the OS keychain or a secrets manager, not in plaintext configuration files.
4. **Warn users about insecure connections.** If an MCP server is using plain HTTP, display a prominent warning.

## Key Takeaways

- MCP's HTTP/SSE transport requires TLS and authentication — but neither is mandated by the protocol specification, and many implementations skip both.
- Unencrypted MCP traffic exposes tool descriptions, parameters, and results to network observers. Combined with prompt injection, this enables powerful MITM attacks.
- Missing authentication on MCP servers allows any network client to query data and execute tools.
- The stdio transport avoids network attacks but inherits the user's full permissions and is vulnerable to local process manipulation.
- Defense requires TLS everywhere, proper authentication (preferably OAuth/OIDC), session isolation, and secure defaults in MCP server implementations.

---

*Next: [#10 — Logging, Monitoring & Audit Failures: When Nobody's Watching](10-logging-monitoring-failures.md)*
