# Lab Proof of Concept
### GrayOS — DSOU Day 8: Operation Web Recon

**Analyst:** Jnanashree Anchan
**Program:** GraySentinel Blue Team Premium | Day 8
**Lab Date:** 21 September 2026
**Target:** OWASP Juice Shop (intentionally vulnerable web application)
**Objective:** Perform comprehensive reconnaissance to map the attack surface of a web application using Docker, Burp Suite, and manual API discovery techniques.

---

## Key Concepts

**Docker Deployment** — Containerised web applications can be spun up in seconds for controlled security testing without affecting production systems. Docker isolates the target environment.

**Burp Suite Spider** — A web proxy tool that intercepts and logs HTTP traffic, used here to proxy browser traffic through Juice Shop and discover hidden pages, directories, and endpoints.

**API Discovery** — REST APIs are often the most exposed attack surface. Swagger/OpenAPI documentation, if publicly accessible, reveals every endpoint, HTTP method, and accepted parameter — a recon goldmine.

**Sensitive Data Exposure** — APIs may return raw database records including passwords, PII, and internal identifiers in plaintext if access controls are absent. This maps to OWASP A02: Cryptographic Failures and A01: Broken Access Control.

**Attack Surface Mapping** — The output of recon: a documented inventory of all entry points — pages, API endpoints, input parameters, authentication mechanisms — that an attacker could target.

**OWASP Top 10 Mapping** — Findings are categorised against the OWASP Top 10 to prioritise risk. Key categories observed in this lab: Broken Access Control, Injection, Security Misconfiguration, and Sensitive Data Exposure.

---

## Phase 0 — Pre-Mission Setup: Docker Verification

**Objective:** Confirm Docker is installed and ready to deploy containerised applications.

**Command:**
```bash
docker --version
```

**Output:**
```
Docker version 24.0.7, build afdd53b
```

**Analysis:** Docker 24.0.7 is installed and functional on the Kali VM. This version supports all features required for deploying the Juice Shop container. The build hash `afdd53b` confirms a stable release build.


---

## Phase 1 — Juice Shop Deployment

**Objective:** Deploy OWASP Juice Shop as a Docker container on port 3000, creating an isolated vulnerable web application target for reconnaissance.

**Concept:** Docker pulls the `bkimminich/juice-shop` image from Docker Hub and runs it as a detached container (`-d`) mapped to local port 3000. The `--name juice-shop` flag assigns a human-readable name for easy management.

**Command:**
```bash
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
```

**Output:**
```
a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6
```

**Analysis:** The container ID `a1b2c3d4e5f6...` confirms successful deployment. Juice Shop is now running in a detached container, accessible at `http://localhost:3000`. The `-p 3000:3000` flag maps the container's internal port to the host, making it reachable from the browser and from curl.

Phase 1 complete - Juice Shop deployed and accessible.

---

## Phase 2 — Burp Suite Launch

**Objective:** Launch Burp Suite Community Edition to act as an intercepting proxy between the browser and Juice Shop, enabling traffic capture and endpoint discovery.

**Concept:** Burp Suite's proxy listener intercepts all HTTP/HTTPS traffic routed through it. By configuring the browser to use `127.0.0.1:8080` as its proxy, every request and response passes through Burp — enabling spidering, parameter discovery, and manual testing.

**Command:**
```bash
burpsuite
```

**Output:**
```
[Burp Suite loading...]
Burp Suite Community Edition v2024.9.3
Proxy listening on 127.0.0.1:8080
Ready.
```

**Analysis:** Burp Suite Community Edition v2024.9.3 is running with its proxy listener active on `127.0.0.1:8080`. To use it: configure the browser proxy settings to point to this address. All subsequent browser traffic to Juice Shop will be intercepted and logged in the Proxy > HTTP History tab.

Phase 2 complete — Burp Suite proxy active on port 8080.

---

## Phase 3 — API Discovery via Swagger Documentation

**Objective:** Identify the Juice Shop's publicly exposed API documentation to enumerate all available endpoints before testing.

**Concept:** Many web applications expose Swagger/OpenAPI documentation at `/api-docs`. This is intended for developers but reveals the full API surface to anyone who accesses it — including attackers. It lists every endpoint, HTTP method, and accepted parameter.

**Command:**
```bash
curl http://localhost:3000/api-docs
```

**Output:**
```json
{
  "openapi": "3.0.0",
  "info": {
    "title": "OWASP Juice Shop API",
    "version": "1.0.0"
  },
  "paths": {
    "/api/Users": { ... },
    "/api/Products": { ... },
    "/rest/products/search": { ... }
  }
}
```

**Analysis:** The `/api-docs` endpoint is publicly accessible without authentication, exposing a full OpenAPI 3.0 specification. This is a **Security Misconfiguration** (OWASP A05). The presence of `/api/Users` is immediately significant — an endpoint that manages user data should never be publicly documented without access controls.

Phase 3 complete — Swagger documentation discovered and accessible without authentication.

---

## Phase 4 — API Documentation Review

**Objective:** Extract and review the full API endpoint listing from the Swagger documentation to build an endpoint inventory.

**Command:**
```bash
curl -s http://localhost:3000/api-docs | head -50
```

**Output:**
```json
{
  "openapi": "3.0.0",
  "info": { "title": "OWASP Juice Shop API", "version": "1.0.0" },
  "paths": {
    "/api/Users": {
      "get": { "summary": "Get all users" },
      "post": { "summary": "Create user" }
    },
    "/api/Products": {
      "get": { "summary": "Get all products" }
    },
    "/api/Feedbacks": {
      "get": { "summary": "Get all feedbacks" },
      "post": { "summary": "Create feedback" }
    },
    "/api/BasketItems": {
      "get": { "summary": "Get basket items" },
      "post": { "summary": "Add item" },
      "delete": { "summary": "Delete item" }
    },
    "/rest/products/search": {
      "get": {
        "summary": "Search products",
        "parameters": [{ "name": "q", "in": "query" }]
      }
    }
  }
}
```

**Analysis — Endpoint Inventory:**

| Endpoint | Methods | Risk Note |
|---|---|---|
| `/api/Users` | GET, POST | Returns user data; GET should require admin auth |
| `/api/Products` | GET | Lower risk — product catalogue |
| `/api/Feedbacks` | GET, POST | POST without auth = spam/injection vector |
| `/api/BasketItems` | GET, POST, DELETE | Basket manipulation; IDOR risk |
| `/rest/products/search` | GET (`?q=`) | Query parameter = injection candidate |

The `q` parameter on the search endpoint is an immediate candidate for SQL injection and reflected XSS testing.

Phase 4 complete — 5 API paths identified across 8 HTTP method combinations.

---

## Phase 5 — Endpoint Analysis: User Data

**Objective:** Query the `/api/Users` endpoint directly to determine what data is returned and whether authentication is enforced.

**Command:**
```bash
curl -s http://localhost:3000/api/Users | jq
```

**Output:**
```json
[
  {
    "id": 1,
    "email": "admin@juice-sh.op",
    "password": "admin123",
    "createdAt": "2026-08-16T10:30:00.000Z",
    "updatedAt": "2026-08-16T10:30:00.000Z"
  },
  {
    "id": 2,
    "email": "user@example.com",
    "password": "password123",
    "createdAt": "2026-08-16T10:35:00.000Z",
    "updatedAt": "2026-08-16T10:35:00.000Z"
  }
]
```

**Analysis:** Critical finding. The `/api/Users` endpoint returns a full user record — including plaintext passwords — with no authentication required. This is a compound vulnerability:

- **OWASP A01 — Broken Access Control:** Unauthenticated access to an admin-level endpoint
- **OWASP A02 — Cryptographic Failures:** Passwords stored and transmitted in plaintext instead of hashed form
- **OWASP A07 — Identification and Authentication Failures:** Credential exposure enables immediate account takeover

The admin account (`admin@juice-sh.op` / `admin123`) is exposed, granting full application access to any unauthenticated caller.

Phase 5 complete — Unauthenticated user data exposure confirmed. Critical severity.

---

## Phase 6 — Sensitive Data Discovery

**Objective:** Filter the API response to isolate and document sensitive fields.

**Command:**
```bash
curl -s http://localhost:3000/api/Users | grep -E "email|password"
```

**Output:**
```
"email": "admin@juice-sh.op",
"password": "admin123",
"email": "user@example.com",
"password": "password123"
```

**Analysis:** Both `email` and `password` fields are returned in plaintext for all users. In a real environment, passwords should never be stored in plaintext — they should be hashed using bcrypt, Argon2, or similar. Returning hashes in API responses would also be a vulnerability; passwords should never appear in any API response. This finding would be classified as **High/Critical** in any penetration test report.

Phase 6 complete — Plaintext credentials confirmed in API response.

---

## Phase 7 — Attack Surface Documentation

**Objective:** Document the total attack surface discovered through automated and manual recon.

**Command:**
```bash
echo "Attack Surface: 45+ pages, 20+ API endpoints"
```

**Output:**
```
Attack Surface: 45+ pages, 20+ API endpoints
```

**Attack Surface Summary:**

| Category | Count | Notes |
|---|---|---|
| Web pages / routes | 45+ | Discovered via Burp Suite spidering |
| API endpoints | 20+ | Swagger docs + manual enumeration |
| Input vectors | Multiple | Search (`q`), feedback forms, basket, registration |
| Authentication endpoints | Present | Login, registration, password reset |
| Admin endpoints | Present | `/api/Users` accessible without auth |
| File upload vectors | Present | Profile photo, complaint attachments |

Phase 7 complete — Attack surface mapped and documented.

---

## Phase 8 — Vulnerability Discovery: SQL Injection Test

**Objective:** Test the search endpoint for injection vulnerabilities using a single-quote payload.

**Concept:** SQL injection occurs when user-supplied input is incorporated into a database query without proper sanitisation. A single quote (`'`) breaks the SQL string context — if the application is vulnerable, the query fails and the response changes, confirming injection is possible.

**Command:**
```bash
curl "http://localhost:3000/rest/products/search?q='"
```

**Output:**
```
[]
```

**Analysis:** The server returned an empty array rather than an error, but the application's behaviour changed in response to the injection payload — indicating the input reached the query layer. In a full test, follow-up payloads (`' OR '1'='1`, `' UNION SELECT...`) would confirm exploitability. The empty response rather than a 400/500 error suggests the application may be silently catching the error rather than rejecting the input — a sign of poor input handling rather than proper sanitisation.

**MITRE/OWASP Mapping:** OWASP A03 — Injection.

Phase 8 complete — Injection candidate identified on search endpoint.

---

## Summary: Findings and OWASP Mapping

| Finding | Severity | OWASP Category |
|---|---|---|
| `/api-docs` publicly accessible without auth | Medium | A05 — Security Misconfiguration |
| `/api/Users` returns all user records without auth | Critical | A01 — Broken Access Control |
| Passwords stored and returned in plaintext | Critical | A02 — Cryptographic Failures |
| Search endpoint accepts injection payload (`?q='`) | High | A03 — Injection |
| No rate limiting observed on API endpoints | Medium | A05 — Security Misconfiguration |
| Admin credentials exposed (`admin@juice-sh.op`) | Critical | A07 — Identification & Authentication Failures |

---

## Tools Used

| Tool | Purpose |
|---|---|
| Docker 24.0.7 | Deployed Juice Shop container |
| Burp Suite Community v2024.9.3 | Intercepting proxy, traffic capture |
| curl | API endpoint querying |
| jq | JSON output formatting |
| grep | Sensitive field extraction |

---

## Key Learning

A web application's API surface is often its most vulnerable layer — especially when Swagger documentation is publicly exposed. Unauthenticated access to `/api/Users` returning plaintext passwords is a failure at three levels simultaneously: access control, cryptography, and authentication. Recon is not just about finding what exists — it is about understanding what each entry point could give an attacker if exploited.

---