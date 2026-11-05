# THREATS.md – TrustVault

Update this document after running each test. Do not claim a threat is fixed unless you have verified it against the running app.

| Threat | Mitigation in this starter | Test/evidence | Remaining risk |
|---|---|---|---|
| IDOR: viewer guesses document ID | Every detail/download route checks server-side permission | `test_private_document_denied_to_unshared_viewer` passes locally. Live test 2026-11-05: viewer got 404 on /document/N/download for an unshared document.| Admin has global access by design |
| Revoked user reuses old URL | Permission is queried on every request; no public file URL | `test_owner_can_grant_and_revoke_access` | Already downloaded copies cannot be recalled |
| Viewer uploads file | Role decorator blocks upload route | `test_viewer_cannot_upload` | Role changes require admin protection |
| Unauthorized edit/delete | Server-side owner/edit checks | Add explicit tests before claiming complete | Admin can edit/delete globally |
| Malicious file upload | Extension allowlist, secure filename, size limit, random stored name | Manually test disallowed extension and oversized file | No signature validation or antivirus scan |
| Audit record alteration | Hash chain and verification function | `test_audit_chain_detects_modified_entry` | DB administrator can rewrite entire chain |
| Password disclosure | Werkzeug password hashing | Inspect database; verify no plaintext password | Demo credentials must be changed |
| Session theft/fixation | Flask-Login and HttpOnly/SameSite cookies | Manual cookie inspection | Secure cookie enabled only with COOKIE_SECURE=1 |
| CSRF on state-changing forms | Flask-WTF CSRFProtect on all POST forms | Manual test 2026-11-05 on live: POST /login without a token returned 400 "CSRF token is missing"; login, upload, edit, grant and delete work with tokens in a browser. Automated tests run with CSRF disabled (WTF_CSRF_ENABLED=False), so there is no automated CSRF test yet. | Logout is a GET route, so it can be triggered cross-site (low impact). |
| Brute-force login | Not implemented | Add rate-limit tests | Password guessing risk |
| SQL injection | SQL values passed as parameters | Review SQL calls and add injection tests | Dynamic SQL fragments are limited to fixed strings |
| Direct filesystem access | Random filenames outside static directory | Check no public upload route exists | Host/operator filesystem access remains |
| Audit log deletion/reordering | Hash-chain detects simple alteration | Tamper test | Need external append-only/WORM storage for stronger evidence |
| XSS via metadata | Jinja autoescaping | Test HTML payload in title | Review any future `safe` rendering |
| File overwrite/path traversal | `secure_filename` and generated UUID storage name | Try `../../...` filename | Add content-signature and archive-bomb checks |

## Threat model
Assets: private document bytes, metadata, permission grants, user credentials, audit history.
Trust boundaries: browser-to-Flask requests; Flask-to-SQLite; Flask-to-private filesystem; deployment operator.
Primary security rule: the server makes the authorization decision on every document operation. UI visibility is not authorization.

## Accepted limitations
This starter is a demonstration. Do not upload real confidential data. Before production, rate limiting, malware scanning, signature-based file validation, robust backup/restore, external immutable audit storage, secure secret management and a persistent private storage service.
