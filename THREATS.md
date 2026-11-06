# THREATS.md – TrustVault

Update this document after running each test. Do not claim a threat is fixed unless you have verified it against the running app.

| Threat | Mitigation in this starter | Test/evidence | Remaining risk |
|---|---|---|---|
| IDOR: viewer guesses document ID | Every detail/download route checks server-side permission | `test_private_document_denied_to_unshared_viewer` passes locally. Live test 2026-11-05: viewer got 404 on /document/N/download for an unshared document.| Admin has global access by design |
| Revoked user reuses old URL | Permission is queried on every request; no public file URL | `test_owner_can_grant_and_revoke_access` | Already downloaded copies cannot be recalled |
| Viewer uploads file | Role decorator blocks upload route | `test_viewer_cannot_upload` | Role changes require admin protection |
| Unauthorized edit/delete | Server-side owner/edit checks | `test_unshared_viewer_cannot_edit`, `test_unshared_viewer_cannot_delete`, `test_read_only_grant_cannot_edit` pass locally (python -m pytest, 8 passed). | Admin can edit/delete globally |
| Malicious file upload | Extension allowlist, secure filename, size limit, random stored name | Manual test 2026-11-05 on live: test.exe and test.txt.exe were rejected (extension allowlist); an 11 MB file was rejected (10 MB limit). No automated upload tests yet. | No signature validation or antivirus scan |
| Audit record alteration | Hash chain and verification function | `test_audit_chain_detects_modified_entry` | DB administrator can rewrite entire chain |
| Password disclosure | Werkzeug password hashing | Local DB check 2026-11-05: all 4 users have scrypt hashes in password_hash; no plaintext password stored. Live database not inspected. | Demo credentials must be changed |
| Session theft/fixation | Flask-Login and HttpOnly/SameSite cookies | Manual cookie inspection 2026-11-06 on live (browser DevTools): session cookie has HttpOnly, Secure and SameSite=Lax. Session fixation and cookie theft were not otherwise tested. | Secure cookie depends on COOKIE_SECURE=1 being set in the deployment environment |
| CSRF on state-changing forms | Flask-WTF CSRFProtect on all POST forms | Manual test 2026-11-05 on live: POST /login without a token returned 400 "CSRF token is missing"; login, upload, edit, grant and delete work with tokens in a browser. Automated tests run with CSRF disabled (WTF_CSRF_ENABLED=False), so there is no automated CSRF test yet. | Logout is a GET route, so it can be triggered cross-site (low impact). |
| Brute-force login | Flask-Limiter: 5 POST /login per minute per IP (in-memory storage) | Manual test 2026-11-05 on live: 6th wrong-password attempt returned 429 Too Many Requests. Automated tests disable the limiter, so there is no automated rate-limit test yet. | In-memory limit is per worker and resets on restart; no account lockout; attackers using many IPs are not limited. |
| SQL injection | SQL values passed as parameters | Code review 2026-11-06: all execute() calls use ? placeholders; the dynamic search query only appends fixed SQL fragments and passes user input through params. No automated injection test yet. | Dynamic SQL fragments are limited to fixed strings |
| Direct filesystem access | Random filenames outside static directory | Code review 2026-11-06: uploads are stored in private_uploads/ under random UUID names, outside Flask's static folder; the only route that serves file bytes is the permission-checked download route (send_file). Manual test on live: /private_uploads/ and /uploads/ returned 404. | Host/operator filesystem access remains |
| Audit log deletion/reordering | Hash-chain detects simple alteration | `test_audit_chain_detects_modified_entry` passes locally (modification detected). Deletion/reordering not separately tested. | Need external append-only/WORM storage for stronger evidence |
| XSS via metadata | Jinja autoescaping | Manual test 2026-11-05 on live: title <script>alert(1)</script> showed as plain text on dashboard, detail and edit pages; no alert. No automated XSS test yet. | Review any future `safe` rendering |
| File overwrite/path traversal | `secure_filename` and generated UUID storage name | Code review and local check 2026-11-05: secure_filename('../../x.txt') returned x.txt; upload route saves to UPLOAD_DIR / uuid4().hex, so the user filename is never used in the disk path. Not tested through the live upload form. | Add content-signature and archive-bomb checks |

## Threat model
Assets: private document bytes, metadata, permission grants, user credentials, audit history.
Trust boundaries: browser-to-Flask requests; Flask-to-SQLite; Flask-to-private filesystem; deployment operator.
Primary security rule: the server makes the authorization decision on every document operation. UI visibility is not authorization.

## Accepted limitations
This starter is a demonstration. Do not upload real confidential data. Before production, add malware scanning, signature-based file validation, robust backup/restore, external immutable audit storage, secure secret management and a persistent private storage service.
