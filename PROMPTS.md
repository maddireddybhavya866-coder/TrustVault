# PROMPTS.md – AI usage log

Keep this file current as you work. The challenge asks for at least five dated entries, including the prompt (or fair summary), output, a specific error/limitation you caught, your correction, and the commit link. Do not invent errors or commit hashes. Replace placeholders only after you have personally reviewed and tested the code.

## Entry 1 – 2026-11-05 – Initial project scaffold
- Asked: Help scaffold a Flask secure document-sharing web application with three roles, document-level permissions, audit events, tests and documentation.
- Produced: Initial Flask app, SQLite schema, templates, test examples and docs.
- What I checked: I must verify each authorization route and run the tests locally. The generated scaffold is not proof of production security.
- What I found wrong / changed: Pending my own review and test run. Record a concrete finding here; do not claim one until observed.
- Evidence/commit: TODO – add the real commit URL after committing.

## Entry 2 – 2026-11-05 – Authorization review (live IDOR test)
- Prompt: Asked the AI to help me test whether a viewer can reach an unshared document on the deployed site, and to find where the download decision is made in app.py.
- AI output: Gave me a test procedure and, after I pasted the code, pointed to the check in download(): allowed = current_user.role == "admin" or can_read(doc, current_user.id).
- Specific issue I caught: In my first live test, the download worked while I thought I was "viewer". I did not accept that as fine and I did not assume the code was correct. I checked the route code, then re-tested.
- My correction and test: The AI suggested a shared incognito session (owner cookie still active). I did not trust that guess. I closed all incognito windows, opened a fresh one, logged in as viewer and requested /document/N/download for an unshared document. Result: 404.
- Commit: https://github.com/maddireddybhavya866-coder/TrustVault/commit/95c7208

## Entry 3 – 2026-11-05 – Authorisation: do the tests really test it?
- Prompt: Asked the AI to write tests for the edit, delete and permission routes, so that one user cannot change another user's documents.
- AI output: Four tests (unshared viewer cannot edit, cannot delete, cannot grant permissions; read-only grant cannot edit).
- Specific issue I checked: The challenge says judges will remove one authorisation check and run my tests. Passing tests alone prove nothing, so I tested the tests.
- My correction and test: I commented out the owner/admin check in delete_document. test_unshared_viewer_cannot_delete failed (302 instead of 404), so the test really depends on that check. I restored the line and all 8 tests passed again.
- Commit: https://github.com/maddireddybhavya866-coder/TrustVault/commit/073e0de

## Entry 4 – Date: YYYY-MM-DD – Upload validation review
- Prompt: [Paste your actual prompt]
- AI output: [Summarise]
- Specific issue I caught: [Describe the actual issue]
- My correction and test: [Describe]
- Commit: [Real commit URL]

## Entry 5 – Date: YYYY-MM-DD – Security test review
- Prompt: [Paste your actual prompt]
- AI output: [Summarise]
- Specific issue I caught: [Describe the actual issue]
- My correction and test: [Describe]
- Commit: [https://github.com/maddireddybhavya866-coder/TrustVault/commit/5321678]

## Reusable context
- The backend, not the frontend, must enforce authorization on every document route.
- Revocation must be checked on every request.
- Never claim a test passed until it has been run.
- Never commit secrets, real private documents, or real user data.
