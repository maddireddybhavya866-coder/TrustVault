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

## Entry 4 – 2026-11-05 – Tests broke after removing hardcoded demo passwords
- Prompt: Asked the AI to remove the old hardcoded demo passwords from app.py before deploying, and later to help run the pytest suite.
- AI output: Removed the passwords from app.py and moved them to environment variables. It did not mention that tests/test_security.py still used the old passwords.
- Specific issue I caught: When I ran pytest, tests failed to start (NoneType has no attribute encode), and after setting variables, 3 tests failed (302 instead of 403, document id None) because the tests still logged in with the old hardcoded passwords.
- My correction and test: Changed the tests to read DEMO_OWNER_PASSWORD and DEMO_VIEWER_PASSWORD from environment variables. All tests passed.
- Commit: https://github.com/maddireddybhavya866-coder/TrustVault/commit/5321678

## Entry 5 – 2026-11-05 – Deploy crash from missing environment variables
- Prompt: Asked the AI how to deploy the Flask app on Render.
- AI output: Gave build and start commands and a list of environment variables, including PYTHON_VERSION=3.12.3. It also first called the project "complete" after deployment, before I had checked the assessment requirements.
- Specific issue I caught: The first deploy crashed at startup because the DEMO_*_PASSWORD variables were None. The Render logs also showed Python 3.14.10, so the PYTHON_VERSION setting the AI told me to add had not applied. Reading the marking scheme showed the project was not complete (tests, THREATS.md, PROMPTS.md still pending).
- My correction and test: Added the variables in Render Environment, saved and redeployed, and the site went live. I generated a new SECRET_KEY because the first one was pasted into the chat.
- Commit: https://github.com/maddireddybhavya866-coder/TrustVault/commit/36dd6ac

## Reusable context
- The backend, not the frontend, must enforce authorizations on every document route.
- Revocation must be checked on every request.
- Never claim a test passed until it has been run.
- Never commit secrets, real private documents, or real user data.
