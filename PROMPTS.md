# PROMPTS.md – AI usage log

Keep this file current as you work. The challenge asks for at least five dated entries, including the prompt (or fair summary), output, a specific error/limitation you caught, your correction, and the commit link. Do not invent errors or commit hashes. Replace placeholders only after you have personally reviewed and tested the code.

## Entry 1 – 2026-11-04 – Initial project scaffold
- Asked: Help scaffold a Flask secure document-sharing web application with three roles, document-level permissions, audit events, tests and documentation.
- Produced: Initial Flask app, SQLite schema, templates, test examples and docs.
- What I checked: I must verify each authorization route and run the tests locally. The generated scaffold is not proof of production security.
- What I found wrong / changed: Pending my own review and test run. Record a concrete finding here; do not claim one until observed.
- Evidence/commit: TODO – add the real commit URL after committing.

## Entry 2 – Date: YYYY-MM-DD – Authorization review
- Prompt: [Paste your actual prompt]
- AI output: [Summarise]
- Specific issue I caught: [Describe the actual issue]
- My correction and test: [Describe]
- Commit: [Real commit URL]

## Entry 3 – Date: YYYY-MM-DD – Audit trail review
- Prompt: [Paste your actual prompt]
- AI output: [Summarise]
- Specific issue I caught: [Describe the actual issue]
- My correction and test: [Describe]
- Commit: [Real commit URL]

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
- Commit: [Real commit URL]

## Reusable context
- The backend, not the frontend, must enforce authorization on every document route.
- Revocation must be checked on every request.
- Never claim a test passed until it has been run.
- Never commit secrets, real private documents, or real user data.
