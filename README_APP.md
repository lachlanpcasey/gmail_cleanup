# Gmail Cleanup (prototype)

This repository contains a FastAPI prototype for securely detecting and unsubscribing from subscription emails using Gmail API.

Key features implemented in scaffold:

- Google OAuth2 sign-in (server-side flow)
- Encrypted token storage (Fernet)
- List-Unsubscribe header parsing and basic detection helpers
- Templates for basic UI
- Unit tests for header parsing
- Dockerfile and .env.example

Security & privacy notes:

- Tokens are encrypted at rest using `FERNET_KEY` (set in environment).
- The app requests only `gmail.readonly` and `gmail.modify` scopes.
- Unsubscribe execution is conservative: only List-Unsubscribe headers are trusted; HTML body links are not auto-clicked.

Next steps:

- Implement mailbox scanning and grouping logic
- Implement unsubscribe execution (HTTPS/mailto) with user confirmation
- Add background jobs, rate limiting, pagination, and activity history
