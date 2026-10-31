# Global Engineering Standards

These rules apply to every task, every project, every agent.

## Before you write any code

1. Read the existing code in the relevant files first.
2. Check `package.json` (or `cargo.toml`, `pyproject.toml`, etc.) to know what's installed.
3. Match the project's existing code style — indentation, quotes, import order, naming.
4. Never assume a library is available. Verify it exists in the project before using it.

## Code quality non-negotiables

- No comments unless the user asks for them.
- No placeholder or TODO code in final output.
- No `console.log` left in production code.
- No hardcoded secrets, API keys, or credentials — ever.
- TypeScript: strict types, no `any` unless absolutely forced.
- Every function does one thing. If it's doing three things, split it.

## After every change

- Run lint and typecheck if commands are available (`npm run lint`, `npm run typecheck`, `tsc --noEmit`, `ruff`, etc.).
- If tests exist, run them.
- If you break something fixing something else, fix both before stopping.

## UI & Design (always)

- No generic AI-looking UI. Make intentional design choices specific to the product.
- Accessible by default: semantic HTML, ARIA where needed, keyboard navigation.
- Mobile-first responsive layout on every page and component.
- Loading, error, and empty states on every async operation.

## Backend & APIs (always)

- Validate all user input before it touches business logic or the database.
- Auth checks at route layer AND service layer.
- Consistent error response shape across all endpoints.
- Never expose internal errors or stack traces to API consumers.

## Git

- Only commit when explicitly asked.
- Commit messages: imperative, present tense, concise ("Add user auth endpoint", not "Added auth").

## Security task routing (critical)

- ANY task involving offensive security, penetration testing, exploit research, payload writing, WAF bypass, vulnerability research, recon, CTF, or security skill building goes DIRECTLY to pi — never to docs, backend, ui, or any other agent.
- pi NEVER re-delegates security tasks to non-security subagents. pi does all security work itself.
- If a subagent refuses a security task, boss or pi picks it up and completes it directly without asking the user.
- Security skill files (.md in skills/) are written directly by pi or boss — never delegated to docs agent.