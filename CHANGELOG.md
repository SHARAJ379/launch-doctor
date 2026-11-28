# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- New category: **Access control** (`access`, weight 3). It looks for the authorization mistakes that come up most in AI-built apps:
  - `server-action-no-auth`: Next.js Server Actions that change data without checking who is calling (every exported action is a public POST endpoint). Actions in one file are grouped into one finding. When a blocking middleware covers every page, it becomes a checklist item instead.
  - `api-write-no-auth`: Next.js route handlers, Express routes, tRPC procedures and FastAPI, Flask and Django views that change data without a sign-in check, in apps that have accounts. Webhooks with a signature check and sign-in, sign-up and contact flows are skipped.
  - `missing-ownership-check`: signed-in handlers that load or change a record by an id from the request, with no owner filter, owner comparison, permission helper or admin check (IDOR). It covers Prisma, Drizzle, Mongoose, Sequelize, Supabase with the service-role key, Firebase Admin, SQLAlchemy and Django. An owner filter taken from the request body does not count.
  - `user-metadata-role` (critical on the server, warning in the browser): roles or plans read from Supabase `user_metadata` or Clerk `unsafeMetadata`, which users can edit themselves, in code, RLS policies and SQL functions.
  - `mass-assignment`: whole request bodies, form data or Server Action arguments saved to the database, and DRF serializers or Django forms with `fields = "__all__"`.
  - `client-only-admin-check`: admin checks (a role or an admin email) that only exist in browser code, with nothing matching on the server or in database rules.
  - `jwt-not-verified` and `jwt-none-algorithm` (critical): tokens decoded without checking the signature, or the `none` algorithm allowed.
  - `supabase-getsession-server`: `supabase.auth.getSession()` trusted in server code without `getClaims()` or `getUser()`.
  - Checklist: try to open another user's data with a second test account.
- The demo app has an admin page that is only protected in the browser.

## [0.3.0] - 2026-11-27

### Added

- GitHub Action (`uses: SHARAJ379/launch-doctor@v0`): runs the checkup on pull requests, posts inline comments with fix prompts on the lines the pull request adds, and keeps one summary comment up to date. Inputs: `path`, `fail-on` (`critical`, `warning` or `never`), `comment`, `args`, `github-token`.
- `--pr-comment` posts the same pull request comments from the CLI. It never fails the run: outside a pull request, or without write access, it explains why it skipped.
- When `GITHUB_OUTPUT` is set, the grade, score, critical and warning counts are saved as step outputs.
- `launch-doctor mcp` runs a Model Context Protocol server, so Claude Code, Cursor and other AI tools can run the checkup themselves. Tools: `scan_project` (grade, findings with file, line and fix prompt, and the checklist), `scan_url` (the live site scan) and `list_checks`. Stdio only, no dependencies, protocol versions 2024-11-05 to 2025-11-25.
- Five more providers. Clerk: secret keys are told apart from Stripe's (same `sk_live_` prefix), and apps get a "switch to a production instance" checklist item. Paddle and Lemon Squeezy: webhooks that never verify the signature are critical, webhooks that sign re-encoded JSON or that are missing are warnings, and their API keys are found in code. Convex: deploy keys in code, and public mutations and actions that never check who is calling (in apps with accounts). Appwrite: API keys passed to `setKey()`, and permissions that let anyone (critical) or every signed-in user (warning) change data, in code and in `appwrite.json`.
- Mobile apps (Expo and React Native). Keys in app code are critical, since they ship inside the app, and `EXPO_PUBLIC_` variables are treated like `NEXT_PUBLIC_` ones. Monitoring looks for crash reporting (Sentry, Crashlytics, Instabug and others). Legal asks every store app for a privacy policy link. First impressions finds placeholder app IDs (`com.anonymous...`), cleartext HTTP on Android, `NSAllowsArbitraryLoads` on iOS and development addresses like `10.0.2.2`, and adds the store-readiness checklist (listing, privacy forms, a reviewer account, a release build on a real phone). Website-only checks no longer run on a mobile app, and a monorepo with both gets both.
- FastAPI, Flask, Django and Gemini are recognised and shown in the report header.
- Findings that have no file and line ("no rate limiting", "no error tracking") now say what Launch Doctor looked for, so you can check the claim yourself.

### Changed

- The workflow written by `launch-doctor init` uses `actions/checkout@v7` and `actions/setup-node@v7`.
- The README now says plainly what Launch Doctor can and cannot do: a "Read this first" summary, a "What it cannot do" section (production settings, runtime errors, authorization logic, code-level vulnerabilities, dependency vulnerabilities, stack coverage and skipped files), how it is tested, and how to report a wrong finding. The live scan's network use is described fully: it also fetches the page's scripts and source maps, which may be on other domains.
- The terminal report and `LAUNCH_FIXES.md` end with a link for reporting wrong or missed findings.

### Fixed

- A separate git repository inside the project folder (a folder with its own `.git`, like a tool you cloned to try out) is no longer scanned as part of your app. Its findings used to drag your grade down. The report names what was left out, and `--json` lists it under `nestedRepos`. Submodules are still scanned, and a folder outside git is scanned as before.
- Stopping `--demo` with Ctrl+C (or SIGTERM/SIGHUP) no longer leaves its sample project in the temp folder, and `--demo` removes `launch-doctor-demo-*` folders over an hour old that earlier killed runs left behind.
- A hand-written rate limiter (for example a counter kept in your database or Redis that answers with HTTP 429) now counts as rate limiting. Passing on the AI provider's own `RateLimitError` still doesn't.
- A Paddle webhook that never imports the Paddle SDK (the dangerous, unverified kind) was reported as "no webhook"; it is now found when its file path names Paddle, and reported as unverified.
- The MCP server said "No problems found" when every finding was in the baseline, right under an F grade. It now says no new problems were found and that the grade still counts the accepted ones.
- Expo, React Native, Paddle, Lemon Squeezy and Appwrite are named in the report header.
- The rate-limit fix prompt suggests a library for your stack (slowapi for FastAPI, Flask-Limiter, django-ratelimit, express-rate-limit, @upstash/ratelimit for serverless...) instead of always @upstash/ratelimit, and first asks your AI tool to check for an existing limiter.

## [0.2.1] - 2026-11-27

### Fixed

- Settings that only mention a sensitive word (for example `VITE_PASSWORD_MIN_LENGTH`) are no longer reported as secrets exposed through a public variable.
- A DNS lookup that times out or is refused (common for long SPF records, which need DNS over TCP) is retried, and if it still fails the report says it couldn't check, instead of warning that the SPF or DMARC record is missing.
- An `import ... from "pkg"` written inside a string (help text, prompts, docs) no longer counts as using that package, which caused false payment and AI findings.

## [0.2.0] - 2026-11-04

### Added

- `launch-doctor scan <url>` checks a deployed site from the outside: downloadable `.env`, `.git` and SQL backups, public source maps, API keys in the JavaScript, Supabase tables readable with the public key, and HTTPS and security headers. `--no-db` skips the Supabase test.
- AI endpoints are now judged one handler at a time: auth and rate limiting must be reachable from that handler, including through local imports.
- `--fail-on <critical|warning>` chooses the lowest severity that makes `--ci` exit with code 1.
- Inline ignores: a `launch-doctor-ignore <id>` comment on a finding's line or the line above silences that one finding (`//`, `#`, `/* */`, `<!-- -->` and SQL `--` comments).
- `--only <ids>` and `--skip <ids>` run or skip categories; skipped categories don't count toward the grade.
- GitHub Actions job summary: when `GITHUB_STEP_SUMMARY` is set, a Markdown summary is added to the job page.
- `--sarif <file>` writes SARIF 2.1.0 for GitHub code scanning.
- Baselines: `--update-baseline` writes `.launchdoctor-baseline.json`; later runs mark known findings, collapse them and leave them out of `--ci`. `--no-baseline` ignores the file.
- `launch-doctor init` creates a commented `.launchdoctorignore` and a GitHub Actions workflow without overwriting existing files.
- `--history` and `--history-depth <n>` find API keys that were removed from the code but are still in git history.
- Comment-aware matching: commented-out code no longer counts as an error boundary, account deletion, rate limiter, auth check or webhook verification.
- Supabase policies are graded by how open they are: open write policies are critical, write policies open to any signed-in user are a warning, and public read policies go on the checklist.
- Email: a sender domain that doesn't exist in DNS gets one clear warning, and a missing root SPF record is a checklist item (not a warning) for Amazon SES, Postmark and SendGrid.
- Web-app detection: monitoring, legal and first-impressions checks only run on web apps.
- Unknown ids in `.launchdoctorignore` are reported as a warning.

### Changed

- Any critical finding now gives an F, in its category and overall.
- Removed all emojis from the terminal report, `LAUNCH_FIXES.md`, `--help` and the docs. The report uses `[CRITICAL]`, `[WARN]`, `[PASS]` and `[ ]` labels.
- `--json` and `--ci` no longer write `LAUNCH_FIXES.md` unless `--out` is given.
- An existing `LAUNCH_FIXES.md` is rewritten (with an "All clear" section) when nothing is left to fix.
- In `.launchdoctorignore`, a bare word that names an existing file or folder is treated as a path.
- Requires Node.js 22 or newer.
- Match line numbers use cached line starts and a binary search, which is faster on large files.

### Fixed

- Middleware only counts as protecting AI routes when it actually blocks signed-out requests and covers `/api` (Supabase's `updateSession()` alone doesn't).
- The rate-limit check no longer passes on comments, `RateLimitError` handling, or a package that is installed but never imported.
- Sending an `Authorization` header to the AI provider is no longer mistaken for a user auth check.
- A global `app.use(express.json())` with no `express.raw()` is reported, because it breaks Stripe signature checks.
- Every Stripe webhook route is checked on its own; one verified webhook no longer hides an unverified one.
- DKIM records that contain only the public key (`p=...`) are recognised.
- Truncated scans (more than 20,000 files) are still sorted.
- The `--demo` temp folder is deleted even if the scan crashes.
- Every git command runs with `core.fsmonitor=false`, so scanning an untrusted folder can't make git run a program from that folder's `.git/config`.

## [0.1.0] - 2026-11-02

First release.

### Added

- `npx launch-doctor`: grades a project A-F in eight categories (secrets and keys, database and backups, payments, AI and API costs, email delivery, errors and monitoring, legal and trust, first impressions).
- Plain-English explanations and a copy-paste fix prompt for every finding, saved to `LAUNCH_FIXES.md`.
- "Check yourself" checklist items for things code can't show.
- Live DNS check of SPF, DKIM and DMARC for the sending domain.
- `--json`, `--ci`, `--offline`, `--out`, `--no-file`, `--domain` and `--demo`.
- `.launchdoctorignore` for silencing findings by id or skipping paths.
- Support for JavaScript / TypeScript and Python projects.

[Unreleased]: https://github.com/SHARAJ379/launch-doctor/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/SHARAJ379/launch-doctor/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/SHARAJ379/launch-doctor/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/SHARAJ379/launch-doctor/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/SHARAJ379/launch-doctor/releases/tag/v0.1.0
