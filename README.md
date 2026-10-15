# RBAC reference implementation — `accesscontrol` v3 over a JSON database

A complete, production-shaped role-based access control system: role hierarchy,
ownership, field-level (attribute) authorization, conditions, mandatory gates,
custom actions, a runtime-editable policy, and an audit trail of every decision.

The database is a directory of JSON files (`data/*.json`) so the whole thing
runs with no services to install — but nothing above the repository layer knows
that, and swapping in Postgres means rewriting one file.

```bash
bun install
bun run seed     # write a fresh database + policy snapshot into ./data
bun run demo     # scripted tour of the policy — every line is a real request
bun run start    # serve on http://127.0.0.1:3000
bun test         # 66 tests: policy decisions + end-to-end HTTP
```

---

## 1. What "industry-standard RBAC" means here

RBAC is usually implemented as `if (user.role === 'admin')` scattered across
route handlers. That is not a policy — it is an opinion repeated in eighty
places. This implementation takes the other approach:

| Property | How it is done |
| --- | --- |
| **Roles are data** | The grants model lives in `data/policy.json` and is edited through `/admin/policy/*` at runtime. Code seeds it; it does not own it. |
| **Hierarchy** | `admin → manager → {editor → author → user → guest, accountant}`. Grants are additive up the chain. |
| **Ownership (`own` vs `any`)** | Enforced by the engine through an ownership resolver, not by handlers comparing ids. |
| **Field-level authority** | Every grant carries an attribute list. `passwordHash` is unreachable because no rule grants it — not because a handler deletes it. |
| **Conditions (ABAC)** | Rules may test the record, the request body, the clock or the session: `$.article.status == "draft"`, `$.invoice.amount <= 100000`. |
| **Mandatory gates** | `require()` restrictions that no grant can override — a disabled account, an unverified session. |
| **Custom actions** | `publish` and `approve` are first-class verbs, not CRUD approximations. |
| **Deny-overrides** | A read-only `auditor` is built by inheriting `manager` and denying every mutation. |
| **Fail-closed** | Every request-path check goes through `tryCan()`; a thrown error can never become an allow. |
| **Auditability** | The engine's `access` event feeds an append-only log: who, what, granted or not, and *why not*. |
| **Least privilege by default** | No route trusts the caller; the anonymous caller holds the `guest` role and is evaluated like everyone else. |

---

## 2. Layout

```
index.ts                     server entry (seeds an empty data dir, then serves)
src/
  config.ts                  environment configuration
  domain/types.ts            entities
  db/
    jsonStore.ts             atomic, serialized JSON document store
    index.ts                 the collections ("tables")
    seed.ts                  accounts, content and the seed policy snapshot
  rbac/
    registry.ts              the vocabulary: roles, resources, actions, owner fields
    policy.ts                THE POLICY — every rule, in one readable file
    accessControl.ts         engine construction: ownership resolver, strict mode
    authz.ts                 the decision layer used by routes
    audit.ts                 access log fed by the engine's own events
  auth/
    passwords.ts             argon2id hashing
    sessions.ts              opaque bearer tokens, stored hashed
    authService.ts           login, step-up, request identification
    rateLimit.ts             login throttling
  http/
    router.ts  app.ts  guards.ts  responses.ts  validate.ts
    routes/                  auth, users, articles, comments, invoices, admin
  scripts/seed.ts  scripts/demo.ts
tests/
  policy.test.ts             decision-level tests (no HTTP, no database)
  api.test.ts                end-to-end contract tests
```

### Request lifecycle

```
Request
  → router match                     404 / 405
  → AuthService.identify()           bearer token → session → user → Actor
                                     (no token ⇒ anonymous actor with role "guest")
  → handler
      ctx.authorize({action, resource, record, input})
          → Authz.check()            engine decision + ownership + deny-overrides
          → HttpError 401/403        with a reason the client can act on
      authz.sanitize(decision, body) reject fields the grant does not cover
      … business logic …
      authz.project(decision, row)   strip fields the grant does not cover
  → JSON response (+ x-request-id)
```

---

## 3. The policy

All of it is in [`src/rbac/policy.ts`](src/rbac/policy.ts). Summary:

### Roles

```
guest                       read published articles, read comments
 └ user                     own profile, own comments
    ├ author                own articles: draft → review → publish
    │  └ editor             all articles, flag/delete comments, publish (business hours)
    └ accountant            invoices: read all, create/update own
          └ manager         (extends editor + accountant) approve ≤ 100 000, read all users
             ├ auditor      everything a manager can *read*, every mutation denied
             └ admin        users, invoices without limits, and the policy itself
```

### Notable rules

| Rule | Why it is interesting |
| --- | --- |
| `guest` reads `article` **where** `$.article.status == "published"`, attributes `['*','!internalNotes']` | Row-level *and* field-level in one rule. |
| `author` updates own article **where** status is `draft`/`review` **and** `$.input.status != "published"` | A condition over the *request body*: an author may move a draft to review, never to published. |
| `author` publishes own article **where** status is `review` | Custom action gated on workflow state. |
| `editor` publishes any article **during** `T0900:1800 E1:5` | Time-bounded authority; denials report `out_of_schedule` ("granted, but not now"). |
| `manager` approves invoices **where** `amount <= 100000 and status == "draft"` | Approval limits as policy, not as an `if`. |
| `admin` approves invoices unconditionally | Rules are additive: the admin's unconditional rule sits beside the manager's capped one. |
| `auditor` inherits `manager`, then denies every write on both possessions | Deny-overrides — see the footgun note in §6. |
| Gate: `$.actorEnabled == true` (global) | A disabled account is denied by the policy, not only by the login endpoint. |
| Gate: `$.mfa == true` on `invoice` | Step-up verification for billing, declared once, enforced everywhere — there is not one MFA check in the invoice routes. |

### Check context

Conditions read a single merged context:

| Path | Meaning |
| --- | --- |
| `$.subject` | the caller — `{ id, roles }` |
| `$.record` | the record under check |
| `$.<resource>` | the same record, named (`$.article.status`, `$.invoice.amount`) |
| `$.input` | the incoming request body |
| `$.mfa`, `$.actorEnabled`, `$.authenticated` | session facts used by gates |
| `$.now` | evaluation instant (auto-injected; overridable for tests) |

The caller is `$.subject`, not `$.user`, on purpose: the record is also exposed
under its resource name, and for the `user` resource that alias would overwrite
the caller — silently turning every `own` rule on users into an `any` rule.
There is a regression test for exactly this.

---

## 4. Using it

### Accounts (password `correct-horse-battery-staple`)

| Email | Roles |
| --- | --- |
| `admin@example.com` | admin |
| `mia@example.com` | manager |
| `eddie@example.com` | editor |
| `aria@example.com`, `alex@example.com` | author |
| `cara@example.com` | accountant |
| `rita@example.com` | auditor |
| `uma@example.com` | user |
| `dana@example.com` | editor (disabled) |

### A session

```bash
# anonymous: published articles only, no internalNotes
curl -s localhost:3000/articles

TOKEN=$(curl -s -XPOST localhost:3000/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"cara@example.com","password":"correct-horse-battery-staple"}' \
  | jq -r .token)

curl -s localhost:3000/invoices -H "authorization: Bearer $TOKEN"
# 403 step_up_required

curl -s -XPOST localhost:3000/auth/mfa/verify -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"code":"123456"}'

curl -s localhost:3000/invoices -H "authorization: Bearer $TOKEN"   # 200

# what may I do?
curl -s localhost:3000/auth/permissions -H "authorization: Bearer $TOKEN"
```

### Endpoints

| | |
| --- | --- |
| **Auth** | `POST /auth/login` · `POST /auth/logout` · `POST /auth/mfa/verify` · `GET /auth/me` · `GET /auth/permissions` |
| **Users** | `GET /users` · `POST /users` · `GET /users/:id` · `PATCH /users/:id` · `POST /users/:id/password` · `DELETE /users/:id` |
| **Articles** | `GET /articles` · `POST /articles` · `GET /articles/:id` · `PATCH /articles/:id` · `DELETE /articles/:id` · `POST /articles/:id/publish` |
| **Comments** | `GET /articles/:id/comments` · `POST /articles/:id/comments` · `PATCH /comments/:id` · `DELETE /comments/:id` |
| **Invoices** | `GET /invoices` · `POST /invoices` · `GET /invoices/:id` · `PATCH /invoices/:id` · `POST /invoices/:id/approve` · `DELETE /invoices/:id` |
| **Policy admin** | `GET /admin/policy` · `GET /admin/policy/roles/:role` · `POST /admin/policy/roles` · `DELETE /admin/policy/roles/:role` · `POST /admin/policy/rules` · `DELETE /admin/policy/rules` · `GET /admin/audit` |

### Editing the policy at runtime

```bash
curl -s -XPOST localhost:3000/admin/policy/roles -H "authorization: Bearer $ADMIN" \
  -H 'content-type: application/json' \
  -d '{"role":"contributor","extend":["user"]}'

curl -s -XPOST localhost:3000/admin/policy/rules -H "authorization: Bearer $ADMIN" \
  -H 'content-type: application/json' \
  -d '{"role":"contributor","resource":"article","action":"create","possession":"own",
       "attributes":["title","body","tags"],"condition":["$.input.status","!=","published"]}'
```

The change is validated by the engine, written to `data/policy.json`, and is in
force for the next request. `POLICY_LOCKED=true` calls `ac.lock()` at boot and
makes the admin API read-only (409) — the right setting once a policy is settled.

### Error codes

Denials are specific enough to act on:

| Status | Code | Meaning |
| --- | --- | --- |
| 401 | `unauthenticated` / `invalid_credentials` | No usable credentials — log in and retry. |
| 403 | `forbidden` | No rule grants this. |
| 403 | `not_owner` | Only `own` rules apply and this record is not yours. |
| 403 | `condition_failed` | A rule exists but its condition did not hold. |
| 403 | `out_of_schedule` | Allowed, outside its time window. |
| 403 | `step_up_required` | A `require()` gate wants a verified session. |
| 403 | `field_forbidden` | The body contained fields your grant does not cover (`details.deniedFields`). |
| 403 | `account_disabled` | The global gate rejected the account. |

---

## 5. Design decisions worth defending

**One decision layer.** Handlers never call `AccessControl` directly. They call
`ctx.authorize(...)`, which resolves `any` vs `own`, applies deny-overrides and
throws the right HTTP error. Scattering those subtleties across twenty handlers
is how authorization bugs are born.

**Ownership is resolved by the engine.** `OWNER_FIELDS` maps each resource to its
owner field, and a single resolver answers "does this record belong to the
caller?". `strict.checks` means an `own` check without a record is denied rather
than waved through.

**Write authority is field-level, and refuses rather than drops.** A body
containing a field the caller may not write returns 403 with `deniedFields`. A
client that believes it changed `roles` and got a 200 has been told a lie.

**Collections are filtered row by row.** A rule like "readable while published"
is a statement about rows; it cannot be answered without the row. `GET /articles`
therefore checks each candidate and projects each survivor through the rule that
let it through — two callers can receive the same row with different fields on
it. Two coarse checks run first (does any read rule exist? does a mandatory gate
fail?) so "verify your second factor" does not masquerade as an empty list.
A SQL-backed version would push this into row-level security; the semantics are
the same.

**Write access does not imply read access.** After a create or update the
response is re-checked with a non-throwing read; if the caller cannot read the
record back, they get its id and `meta.readable: false` instead of a 403 on a
write that already succeeded.

**Sessions are server-side.** Opaque tokens, stored as SHA-256 hashes, so
revocation is immediate: logout, a password change, a role change and a disabled
account all invalidate live sessions on the spot. A role change that waits for a
JWT to expire is a privilege-escalation window.

**The audit log comes from the engine.** Subscribing to the `access` event
records every resolved check, including ones a handler ignores, with the denial
reason. Contexts can hold PII, so rows are reduced to the record id before being
written. Per-row checks in a collection scan are excluded and summarised in one
row, to keep a list request from writing fifty.

**Authentication and authorization are separate.** `AuthService` decides *who*;
the only thing it contributes to a decision is the `Actor`. Validation is a third
thing again: `validate.ts` decides whether a value is well formed, never whether
the caller may send it.

---

## 6. Two sharp edges in `accesscontrol` 3.1.0, and what this code does about them

Both were found by the tests in this repository; both are guarded in
`src/rbac/authz.ts` and pinned by regression tests.

**1. An `own` query can be satisfied by a denied `any` grant.** A `deny` does not
cascade across possession (documented, and reasonable). But querying
`action:own` will happily match an `any` grant whose matching `deny …:any` rule
is never consulted. A read-only role built by denying an inherited role's writes
keeps them.

**2. A `deny` rule does not override a *conditional* grant inherited two or more
levels up.** `auditor → manager → accountant`, where `accountant`'s grant carries
a condition: the deny on `auditor` is ignored entirely. One level up, or without
a condition, it works.

The decision layer therefore (a) asks for `any` first and only falls back to
`own` after verifying ownership itself, and (b) re-checks deny-overrides against
the flattened grants model, where a full, unconditional `deny` for the caller's
roles always denies. Narrower denies (field carve-outs) and conditional denies
are left to the engine, which handles those correctly.

As a policy convention, every deny in `policy.ts` is written for **both**
possessions — a read-only role has to say both, or it keeps the half nobody
thought to revoke.

---

## 7. Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` / `HOST` | `3000` / `127.0.0.1` | listen address |
| `DATA_DIR` | `./data` | the JSON "database" |
| `SESSION_TTL_MS` | 12 h | session lifetime |
| `MFA_CODE` | `123456` | demo step-up code (a real system verifies a TOTP) |
| `AUDIT_LIMIT` | `2000` | rows kept in `audit.json` |
| `LOGIN_MAX_ATTEMPTS` / `LOGIN_WINDOW_MS` | `5` / 5 min | login throttle |
| `ALLOW_TIME_TRAVEL` | on outside production | enables `X-Simulated-Now` for time-based rules |
| `POLICY_LOCKED` | `false` | `ac.lock()` at boot; policy admin becomes read-only |

---

## 8. Tests

```bash
bun test
```

- **`tests/policy.test.ts`** — decisions only: no HTTP, no database. One fact per
  test, so a failure points at a rule. Covers ownership, conditions, schedules,
  gates, deny-overrides, attribute filtering, collection scope, fail-closed
  behaviour on unknown roles/resources/actions, and a snapshot round-trip.
- **`tests/api.test.ts`** — the observable contract over the real pipeline:
  status codes, error codes, which fields come back, session revocation,
  rate limiting, and runtime policy edits taking effect mid-suite.

---

## 9. Taking this to production

What is deliberately simplified, and what it would become:

| Here | There |
| --- | --- |
| JSON files + in-process cache | Postgres; reimplement `src/db/` only |
| Row-by-row read filtering | Row-level security / a `WHERE` clause derived from the same rules |
| In-memory login throttle | Redis, shared across instances |
| `MFA_CODE` constant | TOTP/WebAuthn against the stored factor |
| Single process, policy in memory | Publish policy changes (the snapshot is already serializable) so every instance reloads |
| Capped `audit.json` | Append-only store or SIEM sink; the `access` event payload is unchanged |

What should **not** change: the policy stays declarative and in one file, checks
stay fail-closed, handlers keep calling one decision layer, and every decision
keeps landing in the audit log.
