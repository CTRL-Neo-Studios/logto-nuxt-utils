# @type32/logto-nuxt-utils

Logto RBAC for Nuxt: declare your permissions once, then use the same typed
vocabulary in server routes, abilities and templates.

Logto splits authorization data across two places that its documentation never
states plainly. This module hides that split behind one config block and one
context shape.

| What you want | Where Logto actually puts it |
| --- | --- |
| Role *names* | the `roles` claim of the **ID token**, and only if the `roles` scope was requested |
| Permissions | the `scope` claim of a **resource-scoped access token**, never in the ID token or userinfo |
| Org roles | the `organization_roles` claim, as `orgId:roleName` |

A consequence worth internalising: a **session** caller (a browser) yields both roles
and permissions, because the module reads the ID token *and* fetches the resource
token. A **bearer** caller yields permissions only, since that single access token is
all you get. Authorize on permissions and both work identically.

---

## Installation

```bash
pnpm add @type32/logto-nuxt-utils @logto/nuxt
```

`nuxt-authorization` is registered for you. `@logto/nuxt` is not, because you must
configure its credentials in `nuxt.config` anyway.

## Configuration

```ts
// nuxt.config.ts
export default defineNuxtConfig({
  modules: ['@logto/nuxt', '@type32/logto-nuxt-utils'],

  logto: {
    endpoint: process.env.NUXT_LOGTO_ENDPOINT,
    appId: process.env.NUXT_LOGTO_APP_ID,
    appSecret: process.env.NUXT_LOGTO_APP_SECRET,
    cookieEncryptionKey: process.env.NUXT_LOGTO_COOKIE_ENCRYPTION_KEY,
  },

  logtoRbac: {
    // Resources this app OWNS. Permissions union across these, and only these are
    // accepted as the `aud` of an inbound bearer token.
    resources: [process.env.NUXT_LOGTO_API_RESOURCE!],

    permissions: [
      'assessment:create',
      'assessment:view',
      'assessment:list',
      'assessment:test',
      'assessment:delete',
      'assessment:share',
      'assessment:edit',
    ],
  },
})
```

The `logto` block declares **no `scopes` and no `resources`**. The module derives
both from `logtoRbac`, so the permission list is written exactly once.

Everything from that list becomes a literal `Permission` type, so a typo is a
compile error rather than a silent denial.

### Keeping the catalogue in its own file

No framework helper is needed; plain TypeScript is enough:

```ts
// rbac.ts
export const PERMISSIONS = ['assessment:view', 'assessment:edit'] as const
```

```ts
// nuxt.config.ts
import { PERMISSIONS } from './rbac'

export default defineNuxtConfig({
  logtoRbac: {
    resources: [process.env.NUXT_LOGTO_API_RESOURCE!],
    permissions: [...PERMISSIONS],
  },
})
```

Because these are ordinary module options, Nuxt also **merges them across layers**
(arrays concatenate), so a shared base layer can define common permissions and each
app append its own. Duplicates are de-duplicated by the module.

---

## Guarding server routes

One guard covers everything, so a route handler never contains a hand-written
`if (!user) throw ...` clause:

```ts
// server/api/assessments/index.get.ts
export default defineEventHandler(async (event) => {
  const user = await requireLogtoUser(event, { permissions: ['assessment:list'] })
  return listAssessmentsFor(user.sub)
})
```

`requireLogtoUser` returns the **Logto user claims** — the same shape
`useServerLogtoUser(event)` yields, but never `undefined`, because reaching the next
line proves there is a user. So `user.sub`, `user.email` and `user.roles` are all
there without a null check.

Permissions are **not** among those claims: they live in the `scope` claim of an
access token, never in the ID token. When a handler needs them, ask the context:

```ts
const user = await requireLogtoUser(event, { permissions: ['assessment:list'] })
const { scopes, source } = await useAuthContext(event)
```

That call is memoised per request, so it costs nothing once a guard has run.

`requireLogtoUser(event)` with no second argument is a plain authentication check.
Otherwise it takes **requirements**:

```ts
interface AuthRequirements {
  permissions?: Permission[]      // all of these        ← the primary mechanism
  anyPermission?: Permission[]    // at least one
  roles?: string[]                // exact match, any of  (secondary)
  organization?: { id: string, roles?: string[] }
  verified?: boolean              // default TRUE — pass false to allow unverified
}
```

Requirements are checked permissions-first, then roles, then organization, then
verification, so the reported failure is the most actionable one.

| Guard | Returns | Behaviour |
| --- | --- | --- |
| `requireLogtoUser(event, reqs?)` | Logto claims | 401 if not authenticated, 403 if a requirement is unmet |
| `requirePermission(event, …perms)` | Logto claims | sugar for `{ permissions }` |
| `requireAnyPermission(event, …perms)` | Logto claims | sugar for `{ anyPermission }` |
| `requireRole(event, …roles)` | Logto claims | sugar for `{ roles }` |
| `meetsRequirements(event, reqs?)` | `boolean` | non-throwing |
| `hasPermission(event, …perms)` | `boolean` | non-throwing |

Every one of these funnels through the same `checkRequirements`, so authorization is
decided in exactly one place — the same place the client and the abilities use.

A **bearer** caller has no Logto session, so its claims are the verified access-token
payload: `sub` and `scope` are present, profile claims like `email` normally are not.
Read `sub` and permissions, not profile fields, in a route that serves both.

Failures carry a machine-readable payload:

```json
{ "statusCode": 403, "data": { "failed": "permissions",
  "required": ["assessment:edit"], "held": ["assessment:view"] } }
```

`failed` is one of `unauthenticated` · `permissions` · `anyPermission` · `roles` ·
`organization` · `verified`, so a client can distinguish "sign in" from "you are
missing `assessment:edit`".

---

## On the client

`useAuthorization()` resolves the same context and applies the same checks, so the UI
cannot disagree with the route that enforces it:

```vue
<script setup lang="ts">
const auth = useAuthorization()
await auth.resolve()

const canEdit = computed(() => auth.can('assessment:edit'))
const canReview = computed(() => auth.canAny('assessment:edit', 'assessment:share'))
const isVerifiedEditor = computed(() =>
  auth.satisfies({ permissions: ['assessment:edit'], verified: true }),
)
</script>
```

| Member | Purpose |
| --- | --- |
| `can(…perms)` | every listed permission is held — the common case |
| `canAny(…perms)` | at least one is held |
| `hasRole(…roles)` | exact role match |
| `satisfies(reqs)` | the full declarative check |
| `missingPermissions(…perms)` | the subset not held, for actionable messages |
| `isOrganizationMember(id)` / `hasOrganizationRole(id, …roles)` | organization checks |
| `explain(reqs)` | the guards' full verdict: `failed` / `required` / `held` |
| `profile` | the normalised Logto user — always an object, every field `string \| null` |
| `displayName` | always a `string`: `name` → `username` → `email` → `phoneNumber` → `sub` → `'Guest'` |
| `user` / `isAuthenticated` / `scopes` / `roles` / `source` / `userId` / `organizations` | reactive state |
| `pending` / `error` / `ready` | resolution state; `ready` distinguishes "no" from "not yet" |
| `resolve()` / `refresh()` | ensure fetched / refetch |

Because these read a ref, calling them inside `computed()` is reactive.

`profile` is why a template needs no `?.` chain: unlike `useLogtoUser()` — which returns
`UserInfoResponse | IdTokenClaims | undefined` and whose every field is `Nullable<string>`
— `profile` is always present, its fields are never `undefined`, an empty claim is
normalised to `null`, and it is populated for bearer callers too. `useLogtoUser()` remains
available for raw ID-token claims.

### `useCan()`

`can()` only means anything after `resolve()`; forgetting that `await` yields a silent
`false`. `useCan()` resolves itself, SSR included, and takes the same shorthand as the
gates:

```vue
<script setup lang="ts">
const canEdit = useCan('assessment:edit')
const canManage = useCan(['assessment:edit', 'assessment:delete'])   // ALL
const canReview = useCan({ anyPermission: ['assessment:edit', 'assessment:share'] })
</script>
```

It is `false` in prerendered HTML by design — there is no request-bound cookie — and
re-evaluates on the client once the session exists.

### `useLogtoSession()`

Logto's pathnames live in private runtime config, so the browser cannot read them. The
module mirrors both into public config:

```vue
<script setup lang="ts">
const session = useLogtoSession()
</script>

<template>
  <button @click="session.signIn()">Sign in</button>
  <button @click="session.signOut()">Sign out</button>
</template>
```

`signInPath` / `signOutPath` are also exposed if you would rather render a link. There is
no `returnTo` argument: `@logto/nuxt` redirects to its statically configured
`postCallbackRedirectUri` and ignores query parameters, so one could not be honoured.

### Keeping permissions fresh

Roles and permissions are a snapshot taken when a token was issued, so a change in the
Logto console does not reach a signed-in user on its own. The module revalidates on a
timer, and reports the one case that a timer cannot fix.

**Reduced grants heal themselves.** Revoke a permission, or take a role away, and the
change lands within `revalidateAfter` seconds (default `300`) with no sign-out. Past the
window the module discards the cached access token and performs a refresh grant, which
Logto answers with the current scopes — and with a fresh ID token, so `roles` updates
too.

**Gained permissions do not.** Logto issues only scopes that were requested in the
original authorization request, so a permission added to `logtoRbac.permissions` after a
user signed in can never appear in that session's tokens. No amount of refreshing
helps; the session has to ask for the enlarged grant explicitly. Deploying a new
permission therefore leaves every existing session unable to hold it.

That case is detected rather than papered over. The module records which permission list
a session was granted and compares it on each request:

```vue
<script setup lang="ts">
const auth = useAuthorization()
const session = useLogtoSession()

await auth.resolve()
</script>

<template>
  <button v-if="auth.needsReauthorization.value" @click="session.reauthorize()">
    New permissions are available — reconnect
  </button>
</template>
```

`reauthorize()` starts a fresh authorization request. An already-signed-in user is not
asked for credentials again; they return with a grant covering the current list, and the
flag clears. Nothing redirects automatically — when to interrupt the user is the app's
call.

The cost is one refresh-token exchange per owned resource, per window, per active
session. `revalidateAfter: 0` disables revalidation entirely and reuses tokens until
they expire, which is how the module behaved before this existed;
`detectStaleGrant: false` drops the flag and its one extra cookie field.

### Route guards

```ts
// app/middleware/assessment-editor.ts
export default defineAuthMiddleware({ permissions: ['assessment:edit'] })
```

Unauthenticated visitors are redirected to your Logto sign-in path; authenticated but
unauthorised ones get a 403. Pass `redirectTo` to override the destination, or
`redirectUnauthenticated: false` to make a missing session a 401 like any other
failure. Skipped during prerendering, since a prerendered page has no request-bound
user and gating it would bake one visitor's verdict into shared HTML.

---

## Abilities

Guards work in a route handler but cannot drive a template. Abilities give you one
object usable in both, via `nuxt-authorization`.

Declare them in **`shared/utils/`**, which Nuxt auto-imports into the app *and* the
server. Files at the `shared/` root are not auto-imported — those need `#shared/…`.

```ts
// shared/utils/abilities.ts
export const gates = definePermissionGates({
  viewAssessment: 'assessment:view',                            // a single permission
  manageAssessment: ['assessment:edit', 'assessment:delete'],   // ALL of them
  reviewAssessment: { anyPermission: ['assessment:edit', 'assessment:share'] },
  verifiedEditor: { permissions: ['assessment:edit'], verified: true },
  admin: { roles: ['Admin'] },
})
```

Entries take the **same `AuthRequirements` vocabulary** as the guards, with a bare
string or array as shorthand for "all of these permissions". Keys are preserved, so
`gates.viewAssessment` autocompletes.

### In routes

```ts
export default defineEventHandler(async (event) => {
  await authorize(event, gates.viewAssessment)
  return listAssessments()
})
```

### In templates

Gates take no arguments, so no `:args` is needed:

```vue
<Can :ability="gates.manageAssessment">
  <button>Delete</button>
</Can>

<Cannot :ability="gates.manageAssessment">
  <p>You cannot edit this.</p>
</Cannot>

<!-- An array requires every ability to pass -->
<Can :ability="[gates.viewAssessment, gates.admin]">…</Can>

<Bouncer :ability="gates.reviewAssessment">
  <template #can>…</template>
  <template #cannot>…</template>
</Bouncer>
```

### Individual factories

For one-offs, without the map:

```ts
export const canView = definePermissionAbility('assessment:view')
export const canReview = defineAnyPermissionAbility('assessment:edit', 'assessment:share')
export const verifiedEditor = defineRequirementsAbility({
  permissions: ['assessment:edit'],
  verified: true,
})
export const isAdmin = defineRoleAbility('Admin')
export const isOrgOwner = defineOrganizationRoleAbility('org_123', 'owner')
```

### Your own abilities, and composition

Permission checks are only half of real authorization — ownership matters too. Write
those as ordinary abilities; `ctxHasAll` and friends are auto-imported:

```ts
// shared/utils/abilities.ts
export const editOwnAssessment = defineAbility(
  (user: AuthContext, assessment: Assessment) =>
    ctxHasAll(user, 'assessment:edit') && assessment.ownerId === user.userId,
)

// "own it, or hold the override permission, or be an admin"
export const editAssessment = anyOfAbilities(
  editOwnAssessment,
  gates.manageAssessment,
  gates.admin,
)
```

| Combinator | Behaviour |
| --- | --- |
| `anyOfAbilities(…)` | OR. Propagates the first denial verbatim, keeping its status code |
| `allOfAbilities(…)` | AND. Rarely needed in templates, where an array already means AND |
| `notAbility(a)` | Inverts. Note guests then **pass**, so treat it as UI sugar, not a boundary |

Both combinators **deny when given no abilities**, so an accidentally empty list can
never authorize.

### 401 versus 403

Gates report **401** when nobody is signed in and **403** when a user is signed in but
unauthorised, matching the guards. `nuxt-authorization` would otherwise flatten both
into a 403, making it impossible for a client to choose between "redirect to sign-in"
and "show a forbidden message".

---

## Calling other services

Resources belonging to *other* services go in `additionalResources`. They are
requested at sign-in so a token can be minted, but are **never** a valid inbound
audience and **never** contribute permissions:

```ts
logtoRbac: {
  resources: ['https://tc-manifold.ctrl-neo.dev/api/v1'],

  additionalResources: [
    'https://sibling.ctrl-neo.dev/api/v1',
    // Object form when you need that service's own scopes, which must not be added
    // to `permissions` or they would pollute this app's `Permission` union.
    { resource: 'https://other.ctrl-neo.dev/api/v1', scopes: ['other:read'] },
  ],

  permissions: ['assessment:view'],
}
```

```ts
const token = await useLogtoAccessToken(event, 'https://sibling.ctrl-neo.dev/api/v1')
await $fetch('https://sibling.ctrl-neo.dev/api/v1/things', {
  headers: { authorization: `Bearer ${token}` },
})
```

**Why the two lists are separate.** An access token's `aud` states which API it was
minted for, and verifying it is what stops a token for one service being replayed
against another. If a sibling's resource were accepted as a valid audience here, a
token minted for that sibling would be honoured by this app — and because scope names
realistically overlap between services in the same suite (`assessment:view` and
friends), it could satisfy a permission check it was never intended for. Keeping
"resources I can get tokens for" apart from "audiences I accept" removes that class
of bug by construction.

---
## Server utilities

| Helper | Purpose |
| --- | --- |
| `useAuthContext(event)` | the caller, from a session cookie **or** a verified bearer token; memoised per request |
| `useSessionAuthContext(event)` | session cookie only |
| `refreshAuthContext(event)` | drop cached tokens and re-read, after a role change |
| `verifyAccessToken(token, event?)` | verify an arbitrary Logto JWT (JWKS, `iss`, `aud`, `exp`) |
| `useLogtoAccessToken(event, resource)` | token for calling another configured service |
| `useOwnedResources(event?)` | resources this app owns, i.e. the accepted audiences |
| `useServerLogtoUserInfo(event)` | on-demand `custom_data` / `identities` fetch |
| `useServerLogtoUser(event)` | ID-token claims, free from the session cookie |
| `checkRequirements(ctx, reqs)` | pure check returning *why* it failed |
| `ctxSatisfies(ctx, reqs)` | pure boolean form, null-safe |

`AuthContext` is the normalised shape both sides share:

```ts
{
  isAuthenticated: boolean
  source: 'session' | 'bearer' | 'anonymous'
  userId?: string
  roles: string[]
  scopes: string[]
  organizations: string[]
  organizationRoles: Record<string, string[]>
  /** Always present; all-`null` for a guest, sparse (`sub` only) for a bearer caller. */
  profile: LogtoUserProfile
  /** Resolved server-side so the browser evaluates the same `verified` rule. */
  isVerified?: boolean
}
```

---

## Logto console setup

Code alone is not enough:

1. Create an API resource whose indicator **exactly matches** an entry in `resources`.
2. Add each permission to that resource.
3. Create roles, grant them permissions, assign roles to users.
4. **Sign in again.** Scopes are granted to the refresh token at sign-in and cannot be
   added afterwards, so existing sessions will never see new permissions.

### `invalid_target` — two different causes

```
error=invalid_target ... resource indicator is missing, or unknown
```

Logto sends the **same** code for two unrelated problems, and only one is a
misconfiguration. Which endpoint rejected it tells you which:

| Where it appears | Meaning | Fix |
| --- | --- | --- |
| At the **sign-in callback** | the indicator is not registered in Logto | fix `resources` / the console |
| In the **server log** while resolving permissions | the resource *is* registered, but this session's refresh token predates it | **sign out and sign in again** |

The second case is easy to misread as the first. Resources and scopes are bound to the
refresh token when it is issued, so adding a resource to `logtoRbac.resources` leaves
every existing session unable to exchange for a token against it — Logto reports the
resource as "unknown" *for that token* even though the authorization endpoint accepts
the very same string. The module tells the two apart and prints the right advice.

For the first case, check for a leftover placeholder, a typo, or a trailing slash. The
module warns at build time when a resource looks like a placeholder.

### Sign-in fails with `invalid_scope`

A permission in `logtoRbac.permissions` does not exist on the resource it belongs to.
Add it in the Logto console, or remove it from the config.

---

## Things that will bite you

- **A trailing slash on a resource makes it a different resource to Logto**, which
  surfaces as a silently empty `scope` claim rather than an error. The module warns
  about this at build time.
- **Every resource must exist in the Logto console.** An unregistered indicator fails
  sign-in outright with `invalid_target`; see above.
- **Put other services' resources in `additionalResources`, not `resources`.**
  Everything in `resources` is an accepted inbound audience.
- **Multiple owned resources cost one access token each.** Permissions are the union
  across them, fetched in parallel, and every token is cached in the encrypted session
  cookie keyed `"<sorted scopes>@<resource>"` — a long list can approach the ~4KB
  cookie limit, and a cold session needs one refresh-token exchange per resource.
- **Prefer permissions over roles.** Roles reach your app through the **ID token**, so
  a bearer caller (another service presenting an access token) normally carries none
  and will fail `roles` requirements. Logto role names are also mutable display
  strings that can be renamed in the console. Since a role in Logto is just a bundle
  of permissions, a permission check tests the same thing more durably — and works for
  both caller types. If you do need roles service-to-service, add a `roles` claim to
  your access tokens with a Logto JWT customizer; the module honours it when present.
- **`verified` defaults to `true`.** An unverified caller is rejected unless you pass
  `verified: false`, so forgetting to consider it fails closed. It still will not
  reject a **bearer** caller: `email_verified` is an ID-token claim, and an absent
  claim counts as verified rather than unverified — otherwise the default would lock
  out every service-to-service call.
- **Roles and permissions are a snapshot** from token issue time (typically one hour).
  Use `refreshAuthContext()` to apply a role change immediately.
- **Never trust `getAccessTokenClaims` for inbound tokens.** It is a base64 decode with
  no signature check. `verifyAccessToken` / `useAuthContext` do the real verification.
- **Keep `fetchUserInfo` off** (the default). Roles are an ID-token claim, so enabling
  it buys nothing for RBAC and costs a network round-trip per request.

---

## Module options

```ts
logtoRbac: {
  resources: [],                           // required: resources this app owns
  additionalResources: [],                 // other services, for outbound calls
  permissions: [],                         // sole source of the `Permission` type
  userScopes: [],                          // extra Logto user scopes
  sessionEndpoint: '/api/_auth/session',   // default
  revalidateAfter: 300,                    // seconds; 0 disables revalidation
  detectStaleGrant: true,                  // default: report `needsReauthorization`
  installAuthorizationModule: true,        // default
}
```

---

## Migrating a project that inlined this logic

If you previously hand-rolled these utilities, install the module and add the
`logtoRbac` block, then delete:

- `shared/rbac.ts`
- `server/utils/**` RBAC helpers (`useServerLogto*`, auth context, verify, guards)
- `server/plugins/authorization.ts`
- your session endpoint (e.g. `server/api/v1/auth/session.get.ts`)
- `app/plugins/authorization-resolver.ts`
- any root `logto.d.ts` `#logto` shim (the module ships one)
- the direct `jose` dependency (the module owns it)
- the manual `scopes` / `resources` block in `nuxt.config.ts`

Keep your post-callback route, repointed at the module's auto-imports. If your session
endpoint path was public API, set `sessionEndpoint` to preserve it.

---

## Development

```bash
pnpm install
pnpm dev          # playground
pnpm test
pnpm test:types
pnpm prepack
```

## License

MIT
