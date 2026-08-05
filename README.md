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

Guards are auto-imported. They resolve the caller once per request and throw H3
errors carrying machine-readable `data`.

```ts
// server/api/assessments/index.get.ts
export default defineEventHandler(async (event) => {
  const ctx = await requirePermission(event, 'assessment:list')
  return listAssessmentsFor(ctx.userId)
})
```

| Guard | Behaviour |
| --- | --- |
| `requireUser(event)` | 401 if not authenticated |
| `requirePermission(event, …perms)` | 401, else 403 unless **all** are held |
| `requireAnyPermission(event, …perms)` | 401, else 403 unless **one** is held |
| `requireRole(event, …roles)` | 401, else 403 unless one role matches |
| `hasPermission(event, …perms)` | non-throwing boolean, for branching |

403 responses include `data: { required, missing }` so a client can see *which*
permission was missing.

---

## Abilities

Guards are convenient in a route handler, but they cannot drive a template. Abilities
give you one object usable in both places, via `nuxt-authorization`.

Declare them in **`shared/utils/`**, which Nuxt auto-imports into the app *and* the
server. Files at the `shared/` root are not auto-imported — those need `#shared/…`.

```ts
// shared/utils/abilities.ts
export const gates = definePermissionGates({
  viewAssessment: 'assessment:view',                            // a single permission
  manageAssessment: ['assessment:edit', 'assessment:delete'],   // ALL of them
  reviewAssessment: { any: ['assessment:edit', 'assessment:share'] },
  auditAssessment: { all: ['assessment:view', 'assessment:list'] },
  admin: { roles: ['Admin'] },
  orgOwner: { organizationId: 'org_123', roles: ['owner'] },
})
```

A bare string or array is shorthand for "all of these permissions"; anything else is
spelled out. Keys are preserved, so `gates.viewAssessment` autocompletes.

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
lacks the permission, matching the guards. `nuxt-authorization` would otherwise
flatten both into a 403, which makes it impossible for a client to decide between
"redirect to sign-in" and "show a forbidden message".

---

## Client-side state

The browser cannot read its own permissions — they live in an access token inside an
httpOnly cookie — so the module exposes a session endpoint (`/api/_auth/session` by
default) and wires `nuxt-authorization`'s `resolveClientUser` to it. `<Can>` and
`<Bouncer>` therefore work with no extra setup.

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
| `useAuthContext(event)` | the caller, from a session cookie **or** a verified bearer token |
| `useSessionAuthContext(event)` | session cookie only |
| `refreshAuthContext(event)` | drop cached tokens and re-read, after a role change |
| `verifyAccessToken(token, event?)` | verify an arbitrary Logto JWT (JWKS, `iss`, `aud`, `exp`) |
| `useLogtoAccessToken(event, resource)` | token for calling another configured service |
| `useOwnedResources(event?)` | resources this app owns, i.e. the accepted audiences |
| `useServerLogtoUserInfo(event)` | on-demand `custom_data` / `identities` fetch |
| `useServerLogtoUser(event)` | ID-token claims, free from the session cookie |

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

---

## Things that will bite you

- **A trailing slash on a resource makes it a different resource to Logto**, which
  surfaces as a silently empty `scope` claim rather than an error. The module warns
  about this at build time.
- **Put other services' resources in `additionalResources`, not `resources`.**
  Everything in `resources` is an accepted inbound audience.
- **Multiple owned resources cost one access token each.** Permissions are the union
  across them, fetched in parallel, and every token is cached in the encrypted session
  cookie keyed `"<sorted scopes>@<resource>"` — a long list can approach the ~4KB
  cookie limit, and a cold session needs one refresh-token exchange per resource.
- **Prefer permissions over roles.** Access tokens carry no `roles` claim, so
  `requireRole` and role abilities always reject a sibling service using a bearer
  token. Logto role names are also mutable display strings that can be renamed in the
  console.
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
