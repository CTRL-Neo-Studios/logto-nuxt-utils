# @type32/logto-nuxt-utils

Logto RBAC for Nuxt: declare your permissions once, get typed guards, and verify
tokens between services.

Logto splits authorization data across two places that its documentation never
states plainly. This module hides that split behind one config file and one
context shape.

| What you want | Where Logto actually puts it |
| --- | --- |
| Role *names* | the `roles` claim of the **ID token**, and only if the `roles` scope was requested |
| Permissions | the `scope` claim of a **resource-scoped access token**, never in the ID token or userinfo |
| Org roles | the `organization_roles` claim, as `orgId:roleName` |

## Install

```bash
pnpm add @type32/logto-nuxt-utils @logto/nuxt
```

`nuxt-authorization` is registered for you. `@logto/nuxt` is not, because you must
configure its credentials in `nuxt.config` anyway.

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

Note the `logto` block declares **no `scopes` and no `resources`**. The module
derives both from `logtoRbac`, which is the entire point — the permission list is
written once.

### Keeping the catalogue in its own file

No framework helper is needed; plain TypeScript is enough:

```ts
// rbac.ts
export const PERMISSIONS = [
  'assessment:create',
  'assessment:view',
] as const
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

### Calling other services

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
token minted for that sibling would be honoured by this app — and because scope
names realistically overlap between services in the same suite (`assessment:view`
and friends), it could satisfy a permission check it was never intended for. Keeping
"resources I can get tokens for" apart from "audiences I accept" removes that class
of bug by construction.


## Usage

Guards are auto-imported in server routes, and permission arguments are typed as
the literal union inferred from your config — a typo is a compile error, not a
silent always-deny.

```ts
// server/api/assessments/index.get.ts
export default defineEventHandler(async (event) => {
  const ctx = await requirePermission(event, 'assessment:list')
  return listAssessmentsFor(ctx.userId)
})
```

| Helper | Behaviour |
| --- | --- |
| `requireUser` | 401 if not authenticated |
| `requirePermission` | 401, else 403 unless **all** listed permissions are held |
| `requireAnyPermission` | 401, else 403 unless **one** is held |
| `requireRole` | 401, else 403 unless one role matches |
| `hasPermission` | non-throwing boolean, for branching |
| `useAuthContext` | the caller, from a session cookie **or** a verified bearer token |
| `useSessionAuthContext` | session cookie only |
| `refreshAuthContext` | drop cached tokens and re-read, after a role change |
| `verifyAccessToken` | verify an arbitrary Logto JWT (JWKS, `iss`, `aud`, `exp`) |
| `useLogtoAccessToken` | get a token for calling another configured service |
| `useOwnedResources` | resources this app owns, i.e. the accepted audiences |
| `useServerLogtoUserInfo` | on-demand `custom_data` / `identities` fetch |

403 responses carry `data: { required, missing }` so a client can see *which*
permission was missing.

### Client side

The browser cannot read its own permissions — they live in an access token inside
an httpOnly cookie — so the module exposes a session endpoint
(`/api/_auth/session` by default) and wires `nuxt-authorization`'s
`resolveClientUser` to it. `<Can>` and `<Bouncer>` therefore just work.

## Logto console setup

Code alone is not enough:

1. Create an API resource whose indicator **exactly matches** `resource`.
2. Add each permission to that resource.
3. Create roles, grant them permissions, assign roles to users.
4. **Sign in again.** Scopes are granted to the refresh token at sign-in and
   cannot be added afterwards, so existing sessions will never see new
   permissions.

## Things that will bite you

- **A trailing slash on a resource makes it a different resource to Logto**, which
  surfaces as a silently empty `scope` claim rather than an error. The module warns
  about this at build time.
- **Put other services' resources in `additionalResources`, not `resources`.**
  Everything in `resources` is an accepted inbound audience; see the rationale
  above.
- **Multiple owned resources cost one access token each.** Permissions are the union
  across them, fetched in parallel, and every token is cached in the encrypted
  session cookie keyed `"<sorted scopes>@<resource>"` — a long list can approach the
  ~4KB cookie limit, and a cold session needs one refresh-token exchange per
  resource.
- **Prefer permissions over roles.** Access tokens carry no `roles` claim, so
  `requireRole` always rejects a sibling service using a bearer token. Logto role
  names are also mutable display strings that can be renamed in the console.
- **Roles and permissions are a snapshot** from token issue time (typically one
  hour). Use `refreshAuthContext()` to apply a role change immediately.
- **Never trust `getAccessTokenClaims` for inbound tokens.** It is a base64 decode
  with no signature check. `verifyAccessToken` / `useAuthContext` do the real
  verification.
- **Keep `fetchUserInfo` off** (the default). Roles are an ID-token claim, so
  enabling it buys nothing for RBAC and costs a network round-trip per request.

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

Keep your post-callback route, repointed at the module's auto-imports. If your
session endpoint path was public API, set `sessionEndpoint` to preserve it.

## Development

```bash
pnpm install
pnpm dev          # playground
pnpm test:types
pnpm prepack
```

## License

MIT
