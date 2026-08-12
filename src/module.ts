import { relative, resolve } from 'node:path'
import {
  addImports,
  addPlugin,
  addServerHandler,
  addServerImports,
  addServerImportsDir,
  addServerPlugin,
  addTypeTemplate,
  createResolver,
  defineNuxtModule,
  hasNuxtModule,
  installModule,
  useLogger,
} from '@nuxt/kit'

/**
 * A resource this app wants tokens for but does **not** own.
 *
 * The object form exists so another service's scopes can be requested without
 * adding them to `permissions` — which would wrongly pull them into this app's own
 * `Permission` union.
 */
export type AdditionalResource =
  | string
  | {
    /** The other service's API resource indicator. */
    resource: string
    /** Scopes to request for it, if it defines any you need. */
    scopes?: readonly string[]
  }

/**
 * Module options, configured under the `logtoRbac` key in `nuxt.config`.
 *
 * The RBAC surface lives here rather than in a separate config file, so Nuxt
 * handles typing, layer merging and dev restarts on change for free.
 *
 * A large permission catalogue does not have to live inline — plain TypeScript is
 * enough to keep it in its own file:
 *
 * ```ts
 * // rbac.ts
 * export const PERMISSIONS = ['assessment:view', 'assessment:edit'] as const
 *
 * // nuxt.config.ts
 * import { PERMISSIONS } from './rbac'
 * export default defineNuxtConfig({
 *   logtoRbac: { resources: ['https://…/api/v1'], permissions: [...PERMISSIONS] },
 * })
 * ```
 */
export interface ModuleOptions {
  /**
   * Indicators of the Logto API resources this app **owns**.
   *
   * These are *identifiers*, not endpoints Logto ever calls, so the production URL
   * is normally used in development too. Each must match the value configured in the
   * Logto console byte-for-byte.
   *
   * A trailing slash makes it a *different* resource to Logto, which surfaces as a
   * silently empty `scope` claim rather than an error; the module warns about this at
   * build time.
   *
   * Two consequences of listing more than one:
   *
   * - Permissions are unioned across all of them, which costs one access token per
   *   resource. Each is cached in the encrypted session cookie, so a long list can
   *   approach the ~4KB cookie limit.
   * - **All of them are accepted as the `aud` of an inbound bearer token.** Only list
   *   resources this app actually serves; resources belonging to other services go in
   *   {@link ModuleOptions.additionalResources}, otherwise a token minted for another
   *   service would be accepted here.
   *
   * @example ['https://tc-manifold.ctrl-neo.dev/api/v1']
   */
  resources?: readonly string[]
  /**
   * Resources belonging to *other* services, requested at sign-in so this app can
   * call them.
   *
   * Deliberately kept apart from {@link ModuleOptions.resources}: entries here are
   * never a valid inbound audience and never contribute to this app's permissions.
   * Retrieve a token for one with `useLogtoAccessToken(event, resource)`.
   */
  additionalResources?: readonly AdditionalResource[]
  /**
   * Every permission this app's own API resources define.
   *
   * Each entry must exist verbatim as a permission in the Logto console. Logto
   * silently omits scopes it does not recognise from the issued access token rather
   * than erroring, so a typo shows up as a mysteriously missing permission.
   *
   * This list is the sole source of the `Permission` type.
   */
  permissions?: readonly string[]
  /**
   * Additional Logto user scopes to request beyond the defaults.
   *
   * The module always requests `roles`, `email` and `profile`. Add
   * `'urn:logto:scope:organizations'` and `'urn:logto:scope:organization_roles'` here
   * if you need organization data in the token claims.
   */
  userScopes?: readonly string[]
  /**
   * Route the session endpoint is mounted at.
   *
   * The browser cannot read its own permissions — they live in the `scope` claim of
   * an access token inside an httpOnly cookie — so this endpoint is what makes
   * client-side ability checks possible.
   */
  sessionEndpoint?: string
  /**
   * How long a resolved session context may be reused before its resource tokens are
   * re-fetched from Logto, in **seconds**.
   *
   * Logto reflects *reduced* grants on the next token issuance, but a cached access
   * token is reused until its own expiry (default one hour), so a revoked permission
   * keeps working until then. Within this window the cached token is used; past it,
   * the cached access token is discarded and a refresh grant is performed, which also
   * refreshes the stored ID token and therefore the `roles` claim.
   *
   * Costs one refresh-token exchange per owned resource per window per active session.
   * Set to `0` to disable revalidation and reuse tokens until they expire.
   */
  revalidateAfter?: number
  /**
   * Detect sessions whose grant predates the current permission list.
   *
   * A permission that was not requested at sign-in can never be obtained by a refresh
   * grant — Logto only issues scopes from the original authorization request — so
   * deploying a new permission leaves existing sessions permanently unable to hold it.
   * When enabled, the module records the requested permission set at the sign-in
   * callback and sets `needsReauthorization` on the context once it no longer matches,
   * so the app can prompt for re-authorization instead of silently denying.
   */
  detectStaleGrant?: boolean
  /**
   * Register `nuxt-authorization` automatically.
   *
   * It requires no configuration of its own, so installing it here saves consumers
   * a line. `@logto/nuxt` is deliberately *not* auto-installed, since you must
   * configure its endpoint, credentials and pathnames in `nuxt.config` regardless —
   * it should stay visible there.
   */
  installAuthorizationModule?: boolean
  /**
   * Register the client-side `$authorization` resolver plugin.
   *
   * Set to `false` when the consuming project supplies its own
   * `plugins/authorization-resolver.ts`. Nuxt's `provide` defines a
   * non-configurable property, so two plugins providing `authorization` make the
   * second one throw `Cannot redefine property: $authorization`.
   *
   * Leaving this `true` is safe: the module detects a consumer-supplied resolver at
   * build time and steps aside automatically. Setting it to `false` silences the
   * warning that detection emits.
   */
  installClientResolver?: boolean
}

/**
 * User scopes always requested.
 *
 * `roles` is what populates the `roles` ID-token claim; without it the claim is
 * absent entirely (`undefined`, not an empty array). It grants no permissions of
 * its own — it merely discloses role names.
 *
 * These are the literal values of `UserScope.Roles` / `.Email` / `.Profile` from
 * `@logto/nuxt`. They are inlined rather than imported because `@logto/nuxt` is a
 * peer dependency whose root export is itself a Nuxt module; importing it here
 * would make this module hard-fail when the peer is missing, instead of emitting the
 * actionable warning below.
 */
const BASE_USER_SCOPES = ['roles', 'email', 'profile'] as const

/** This package's own name, used for the generated type augmentation. */
const PACKAGE_NAME = '@type32/logto-nuxt-utils'

/**
 * Markers of a resource indicator that was never filled in.
 *
 * Deliberately narrow: these are strings nobody uses for a real Logto API resource,
 * so matching one is a near-certain misconfiguration rather than a style preference.
 */
const PLACEHOLDER_PATTERN = /example\.(?:com|org|net)|replace-?me|your-?(?:app|domain|tenant)/iu

/**
 * The slice of `runtimeConfig.logto` this module writes to.
 *
 * Declared locally because the type Nuxt generates for that key is derived from
 * whatever the consuming app sets in its own config, so it cannot be relied on
 * structurally from here.
 */
interface MutableLogtoRuntimeConfig {
  scopes?: string[]
  resources?: string[]
  fetchUserInfo?: boolean
  pathnames?: { signIn?: string, signOut?: string }
}

function unique(values: Iterable<string>): string[] {
  return [...new Set(values)].filter(Boolean)
}

export default defineNuxtModule<ModuleOptions>({
  meta: {
    name: PACKAGE_NAME,
    configKey: 'logtoRbac',
    compatibility: { nuxt: '>=4.0.0' },
  },
  defaults: {
    resources: [],
    additionalResources: [],
    permissions: [],
    userScopes: [],
    sessionEndpoint: '/api/_auth/session',
    revalidateAfter: 300,
    detectStaleGrant: true,
    installAuthorizationModule: true,
    installClientResolver: true,
  },
  async setup(options, nuxt) {
    const logger = useLogger('logto-rbac')
    const resolver = createResolver(import.meta.url)
    const sessionEndpoint = options.sessionEndpoint ?? '/api/_auth/session'

    if (!hasNuxtModule('@logto/nuxt', nuxt)) {
      logger.warn(
        '`@logto/nuxt` is not registered. Add it to `modules` in nuxt.config, otherwise '
        + 'no session or permission can ever be resolved.',
      )
    }

    // ---------------------------------------------------------------- config

    const ownedResources = unique((options.resources ?? []).map(entry => entry.trim()))
    const additionalResources = (options.additionalResources ?? [])
      .map(entry => (typeof entry === 'string' ? { resource: entry } : entry))
      .map(entry => ({ resource: entry.resource.trim(), scopes: unique(entry.scopes ?? []) }))
      .filter(entry => entry.resource.length > 0)
    const additionalResourceIndicators = unique(additionalResources.map(entry => entry.resource))
    const permissions = unique(options.permissions ?? [])
    const revalidateAfter = Math.max(0, Math.trunc(options.revalidateAfter ?? 300))

    if (ownedResources.length === 0) {
      logger.warn(
        'No `logtoRbac.resources` configured. Permissions will not be requested and '
        + '`Permission` will fall back to `string`.',
      )
    }
    else {
      // A trailing slash makes it a *different* resource to Logto, which surfaces as
      // a silently empty `scope` claim rather than an error — worth catching here.
      for (const resource of [...ownedResources, ...additionalResourceIndicators]) {
        if (resource.endsWith('/')) {
          logger.warn(
            `The API resource "${resource}" ends with a trailing slash. Logto treats that `
            + 'as a different resource, which shows up as an empty `scope` claim. Remove it '
            + 'unless the Logto console really is configured with the slash.',
          )
        }

        // Every resource is sent as an RFC 8707 `resource` parameter and validated by
        // Logto against its registered API resources. An unregistered one fails the
        // entire authorization request with `invalid_target`, and that surfaces at the
        // sign-in callback far from this config — so catch a leftover placeholder now.
        if (PLACEHOLDER_PATTERN.test(resource)) {
          logger.warn(
            `The API resource "${resource}" looks like a placeholder. Logto rejects any `
            + 'resource not registered in its console with "invalid_target: resource '
            + 'indicator is missing, or unknown", which appears at the sign-in callback '
            + 'rather than here.',
          )
        }
      }

      // Listing a resource in both places is almost certainly a mistake: being in
      // `resources` already makes it a valid inbound audience, so the entry in
      // `additionalResources` achieves nothing and muddies the intent.
      for (const resource of additionalResourceIndicators) {
        if (ownedResources.includes(resource)) {
          logger.warn(
            `"${resource}" appears in both \`resources\` and \`additionalResources\`. It is `
            + 'being treated as owned, which means inbound tokens for it are accepted. '
            + 'Remove it from one of the two lists.',
          )
        }
      }

      if (permissions.length === 0) {
        logger.warn(
          'No `logtoRbac.permissions` declared; only role names will be available.',
        )
      }
    }

    // ------------------------------------------------- logto config injection

    /**
     * Injected in `modules:done` so it runs after `@logto/nuxt`'s own setup.
     *
     * That module computes `defu(runtimeConfig.logto, options, defaults)` and assigns
     * the result. Mutating the finished object afterwards gives deterministic control
     * over de-duplication, and `runtimeConfig` is not serialised until much later in
     * the build, so the change still lands.
     *
     * This is what removes the need to restate permissions in `nuxt.config`'s `logto`
     * block.
     */
    nuxt.hook('modules:done', () => {
      const runtimeConfig = nuxt.options.runtimeConfig as unknown as {
        logto?: MutableLogtoRuntimeConfig
      }
      const logto = (runtimeConfig.logto ||= {})

      if (logto.fetchUserInfo === true) {
        logger.warn(
          '`logto.fetchUserInfo` is enabled, which costs a network round-trip to the '
          + 'userinfo endpoint on every request that touches Logto. Roles are an ID-token '
          + 'claim and do not need it; use `useServerLogtoUserInfo()` for `custom_data` '
          + 'or `identities` instead.',
        )
      }

      logto.scopes = unique([
        ...(logto.scopes ?? []),
        ...BASE_USER_SCOPES,
        ...(options.userScopes ?? []),
        ...permissions,
        // Another service's scopes must be granted for this app to call it, but they
        // are deliberately absent from `permissions` so they never leak into this
        // app's own `Permission` union.
        ...additionalResources.flatMap(entry => entry.scopes),
      ])

      // Every resource must be requested at sign-in for a token to be obtainable,
      // owned or not. Which of them count as valid inbound audiences is a separate
      // question, answered by `runtimeConfig.logtoRbac.resources` below.
      logto.resources = unique([
        ...(logto.resources ?? []),
        ...ownedResources,
        ...additionalResourceIndicators,
      ])

      // Mirrored into public config so client-side guards can send an unauthenticated
      // visitor to sign in. The Logto pathnames themselves live in private runtime
      // config, so the browser has no other way to discover it.
      nuxt.options.runtimeConfig.public.logtoRbac.signInPath
        = logto.pathnames?.signIn ?? '/sign-in'
      nuxt.options.runtimeConfig.public.logtoRbac.signOutPath
        = logto.pathnames?.signOut ?? '/sign-out'
    })

    /**
     * The owned resources and freshness policy, published privately for the server
     * runtime.
     *
     * The resource list cannot be derived from `logto.resources`, which intentionally
     * also holds other services' resources. Keeping the owned list separate is what
     * stops a token minted for another service from being accepted here as though it
     * were meant for us.
     */
    nuxt.options.runtimeConfig.logtoRbac = {
      resources: ownedResources,
      revalidateAfter,
      detectStaleGrant: options.detectStaleGrant !== false,
      // Sorted so the fingerprint is order-insensitive: reordering `permissions` in
      // nuxt.config must not invalidate every live session.
      permissions: [...permissions].sort(),
    }

    // Exposed publicly so the client plugin knows where to resolve the session, so
    // client-side guards can redirect to sign-in, and so the client can expire its own
    // cached verdict on the same schedule as the server. `signInPath` is filled in
    // during `modules:done`, once @logto/nuxt has resolved its own defaults.
    nuxt.options.runtimeConfig.public.logtoRbac = {
      sessionEndpoint,
      signInPath: '/sign-in',
      signOutPath: '/sign-out',
      revalidateAfter,
    }

    // -------------------------------------------------------------- wiring

    if (options.installAuthorizationModule && !hasNuxtModule('nuxt-authorization', nuxt)) {
      await installModule('nuxt-authorization')
    }

    // Guards and Logto helpers, auto-imported in server routes.
    addServerImportsDir(resolver.resolve('./runtime/server/utils'))

    // The shared predicates are imported by name rather than by directory, so that
    // generic helpers like `toStringArray` do not silently occupy consumers'
    // auto-import namespace.
    const sharedPredicates = [
      'ctxHasAll',
      'ctxHasAny',
      'ctxHasRole',
      'ctxMissingPermissions',
      'ctxHasOrganizationRole',
      'createAnonymousContext',
    ]
    const sharedCore = resolver.resolve('./runtime/shared/core')
    addImports(sharedPredicates.map(name => ({ name, from: sharedCore })))
    addServerImports(sharedPredicates.map(name => ({ name, from: sharedCore })))

    // The declarative requirements vocabulary, shared by guards, gates and the client.
    const requirementHelpers = [
      'checkRequirements',
      'ctxSatisfies',
      'ctxIsVerified',
      'toRequirements',
    ]
    const sharedRequirements = resolver.resolve('./runtime/shared/requirements')
    addImports(requirementHelpers.map(name => ({ name, from: sharedRequirements })))
    addServerImports(requirementHelpers.map(name => ({ name, from: sharedRequirements })))

    // Ability factories for `nuxt-authorization`. Registered in both contexts, since
    // the same ability is evaluated by `<Can>` on the client and `authorize(event, …)`
    // on the server. None of these names collide with the guards above or with
    // `nuxt-authorization`'s own `defineAbility` / `allow` / `deny` / `allows` /
    // `denies` / `authorize`.
    const abilityFactories = [
      'definePermissionGates',
      'definePermissionAbility',
      'defineAnyPermissionAbility',
      'defineRequirementsAbility',
      'defineRoleAbility',
      'defineOrganizationRoleAbility',
      'anyOfAbilities',
      'allOfAbilities',
      'notAbility',
    ]
    const sharedAbilities = resolver.resolve('./runtime/shared/abilities')
    addImports(abilityFactories.map(name => ({ name, from: sharedAbilities })))
    addServerImports(abilityFactories.map(name => ({ name, from: sharedAbilities })))

    // Client-only: reactive permission state and the route-guard factory.
    addImports([
      {
        name: 'useAuthorization',
        from: resolver.resolve('./runtime/app/composables/useAuthorization'),
      },
      {
        name: 'defineAuthMiddleware',
        from: resolver.resolve('./runtime/app/utils/auth-middleware'),
      },
      { name: 'useCan', from: resolver.resolve('./runtime/app/composables/useCan') },
      {
        name: 'useLogtoSession',
        from: resolver.resolve('./runtime/app/composables/useLogtoSession'),
      },
    ])

    addServerPlugin(resolver.resolve('./runtime/server/plugins/authorization'))

    addServerHandler({
      route: sessionEndpoint,
      method: 'get',
      handler: resolver.resolve('./runtime/server/api/session.get'),
    })

    const clientResolverSrc = resolver.resolve('./runtime/app/plugins/authorization-resolver')

    /**
     * Whether `src` is *this* module's client resolver.
     *
     * A prefix test rather than `===`: `resolveApp` runs `resolvePaths` over the
     * plugin list *before* it fires `app:resolve`, so by then `src` carries the
     * resolved extension (`…/authorization-resolver.ts`) while `resolver.resolve`
     * returns the extensionless path. An equality check would never match.
     */
    const isOwnClientResolver = (src: string): boolean =>
      src === clientResolverSrc || src.startsWith(`${clientResolverSrc}.`)

    if (options.installClientResolver !== false) {
      addPlugin(clientResolverSrc)

      /**
       * Steps aside when the project supplies its own client resolver.
       *
       * Nuxt's `provide` defines a non-configurable property, and module plugins are
       * unshifted ahead of scanned app plugins, so shipping ours unconditionally makes
       * the *consumer's* plugin throw `Cannot redefine property: $authorization`.
       *
       * `app:resolve` is the earliest hook where `app.plugins` holds both the module
       * plugins and the ones scanned from `app/plugins/`, which is what makes the
       * consumer's file detectable at all.
       */
      nuxt.hook('app:resolve', (app) => {
        const theirs = app.plugins.filter(
          plugin => !isOwnClientResolver(plugin.src)
            && /authorization-resolver/u.test(plugin.src),
        )

        if (theirs.length === 0) return

        app.plugins = app.plugins.filter(plugin => !isOwnClientResolver(plugin.src))

        logger.warn(
          'A project-level authorization resolver was found at '
          + `${theirs.map(plugin => relative(nuxt.options.rootDir, plugin.src)).join(', ')}, `
          + 'so this module\'s own client resolver was not registered — two plugins '
          + 'providing `authorization` would throw "Cannot redefine property: '
          + '$authorization". Your resolver is being used. Either delete it to use the '
          + 'module\'s Logto-backed resolver, or set `logtoRbac.installClientResolver: '
          + 'false` in nuxt.config to silence this warning.',
        )
      })
    }

    // --------------------------------------------------------------- types

    /**
     * Populates the permission registry with a generated literal union.
     *
     * The union has to be written out rather than inferred from `nuxt.config`:
     * `defineNuxtConfig` is typed as `(input: InputConfig<NuxtConfig>) =>
     * InputConfig<NuxtConfig>`, so it is not generic over its argument and the
     * literal types of `permissions` are widened to `string[]` on the way out.
     *
     * Generated code cannot go stale here, because editing `nuxt.config` restarts
     * Nuxt and regenerates this file.
     *
     * `Record<Union, true>` is a mapped type with statically known members, which an
     * interface may extend.
     *
     * The augmentation is emitted for two specifiers. The public subpath is what
     * consumers resolve. The second, a relative path to this module's own runtime
     * types, matters during module development: `nuxt-module-build --stub` makes
     * auto-imports resolve to `src/runtime/**`, whose `Permission` comes from
     * `src/runtime/types.ts` — a *different* module from the `dist` one the public
     * subpath resolves to, which would silently widen `Permission` back to `string`
     * in the playground.
     */
    addTypeTemplate({
      filename: 'types/logto-rbac.d.ts',
      getContents: () => {
        if (permissions.length === 0) {
          return [
            '// No `logtoRbac.permissions` configured, so `Permission` stays `string`.',
            'export {}',
            '',
          ].join('\n')
        }

        // JSON.stringify handles quoting and escaping, so a permission containing a
        // quote or backslash cannot break out of the generated type.
        const union = permissions.map(permission => JSON.stringify(permission)).join(' | ')

        const relativeRuntimeTypes = relative(
          resolve(nuxt.options.buildDir, 'types'),
          resolver.resolve('./runtime/types'),
        )
          .replace(/\\/gu, '/')
          .replace(/\.(?:ts|mts|cts|js|mjs|cjs|d\.ts)$/u, '')

        const specifiers = unique([
          `${PACKAGE_NAME}/types`,
          relativeRuntimeTypes.startsWith('.')
            ? relativeRuntimeTypes
            : `./${relativeRuntimeTypes}`,
        ])

        return [
          ...specifiers.flatMap(specifier => [
            `declare module '${specifier}' {`,
            `  interface RbacPermissionMap extends Record<${union}, true> {}`,
            `}`,
            '',
          ]),
          'export {}',
          '',
        ].join('\n')
      },
    // `Permission` is referenced by the server guards and by client-side abilities
    // alike, so the augmentation has to reach every TS project Nuxt generates, not
    // just the default `nuxt` one.
    }, { nitro: true, nuxt: true, node: true, shared: true })

    /**
     * Ambient declaration for `#logto`.
     *
     * `@logto/nuxt` registers that alias through Nitro, and although Nuxt does copy it
     * into the server project's `paths`, importing it still fails to resolve in
     * practice — reproduced across two separate projects. This declaration makes it
     * resolve deterministically in every context.
     *
     * The `config` parameter is intentionally permissive: the type Nuxt generates for
     * `runtimeConfig.logto` contains only the keys actually set in `nuxt.config`,
     * whereas the package's own `LogtoRuntimeConfig` marks further keys as required,
     * so the stricter type would reject a valid call.
     */
    addTypeTemplate({
      filename: 'types/logto-rbac-shims.d.ts',
      // No `export {}` here, deliberately. Adding one would turn this file into a
      // module, which downgrades `declare module '#logto'` from a new *ambient*
      // declaration into an *augmentation* of a module that cannot be resolved —
      // silently ineffective. It must stay a global script.
      getContents: () => [
        `declare module '#logto' {`,
        `  import type { H3Event } from 'h3'`,
        `  export function logtoEventHandler(`,
        `    event: H3Event,`,
        `    config: { logto: unknown },`,
        `  ): Promise<void>`,
        `}`,
        '',
      ].join('\n'),
    }, { nitro: true, nuxt: true, node: true, shared: true })
  },
})

declare module '@nuxt/schema' {
  interface RuntimeConfig {
    logtoRbac: {
      /**
       * API resources this app owns.
       *
       * The only values accepted as the `aud` of an inbound bearer token, and the
       * only resources whose scopes contribute to the caller's permissions.
       */
      resources: string[]
      /** Seconds a resolved context may be reused before resource tokens are re-fetched. */
      revalidateAfter: number
      /** Whether to flag sessions whose grant predates the current permission list. */
      detectStaleGrant: boolean
      /** Configured permissions, sorted, for the session grant fingerprint. */
      permissions: string[]
    }
  }

  interface PublicRuntimeConfig {
    logtoRbac: {
      /** Route the session endpoint is mounted at. */
      sessionEndpoint: string
      /** Logto sign-in path, mirrored from private config for client-side guards. */
      signInPath: string
      /** Logto sign-out path, mirrored from private config for client-side navigation. */
      signOutPath: string
      /** Seconds the client may reuse a resolved context before refetching it. */
      revalidateAfter: number
    }
  }
}
