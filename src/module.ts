import { relative } from 'node:path'
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
import { loadConfig } from 'c12'
import type { RbacConfig } from './runtime/types'

export interface ModuleOptions {
  /**
   * Path to the RBAC config file, relative to the project root.
   *
   * Defaults to discovering `rbac.config.{ts,mts,js,mjs}` at the project root.
   */
  configFile?: string
  /**
   * Route the session endpoint is mounted at.
   *
   * The browser cannot read its own permissions — they live in the `scope` claim
   * of an access token inside an httpOnly cookie — so this endpoint is what makes
   * client-side ability checks possible.
   */
  sessionEndpoint?: string
  /**
   * Register `nuxt-authorization` automatically.
   *
   * It requires no configuration of its own, so installing it here saves
   * consumers a line. `@logto/nuxt` is deliberately *not* auto-installed, since
   * you must configure its endpoint, credentials and pathnames in `nuxt.config`
   * regardless — it should stay visible there.
   */
  installAuthorizationModule?: boolean
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
 * would make this module hard-fail when the peer is missing, instead of emitting
 * the actionable warning below.
 */
const BASE_USER_SCOPES = ['roles', 'email', 'profile'] as const

/** This package's own name, used for the config alias and type augmentations. */
const PACKAGE_NAME = '@type32/logto-nuxt-utils'

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
    sessionEndpoint: '/api/_auth/session',
    installAuthorizationModule: true,
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

    const { config, configFile } = await loadConfig<Partial<RbacConfig>>({
      cwd: nuxt.options.rootDir,
      name: 'rbac',
      configFile: options.configFile,
      /**
       * Lets `rbac.config.ts` import `defineRbacConfig` from this package by name.
       *
       * c12 loads that file through jiti, which resolves via CommonJS. Without this
       * alias the import depends entirely on the published `exports` map, and in
       * particular breaks during development: `nuxt-module-build build --stub`
       * wipes `dist/` and emits only the module entry, so `dist/runtime/config.js`
       * does not exist.
       *
       * `resolver.resolve` points at `src/` when stubbed and `dist/` when built, so
       * one expression covers both.
       */
      jitiOptions: {
        alias: {
          [`${PACKAGE_NAME}/config`]: resolver.resolve('./runtime/config'),
        },
      },
    })

    const ownedResources = unique((config?.resources ?? []).map(entry => entry.trim()))
    const additionalResources = (config?.additionalResources ?? [])
      .map(entry => (typeof entry === 'string' ? { resource: entry } : entry))
      .map(entry => ({ resource: entry.resource.trim(), scopes: unique(entry.scopes ?? []) }))
      .filter(entry => entry.resource.length > 0)
    const additionalResourceIndicators = unique(additionalResources.map(entry => entry.resource))
    const permissions = unique(config?.permissions ?? [])
    const hasConfig = Boolean(configFile && ownedResources.length > 0)

    if (!configFile || ownedResources.length === 0) {
      logger.warn(
        'No `rbac.config.ts` with a non-empty `resources` array was found at the project '
        + 'root. Permissions will not be requested and `Permission` will fall back to '
        + '`string`.',
      )
    }
    else {
      // A trailing slash makes it a *different* resource to Logto, which surfaces
      // as a silently empty `scope` claim rather than an error — worth catching here.
      for (const resource of [...ownedResources, ...additionalResourceIndicators]) {
        if (resource.endsWith('/')) {
          logger.warn(
            `The API resource "${resource}" ends with a trailing slash. Logto treats that `
            + 'as a different resource, which shows up as an empty `scope` claim. Remove it '
            + 'unless the Logto console really is configured with the slash.',
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
        logger.warn(`No permissions declared in ${configFile}; only role names will be available.`)
      }

      // Re-run the build when the config changes, since scopes and types derive from it.
      nuxt.options.watch ||= []
      nuxt.options.watch.push(configFile)
    }

    // ------------------------------------------------- logto config injection

    /**
     * Injected in `modules:done` so it runs after `@logto/nuxt`'s own setup.
     *
     * That module computes `defu(runtimeConfig.logto, options, defaults)` and
     * assigns the result. Mutating the finished object afterwards gives
     * deterministic control over de-duplication, and `runtimeConfig` is not
     * serialised until much later in the build, so the change still lands.
     *
     * This is what removes the need to restate permissions in `nuxt.config`.
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
        ...(config?.userScopes ?? []),
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
    })

    /**
     * The owned resources, published privately for the server runtime.
     *
     * This cannot be derived from `logto.resources`, which intentionally also holds
     * other services' resources. Keeping the owned list separate is what stops a
     * token minted for another service from being accepted here as though it were
     * meant for us.
     */
    nuxt.options.runtimeConfig.logtoRbac = { resources: ownedResources }

    // Exposed publicly so the client plugin knows where to resolve the session.
    nuxt.options.runtimeConfig.public.logtoRbac = { sessionEndpoint }

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

    addServerPlugin(resolver.resolve('./runtime/server/plugins/authorization'))

    addServerHandler({
      route: sessionEndpoint,
      method: 'get',
      handler: resolver.resolve('./runtime/server/api/session.get'),
    })

    addPlugin(resolver.resolve('./runtime/app/plugins/authorization-resolver'))

    // --------------------------------------------------------------- types

    /**
     * Populates the permission registry by *inferring* from the consumer's config
     * file, rather than stringifying a union into generated code.
     *
     * Inference means the type can never drift from `rbac.config.ts`, and there is
     * no generated union to regenerate after an edit. `Record<Union, true>` is a
     * mapped type with statically known members, which an interface may extend.
     */
    addTypeTemplate({
      filename: 'types/logto-rbac.d.ts',
      getContents: () => {
        if (!hasConfig || permissions.length === 0) {
          return [
            '// No rbac.config.ts resolved, so `Permission` stays `string`.',
            'export {}',
            '',
          ].join('\n')
        }

        const specifier = relative(
          resolver.resolve(nuxt.options.buildDir, 'types'),
          configFile!,
        )
          .replace(/\\/gu, '/')
          .replace(/\.(?:ts|mts|cts|js|mjs|cjs)$/u, '')

        return [
          `declare module '${PACKAGE_NAME}/types' {`,
          `  interface RbacPermissionMap extends Record<`,
          `    (typeof import('${specifier}').default)['permissions'][number],`,
          `    true`,
          `  > {}`,
          `}`,
          '',
          'export {}',
          '',
        ].join('\n')
      },
    // `Permission` is referenced by the server guards and by client-side
    // abilities alike, so the augmentation has to reach every TS project Nuxt
    // generates, not just the default `nuxt` one.
    }, { nitro: true, nuxt: true, node: true, shared: true })

    /**
     * Ambient declaration for `#logto`.
     *
     * `@logto/nuxt` registers that alias through Nitro, and although Nuxt does copy
     * it into the server project's `paths`, importing it still fails to resolve in
     * practice — reproduced across two separate projects. This declaration makes it
     * resolve deterministically in every context.
     *
     * The `config` parameter is intentionally permissive: the type Nuxt generates
     * for `runtimeConfig.logto` contains only the keys actually set in `nuxt.config`,
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
    }
  }

  interface PublicRuntimeConfig {
    logtoRbac: {
      /** Route the session endpoint is mounted at. */
      sessionEndpoint: string
    }
  }
}
