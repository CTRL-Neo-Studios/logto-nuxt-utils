/**
 * Public type surface of `@type32/logto-nuxt-utils`.
 *
 * Consumers may augment {@link RbacPermissionMap} to obtain literal-typed
 * permissions. The module generates that augmentation automatically from the
 * project's `rbac.config.ts`, so this is not something you normally write by
 * hand.
 */

/**
 * Registry of the consuming project's permissions, populated by declaration
 * merging.
 *
 * The module emits a `.d.ts` into the consumer's build that augments this
 * interface by *inferring* from `rbac.config.ts`, rather than by stringifying a
 * union into generated code. That means the type can never drift from the config
 * file, and there is no codegen step to re-run after editing it.
 *
 * @example The generated augmentation looks like this
 * ```ts
 * declare module '@type32/logto-nuxt-utils/types' {
 *   interface RbacPermissionMap
 *     extends Record<(typeof import('~~/rbac.config').default)['permissions'][number], true> {}
 * }
 * ```
 */
// Intentionally empty: this exists purely as a declaration-merging target, and is
// populated by the augmentation the module generates from `rbac.config.ts`.
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface RbacPermissionMap {}

/**
 * A permission this project recognises.
 *
 * Resolves to a union of the exact permission strings from `rbac.config.ts`
 * once {@link RbacPermissionMap} has been augmented, and falls back to `string`
 * when it has not — so the package stays usable before the module has run, and
 * degrades to "no autocomplete" rather than to `never`, which would make every
 * call site an error.
 *
 * The tuple wrapper makes the check non-distributive; a bare
 * `keyof RbacPermissionMap extends never` would behave incorrectly for unions.
 */
export type Permission = [keyof RbacPermissionMap] extends [never]
  ? string
  : Extract<keyof RbacPermissionMap, string>

/** How an {@link AuthContext} was established for the current request. */
export type AuthSource
  /** Resolved from the encrypted Logto session cookie (a browser user). */
  = | 'session'
  /** Resolved from a verified `Authorization: Bearer` JWT (a sibling service). */
    | 'bearer'
  /** No credentials present, or credentials could not be resolved. */
    | 'anonymous'

/**
 * Normalised view of "who is calling and what may they do", independent of
 * whether the caller authenticated with a session cookie or a bearer token.
 *
 * A single shape for both is what allows one set of guards and one set of
 * abilities to serve browser users and service-to-service calls alike.
 */
export interface AuthContext {
  isAuthenticated: boolean
  source: AuthSource
  /** Logto user id (the `sub` claim). */
  userId?: string
  /**
   * Role *names* held by the user.
   *
   * Populated for `session` callers only. Logto access tokens carry no `roles`
   * claim — only ID tokens do — so bearer callers always see an empty array.
   * Prefer permission checks over role checks for anything that must work
   * service-to-service.
   *
   * Note also that Logto role names are mutable display strings (they may even
   * contain spaces), so renaming a role in the console will silently invalidate
   * any hard-coded role check.
   */
  roles: string[]
  /**
   * Granted permissions, parsed from the resource access token's `scope` claim.
   *
   * Typed as `string[]` rather than `Permission[]` because Logto is the source of
   * truth at runtime and may legitimately return scopes this project does not
   * model.
   */
  scopes: string[]
  /** Organization ids the user belongs to (requires the `organizations` scope). */
  organizations: string[]
  /** Map of organization id to the role names held within it. */
  organizationRoles: Record<string, string[]>
  /** Raw token claims, for callers needing something not modelled above. */
  claims?: Record<string, unknown>
}

/**
 * The context as exposed to the browser by the session endpoint.
 *
 * Raw claims are withheld: the client only needs normalised decision inputs, and
 * claims may contain data that has no business reaching it.
 */
export type ClientAuthContext = Omit<AuthContext, 'claims'>

/**
 * A resource this app wants tokens for but does **not** own.
 *
 * The object form exists so another service's scopes can be requested without
 * adding them to `permissions` — which would wrongly pull them into this app's
 * own {@link Permission} union.
 */
export type AdditionalResource =
  | string
  | {
    /** The other service's API resource indicator. */
    resource: string
    /** Scopes to request for it, if it defines any you need. */
    scopes?: readonly string[]
  }

/** Shape of a project's `rbac.config.ts`. */
export interface RbacConfig {
  /**
   * Indicators of the Logto API resources this app **owns**.
   *
   * These are *identifiers*, not endpoints Logto ever calls, so the production URL
   * is normally used in development too. Each must match the value configured in
   * the Logto console byte-for-byte.
   *
   * A trailing slash makes it a *different* resource to Logto, which surfaces as a
   * silently empty `scope` claim rather than an error; the module warns about this
   * at build time.
   *
   * Two consequences of listing more than one:
   *
   * - Permissions are unioned across all of them, which costs one access token per
   *   resource. Each is cached in the encrypted session cookie, so a long list can
   *   approach the ~4KB cookie limit.
   * - **All of them are accepted as the `aud` of an inbound bearer token.** Only
   *   list resources this app actually serves; resources belonging to other
   *   services go in {@link RbacConfig.additionalResources}, otherwise a token
   *   minted for another service would be accepted here.
   *
   * @example ['https://tc-manifold.ctrl-neo.dev/api/v1']
   */
  resources: readonly string[]
  /**
   * Resources belonging to *other* services, requested at sign-in so this app can
   * call them.
   *
   * Deliberately kept apart from {@link RbacConfig.resources}: entries here are
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
   * This list is the sole source of the {@link Permission} type.
   */
  permissions: readonly string[]
  /**
   * Additional Logto user scopes to request beyond the defaults.
   *
   * The module always requests `roles`, `email` and `profile`. Add
   * `'urn:logto:scope:organizations'` and `'urn:logto:scope:organization_roles'`
   * here if you need organization data in the token claims.
   */
  userScopes?: readonly string[]
}
