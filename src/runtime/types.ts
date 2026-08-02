/**
 * Public type surface of `@type32/logto-nuxt-utils`.
 *
 * Consumers may augment {@link RbacPermissionMap} to obtain literal-typed
 * permissions. The module generates that augmentation automatically from
 * `logtoRbac.permissions` in `nuxt.config`, so this is not something you normally
 * write by hand.
 */

/**
 * Registry of the consuming project's permissions, populated by declaration
 * merging.
 *
 * The module generates that augmentation from `logtoRbac.permissions` in
 * `nuxt.config`, so this is not something you normally write by hand.
 *
 * @example The generated augmentation looks like this
 * ```ts
 * declare module '@type32/logto-nuxt-utils/types' {
 *   interface RbacPermissionMap extends Record<"assessment:view" | "assessment:edit", true> {}
 * }
 * ```
 */
// Intentionally empty: this exists purely as a declaration-merging target, and is
// populated by the augmentation the module generates from `logtoRbac.permissions`.
// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface RbacPermissionMap {}

/**
 * A permission this project recognises.
 *
 * Resolves to a union of the exact permission strings from `logtoRbac.permissions`
 * once {@link RbacPermissionMap} has been augmented, and falls back to `string`
 * when it has not 鈥?so the package stays usable before the module has run, and
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
   * claim 鈥?only ID tokens do 鈥?so bearer callers always see an empty array.
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
