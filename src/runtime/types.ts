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
 * The Logto user, normalised into a shape that is pleasant to consume.
 *
 * Every field is present, so `profile.name` needs no optional chaining. Absent claims
 * become `null` rather than `undefined`, collapsing the `string | null | undefined` that
 * `@logto/js` declares (`Nullable<string>` on an optional property) down to one nullable
 * state instead of two. An empty string is normalised to `null` as well, since Logto
 * returns `""` for cleared fields and "present but blank" is never a useful distinction
 * for a caller.
 *
 * Keys are camelCase, unlike the underlying snake_case OIDC claims: this is the module's
 * own shape, and `claims` on {@link AuthContext} remains available for anything not
 * modelled here.
 */
export interface LogtoUserProfile {
  /** Logto user id (the `sub` claim). */
  sub: string | null
  name: string | null
  username: string | null
  email: string | null
  /**
   * True only when `email_verified` is explicitly `true`.
   *
   * This is the honest reading of the claim, and is deliberately *not* the input to the
   * `verified` requirement — see {@link AuthContext.isVerified}, which treats an absent
   * claim as verified so bearer callers are not locked out.
   */
  emailVerified: boolean
  phoneNumber: string | null
  phoneNumberVerified: boolean
  picture: string | null
}

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
   * Always populated for `session` callers, since `roles` is an ID-token claim.
   *
   * Normally **empty for `bearer` callers**: Logto does not include roles in access
   * tokens by default, so a sibling service presenting one asserts its permissions
   * but not its role names. A Logto JWT customizer can add a `roles` claim, in which
   * case it is honoured. Prefer permission checks for anything that must work
   * service-to-service.
   *
   * Note also that Logto role names are mutable display strings — they may contain
   * spaces and can be renamed in the console — so renaming a role silently
   * invalidates any hard-coded role check. In Logto a role is a bundle of
   * permissions, so checking permissions tests the *effect* of a role and is the more
   * durable choice.
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
  /**
   * The normalised Logto user. Always present; all-`null` for an anonymous caller, and
   * sparse for a bearer caller, whose access token carries `sub` but no profile claims.
   */
  profile: LogtoUserProfile
  /**
   * Whether the caller counts as verified for the `verified` requirement.
   *
   * Resolved server-side so the browser can evaluate the same rule: an **absent**
   * `email_verified` claim counts as verified (bearer tokens carry none), while an
   * explicit `false` does not. Optional so the many synthetic contexts in tests stay
   * valid; when absent, `ctxIsVerified` falls back to `true`, which is the pre-existing
   * behaviour for a claim-less context.
   */
  isVerified?: boolean
}

/**
 * The context as exposed to the browser by the session endpoint.
 *
 * Raw claims are withheld: the client only needs normalised decision inputs, and
 * claims may contain data that has no business reaching it.
 */
export type ClientAuthContext = Omit<AuthContext, 'claims'>
