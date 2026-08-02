import type { RbacConfig } from './types'

export type { RbacConfig } from './types'

/**
 * Defines a project's RBAC configuration.
 *
 * Place the result as the default export of `rbac.config.ts` at your project
 * root; the module discovers it there automatically.
 *
 * The `const` type parameter preserves the literal types of `permissions`
 * without you having to write `as const`, which is what lets the module infer a
 * literal-typed `Permission` union from this file.
 *
 * This function is intentionally dependency-free and does nothing at runtime: the
 * config file is loaded by the module at build time, outside of any Nuxt or Nitro
 * context, so it must not pull in anything heavier.
 *
 * @example
 * ```ts
 * // rbac.config.ts
 * import { defineRbacConfig } from '@type32/logto-nuxt-utils/config'
 *
 * export default defineRbacConfig({
 *   resource: 'https://tc-manifold.ctrl-neo.dev/api/v1',
 *   permissions: [
 *     'assessment:create',
 *     'assessment:view',
 *   ],
 * })
 * ```
 */
export function defineRbacConfig<const T extends RbacConfig>(config: T): T {
  return config
}
