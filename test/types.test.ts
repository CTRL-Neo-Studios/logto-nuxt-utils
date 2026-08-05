import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

/**
 * The generated `Permission` union.
 *
 * The union must be written out rather than inferred from `nuxt.config`, because
 * `defineNuxtConfig` is typed `(input: InputConfig<NuxtConfig>) =>
 * InputConfig<NuxtConfig>` — not generic over its argument — so literal types are
 * widened to `string[]` on the way out.
 *
 * Since that means real codegen, these tests assert the generated file rather than
 * trusting it. The playground is prepared by `pnpm run dev:prepare`.
 */
const generated = resolve(
  fileURLToPath(new URL('..', import.meta.url)),
  'playground/.nuxt/types/logto-rbac.d.ts',
)

describe('generated permission union', () => {
  const contents = readFileSync(generated, 'utf8')

  it('augments the registry on the public subpath', () => {
    // Augmenting the published specifier is what makes declaration merging reach the
    // same file the guards import their `Permission` type from.
    expect(contents).toContain(`declare module '@type32/logto-nuxt-utils/types'`)
    expect(contents).toContain('interface RbacPermissionMap')
  })

  it('contains every configured permission as a literal', () => {
    for (const permission of [
      'assessment:create',
      'assessment:view',
      'assessment:list',
      'assessment:test',
      'assessment:delete',
      'assessment:share',
      'assessment:edit',
    ]) {
      expect(contents).toContain(`"${permission}"`)
    }
  })

  it('quotes members so a permission cannot break out of the type', () => {
    // Members are emitted with JSON.stringify, so quoting and escaping are handled.
    const union = contents.match(/Record<(.+), true>/u)?.[1] ?? ''
    expect(union.length).toBeGreaterThan(0)

    for (const member of union.split('|')) {
      expect(member.trim()).toMatch(/^"(?:[^"\\]|\\.)*"$/u)
    }
  })

  it('also augments the module\'s own runtime types path', () => {
    // Two specifiers are emitted on purpose. `nuxt-module-build --stub` makes
    // auto-imports resolve to `src/runtime/**`, whose `Permission` comes from a
    // different module than the published subpath resolves to; without the second
    // augmentation, `Permission` silently widens back to `string` during development
    // and permission typos stop being compile errors.
    const declarations = contents.match(/declare module '[^']+'/gu) ?? []

    expect(declarations).toHaveLength(2)
    expect(declarations.some(d => d.includes('@type32/logto-nuxt-utils/types'))).toBe(true)
    expect(declarations.some(d => /(?:src|dist)\/runtime\/types/u.test(d))).toBe(true)
  })
})
