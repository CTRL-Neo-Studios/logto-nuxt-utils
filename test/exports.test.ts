import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const root = fileURLToPath(new URL('..', import.meta.url))
const pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8')) as {
  exports: Record<string, Record<string, string>>
}

/**
 * `nuxt-module-build build --stub` wipes `dist/` and emits only the module entry,
 * so file-existence checks are meaningful only against a full build. CI runs
 * `prepack` before the tests for exactly this reason.
 */
const isFullBuild = existsSync(resolve(root, 'dist/runtime/types.js'))

describe('package exports', () => {
  it('declares a CJS-resolvable condition for every subpath', () => {
    // A subpath offering only `import` + `types` makes CommonJS resolution throw
    // ERR_PACKAGE_PATH_NOT_EXPORTED ("Package subpath ... is not defined by
    // exports"). That is how a previous release broke: TypeScript resolved happily
    // through `types` while anything resolving via `require` failed.
    for (const [subpath, conditions] of Object.entries(pkg.exports)) {
      expect(
        conditions.require ?? conditions.default,
        `"${subpath}" needs a \`require\` or \`default\` condition`,
      ).toBeDefined()
    }
  })

  it.skipIf(!isFullBuild)('points every condition at a file that exists', () => {
    for (const [subpath, conditions] of Object.entries(pkg.exports)) {
      for (const [condition, target] of Object.entries(conditions)) {
        expect(
          existsSync(resolve(root, target)),
          `"${subpath}" (${condition}) -> ${target} is missing`,
        ).toBe(true)
      }
    }
  })
})
