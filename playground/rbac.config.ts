// Imported from source rather than by package name on purpose: this is the
// in-repo playground, and `nuxt-module-build build --stub` wipes `dist/`, so the
// package's own `./config` type declaration is unavailable during `pnpm dev`.
// Real consumers import from '@type32/logto-nuxt-utils/config' (as the test
// fixture does, which is what keeps that path covered).
import { defineRbacConfig } from '../src/runtime/config'

/**
 * Playground RBAC config.
 *
 * Declared once here; the module derives `logto.scopes` and `logto.resources`
 * from it, and infers the literal-typed `Permission` union from this file.
 */
export default defineRbacConfig({
  resources: ['https://tc-manifold.ctrl-neo.dev/api/v1'],

  permissions: [
    'assessment:create',
    'assessment:view',
    'assessment:list',
    'assessment:test',
    'assessment:delete',
    'assessment:share',
    'assessment:edit',
  ],
})
