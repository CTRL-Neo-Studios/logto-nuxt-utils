/**
 * Ambient shims for this repository's own typecheck only. Not shipped.
 *
 * `#logto` is a Nitro alias registered by `@logto/nuxt` at runtime, so it does not
 * exist while type-checking the module in isolation. Consumers get an equivalent
 * declaration emitted by the module itself (see `addTypeTemplate` in
 * `src/module.ts`).
 */
declare module '#logto' {
  import type { H3Event } from 'h3'

  export function logtoEventHandler(
    event: H3Event,
    config: { logto: unknown },
  ): Promise<void>
}
