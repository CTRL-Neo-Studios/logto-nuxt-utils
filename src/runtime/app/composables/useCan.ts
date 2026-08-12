import {
  computed,
  type ComputedRef,
  getCurrentInstance,
  type MaybeRefOrGetter,
  onServerPrefetch,
  toValue,
} from 'vue'
import {
  type RequirementsInput,
  toRequirements,
} from '../../shared/requirements'
import { useAuthorization } from './useAuthorization'

/**
 * Declarative permission check that resolves the context itself.
 *
 * `useAuthorization().can()` only means anything once `resolve()` has run; forgetting
 * that `await` yields a silent `false`. This starts resolution on your behalf, and when
 * called inside a component it also registers `onServerPrefetch`, so SSR awaits the same
 * de-duplicated request rather than rendering a not-yet-resolved `false`.
 *
 * Accepts the same shorthand as the gates: a single permission, an array of them
 * (meaning ALL), or full {@link AuthRequirements}. The input may be a ref or getter, so
 * a check whose subject changes stays reactive.
 *
 * During **prerendering** this is always `false` by design: there is no request-bound
 * cookie, so `useAuthorization().resolve()` deliberately returns `null` and the check
 * re-evaluates on the client once the session exists.
 *
 * @example
 * ```vue
 * <script setup lang="ts">
 * const canEdit = useCan('assessment:edit')
 * </script>
 *
 * <template>
 *   <button v-if="canEdit">Edit</button>
 * </template>
 * ```
 */
export function useCan(input: MaybeRefOrGetter<RequirementsInput>): ComputedRef<boolean> {
  const auth = useAuthorization()

  // Fire-and-forget: the promise is shared per Nuxt app instance, so this costs one
  // request no matter how many checks a page declares.
  void auth.resolve()

  // Outside a component (a plugin, for instance) there is no instance to attach a
  // prefetch hook to; the fire-and-forget resolve above still populates the state.
  if (getCurrentInstance()) onServerPrefetch(() => auth.resolve())

  return computed(() => auth.satisfies(toRequirements(toValue(input))))
}
