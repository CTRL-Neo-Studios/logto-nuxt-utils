<script setup lang="ts">
// Reactive, permission-first client API. `can()` reads the same context the server
// guards use, so UI and enforcement cannot disagree.
const auth = useAuthorization()
await auth.resolve()

const canEdit = computed(() => auth.can('assessment:edit'))
const canReview = computed(() => auth.canAny('assessment:edit', 'assessment:share'))
const isVerifiedEditor = computed(() =>
  auth.satisfies({ permissions: ['assessment:edit'], verified: true }),
)
</script>

<template>
  <div style="font-family: monospace; padding: 2rem">
    <h1>logto-nuxt-utils playground</h1>

    <p v-if="!auth.isAuthenticated.value">
      Not signed in. <a href="/signin">Sign in</a>
    </p>
    <p v-else>
      Signed in as {{ auth.user.value?.userId }} — <a href="/signout">Sign out</a>
    </p>

    <h2>Session context</h2>
    <pre>{{ auth.user.value }}</pre>

    <h2>useAuthorization()</h2>
    <ul>
      <li>can('assessment:edit'): {{ canEdit }}</li>
      <li>canAny('assessment:edit', 'assessment:share'): {{ canReview }}</li>
      <li>satisfies({{ '{ permissions, verified }' }}): {{ isVerifiedEditor }}</li>
      <li>roles: {{ auth.roles.value }}</li>
      <li>scopes: {{ auth.scopes.value }}</li>
    </ul>
    <button @click="auth.refresh()">
      Refresh context
    </button>

    <h2>Abilities</h2>
    <!-- No `:args` needed: gates are pre-bound and take no arguments. -->
    <Can :ability="gates.viewAssessment">
      <p>Can view assessments.</p>
    </Can>
    <Cannot :ability="gates.viewAssessment">
      <p>Cannot view assessments.</p>
    </Cannot>

    <!-- An array requires every ability to pass. -->
    <Can :ability="[gates.viewAssessment, gates.listAssessments]">
      <p>Can both view and list.</p>
    </Can>

    <Bouncer :ability="editOrAdmin">
      <template #can>
        <p>May edit (or is an admin).</p>
      </template>
      <template #cannot>
        <p>May not edit.</p>
      </template>
    </Bouncer>

    <h2>Probes</h2>
    <ul>
      <li><a href="/api/whoami">/api/whoami</a> — unified session or bearer context</li>
      <li><a href="/api/guarded">/api/guarded</a> — <code>requirePermission</code></li>
      <li><a href="/api/required">/api/required</a> — <code>requireLogtoUser</code> + requirements</li>
      <li><a href="/api/gated">/api/gated</a> — ability via <code>authorize</code></li>
    </ul>
  </div>
</template>
