<script setup lang="ts">
const { data: session } = await useFetch('/api/_auth/session')
</script>

<template>
  <div style="font-family: monospace; padding: 2rem">
    <h1>logto-nuxt-utils playground</h1>

    <p v-if="!session?.isAuthenticated">
      Not signed in. <a href="/signin">Sign in</a>
    </p>
    <p v-else>
      Signed in as {{ session.userId }} — <a href="/signout">Sign out</a>
    </p>

    <h2>Session context</h2>
    <pre>{{ session }}</pre>

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

    <!-- Composed ability: manage OR admin. -->
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
      <li><a href="/api/gated">/api/gated</a> — ability via <code>authorize</code></li>
    </ul>
  </div>
</template>
