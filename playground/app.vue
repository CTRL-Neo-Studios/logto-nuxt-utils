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

    <h2>Probes</h2>
    <ul>
      <li><a href="/api/whoami">/api/whoami</a> — unified session or bearer context</li>
      <li><a href="/api/guarded">/api/guarded</a> — requires <code>assessment:view</code></li>
    </ul>
  </div>
</template>
