<script setup lang="ts">
const canView = useCan('assessment:view')
const session = useLogtoSession()
const auth = useAuthorization()
await auth.resolve()
</script>

<template>
  <div>
    <p id="can-view">{{ canView }}</p>
    <p id="display-name">{{ auth.displayName.value }}</p>
    <p id="profile-name">{{ auth.profile.value.name }}</p>
    <p id="sign-in-path">{{ session.signInPath }}</p>
    <p id="sign-out-path">{{ session.signOutPath }}</p>
    <p id="ready">{{ auth.ready.value }}</p>
    <p id="source">{{ auth.source.value }}</p>
    <p id="failed">{{ auth.explain({ permissions: ['assessment:view'] }).failed }}</p>
  </div>
</template>
