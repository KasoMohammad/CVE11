<template>
  <div id="app">
    <header>
      <h1>CVE-Feed</h1>
    </header>
    <div>
      <button @click="showAllCVEs">Alle CVEs anzeigen</button>
      <button @click="goToManageAssets">Manage Assets</button>
      <button @click="showCvssCVEs">Cvss CVEs</button>
      <button @click="showRedHatCVEs">Red Hat Backup CVEs</button>
    </div>
    <router-view></router-view>
  </div>
</template>

<script>
export default {
  data() {
    return {
      searchQuery: ''
    };
  },
  methods: {
    showAllCVEs() {
      this.$router.push({ name: 'HomePage' });
    },
    goToManageAssets() {
      this.$router.push({ name: 'ManageAssets' });
    },
    showCvssCVEs() {
      this.$router.push({ name: 'CvssCVEs' });
    },
    showRedHatCVEs() {
      this.$router.push({ name: 'RedHatCVEs' });
    }
  }
};
</script>

<style>
.asset-item {
  display: flex;
  align-items: center;
  margin-bottom: 10px;
}

.asset-item span {
  margin-right: 10px;
}

.asset-item input {
  margin-right: 10px;
}

.severity-none {
  background-color: green;
  color: white;
}

.severity-low {
  background-color: yellow;
  color: black;
}

.severity-medium {
  background-color: orange;
  color: white;
}

.severity-high {
  background-color: red;
  color: white;
}

.severity-critical {
  background-color: darkred;
  color: white;
}

.severity-unknown {
  background-color: gray;
  color: white;
}

.cve-item {
  padding: 10px;
  margin-bottom: 10px;
  border-radius: 5px;
}
</style>
