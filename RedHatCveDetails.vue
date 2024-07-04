<template>
  <div v-if="loading">Loading...</div>
  <div v-else>
    <h2>CVE Details: {{ cveData.name }}</h2>
    <p><strong>Threat Severity:</strong> {{ cveData.threat_severity }}</p>
    <p><strong>Public Date:</strong> {{ formatPublishedDate(cveData.public_date) }}</p>
    <p><strong>Bugzilla:</strong> <a :href="cveData.bugzilla.url" target="_blank">{{ cveData.bugzilla.description }}</a></p>
    <p><strong>CVSS3 Base Score:</strong> {{ cveData.cvss3.cvss3_base_score }}</p>
    <p><strong>CVSS3 Scoring Vector:</strong> {{ cveData.cvss3.cvss3_scoring_vector }}</p>
    <p><strong>Status:</strong> {{ cveData.status }}</p>
    <h3>Details:</h3>
    <p v-for="detail in cveData.details" :key="detail">{{ detail }}</p>
    <h3>Package State:</h3>
    <div v-for="(packageState, index) in cveData.package_state" :key="index">
      <p><strong>Product Name:</strong> {{ packageState.product_name }}</p>
      <p><strong>Fix State:</strong> {{ packageState.fix_state }}</p>
      <p><strong>Package Name:</strong> {{ packageState.package_name }}</p>
      <p><strong>CPE:</strong> {{ packageState.cpe }}</p>
    </div>
    <h3>References:</h3>
    <ul>
      <li v-for="reference in cveData.references" :key="reference"><a :href="reference" target="_blank">{{ reference }}</a></li>
    </ul>
  </div>
</template>

<script>
export default {
  data() {
    return {
      cveData: null,
      loading: true,
    };
  },
  created() {
    this.fetchCveDetails();
  },
  methods: {
    async fetchCveDetails() {
      const cveUrl = this.$route.params.url;
      try {
        const response = await fetch(cveUrl);
        const data = await response.json();
        this.cveData = data;
      } catch (error) {
        console.error('Error fetching CVE details:', error);
      } finally {
        this.loading = false;
      }
    },
    formatPublishedDate(dateString) {
      const options = {
        year: 'numeric',
        month: 'numeric',
        day: 'numeric',
        hour: 'numeric',
        minute: 'numeric',
        second: 'numeric',
      };
      return new Date(dateString).toLocaleString('de-DE', options);
    },
  },
};
</script>

<style scoped>
/* Fügen Sie hier Ihre Stile hinzu */
</style>
