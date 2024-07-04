<template>
  <div>
    <h2>Search Results</h2>
    <div>
      <input type="text" v-model="searchQuery" placeholder="Search CVEs by ID, description, or date" />
      <button @click="searchAgain">Search</button>
    </div>
    <div v-if="loading">
      <p>Loading...</p>
    </div>
    <div v-if="error">
      <p>Error: {{ error }}</p>
    </div>
    <div v-if="cves.length === 0 && !loading">
      <p>No CVEs found.</p>
    </div>
    <div v-else>
      <div v-for="cve in cves" :key="cve._id" class="cve-item">
        <h3>CVE-ID: {{ cve.id }}</h3>
        <p>Description: {{ cve.descriptions[0].value }}</p>
        <p>Published: {{ formatPublishedDate(cve.published) }}</p>
        <p>Last Modified: {{ formatLastModifiedDate(cve.lastModified) }}</p>
        <p v-if="cve.metrics && cve.metrics.cvssMetricV2 && cve.metrics.cvssMetricV2[0]">Severity: {{ cve.metrics.cvssMetricV2[0].baseSeverity }}</p>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  data() {
    return {
      cves: [],
      loading: false,
      error: null,
      searchQuery: this.$route.query.q || ''
    };
  },
  watch: {
    '$route.query.q': 'fetchSearchResults'
  },
  created() {
    this.fetchSearchResults();
  },
  methods: {
    async fetchSearchResults() {
      const searchQuery = this.searchQuery;
      if (!searchQuery) return;

      this.loading = true;
      try {
        const response = await fetch(`http://localhost:3000/api/search?q=${encodeURIComponent(searchQuery)}`);
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
        const data = await response.json();
        this.cves = data.cves;
      } catch (error) {
        this.error = `Error fetching search results: ${error.message}`;
        console.error(this.error);
      } finally {
        this.loading = false;
      }
    },
    searchAgain() {
      this.$router.push({
        name: 'SearchResults',
        query: { q: this.searchQuery }
      });
    },
    formatPublishedDate(dateString) {
      const options = { year: 'numeric', month: 'numeric', day: 'numeric' };
      return new Date(dateString).toLocaleDateString('de-DE', options);
    },
    formatLastModifiedDate(dateString) {
      const options = { year: 'numeric', month: 'numeric', day: 'numeric' };
      return new Date(dateString).toLocaleDateString('de-DE', options);
    }
  }
};
</script>

<style>
.cve-item {
  border: 1px solid #ddd;
  padding: 10px;
  margin-bottom: 20px;
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
