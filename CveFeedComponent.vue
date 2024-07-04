<template>
  <div>
    <div id="cveFeed">
      <div v-if="loading">
        <p>Loading...</p>
      </div>
      <div v-if="error">
        <p>Error: {{ error }}</p>
      </div>
      <div v-if="currentCVEs.length === 0 && !loading">
        <p>Keine CVEs gefunden.</p>
      </div>
      <div v-else>
        <div v-for="cve in currentCVEs" :key="cve._id" class="rss-item">
          <h3>CVE-ID: {{ cve.id || 'N/A' }}</h3>
          <p v-if="cve.descriptions && cve.descriptions.length > 0">Beschreibung: {{ cve.descriptions[0].value }}</p>
          <p v-if="cve.published">Veröffentlichungsdatum: {{ formatPublishedDate(cve.published) }}</p>
          <p v-if="cve.lastModified">Letzte Änderung: {{ formatLastModifiedDate(cve.lastModified) }}</p>
          <p v-if="cve.vulnStatus">Status: {{ cve.vulnStatus }}</p>
          <p v-if="cve.references && cve.references.length > 0">Referenzen: <a :href="cve.references[0]" target="_blank">{{ cve.references[0] }}</a></p>
          <div v-if="cve.metrics.cvssMetricV2 && cve.metrics.cvssMetricV2.length > 0">
            <p>Schweregrad: {{ cve.metrics.cvssMetricV2[0].baseSeverity }}</p>
            <p>Ausnutzbarkeit: {{ cve.metrics.cvssMetricV2[0].exploitabilityScore }}</p>
            <p>Auswirkung: {{ cve.metrics.cvssMetricV2[0].impactScore }}</p>
          </div>
          <div v-if="cve.weaknesses && cve.weaknesses.length > 0">
            <p>Schwachstellen:</p>
            <ul>
              <li v-for="weakness in cve.weaknesses" :key="weakness.source">{{ weakness.description[0].value }}</li>
            </ul>
          </div>
          <div v-if="cve.configurations && cve.configurations.length > 0">
            <p>Konfigurationen:</p>
            <ul>
              <li v-for="configuration in cve.configurations" :key="configuration.nodes[0].cpeMatch[0].matchCriteriaId">
                <p>Kriterien: {{ configuration.nodes[0].cpeMatch[0].criteria }}</p>
              </li>
            </ul>
          </div>
          <hr>
        </div>
      </div>
    </div>
    <div>
      <button @click="prevPage" :disabled="page === 1">Vorherige Seite</button>
      <button @click="nextPage" :disabled="page === pages">Nächste Seite</button>
      <p>Seite {{ page }} von {{ pages }}</p>
    </div>
  </div>
</template>

<script>
export default {
  data() {
    return {
      allCVEs: [],
      todaysCVEs: [],
      showAll: true,
      loading: true,
      error: null,
      page: 1,
      pages: 1,
      limit: 20,
      newAsset: '', // New asset field
      searchTerm: '' // Search term field
    };
  },
  created() {
    this.fetchCVEs();
  },
  methods: {
    async fetchCVEs() {
      try {
        this.loading = true;
        const apiUrl = `http://localhost:3000/api/cves?page=${this.page}&limit=${this.limit}`;
        const response = await fetch(apiUrl);
        if (!response.ok) {
          throw new Error(`HTTP-Fehler! Status: ${response.status}`);
        }
        const data = await response.json();
        console.log("Fetched data:", data);

        this.allCVEs = data.cves;
        this.pages = data.pages;
        this.filterTodaysCVEs();
      } catch (error) {
        this.error = `Fehler beim Abrufen von CVEs: ${error.message}`;
        console.error(this.error);
      } finally {
        this.loading = false;
      }
    },
    showAllCVEs() {
      this.showAll = true;
    },
    showTodaysCVEs() {
      this.showAll = false;
      this.filterTodaysCVEs();
    },
    filterTodaysCVEs() {
      const today = new Date().toISOString().slice(0, 10);
      this.todaysCVEs = this.allCVEs.filter(cve => {
        const isToday = cve.published && cve.published.startsWith(today);
        if (isToday) {
          console.log("Today's CVE:", cve);
        }
        return isToday;
      });
    },
    formatPublishedDate(dateString) {
      const options = {
        year: 'numeric',
        month: 'numeric',
        day: 'numeric',
        hour: 'numeric',
        minute: 'numeric',
        second: 'numeric'
      };
      return new Date(dateString).toLocaleString('de-DE', options);
    },
    formatLastModifiedDate(dateString) {
      const options = {
        year: 'numeric',
        month: 'numeric',
        day: 'numeric',
        hour: 'numeric',
        minute: 'numeric',
        second: 'numeric'
      };
      return new Date(dateString).toLocaleString('de-DE', options);
    },
    async prevPage() {
      if (this.page > 1) {
        this.page--;
        await this.fetchCVEs();
      }
    },
    async nextPage() {
      if (this.page < this.pages) {
        this.page++;
        await this.fetchCVEs();
      }
    },
    async saveAsset() {
      try {
        const response = await fetch('http://localhost:3000/api/assets', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ text: this.newAsset }),
        });
        if (!response.ok) {
          throw new Error(`HTTP-Fehler! Status: ${response.status}`);
        }
        const data = await response.json();
        console.log(data.message);
        this.newAsset = ''; // Clear the input field after saving
      } catch (error) {
        this.error = `Fehler beim Speichern des Assets: ${error.message}`;
        console.error(this.error);
      }
    },
    async searchCVEs() {
      try {
        this.loading = true;
        const apiUrl = `http://localhost:3000/api/cves/search?q=${this.searchTerm}`;
        const response = await fetch(apiUrl);
        if (!response.ok) {
          throw new Error(`HTTP-Fehler! Status: ${response.status}`);
        }
        const data = await response.json();
        console.log("Fetched search results:", data);

        this.allCVEs = data; // Setzen Sie die gefundenen CVEs auf allCVEs
      } catch (error) {
        this.error = `Fehler beim Suchen der CVEs: ${error.message}`;
        console.error(this.error);
      } finally {
        this.loading = false;
      }
    }
  },
  computed: {
    currentCVEs() {
      return this.showAll ? this.allCVEs : this.todaysCVEs;
    }
  }
};
</script>

<style>
.rss-item {
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
