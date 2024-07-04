<template>
  <div>
    <search-bar></search-bar>
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
          <!-- CVE Details anzeigen -->
          <h3>CVE-ID: {{ cve.id || 'N/A' }}</h3>
          <p v-if="cve.descriptions && cve.descriptions.length > 0">Beschreibung: {{ cve.descriptions[0].value }}</p>
          <p v-if="cve.published">Veröffentlichungsdatum: {{ formatPublishedDate(cve.published) }}</p>
          <p v-if="cve.lastModified">Letzte Änderung: {{ formatLastModifiedDate(cve.lastModified) }}</p>
          <p v-if="cve.vulnStatus">Status: {{ cve.vulnStatus }}</p>
          <p v-if="cve.references && cve.references.length > 0">Referenzen: <a :href="cve.references[0]" target="_blank">{{ cve.references[0] }}</a></p>
          <div v-if="cve.metrics && cve.metrics.cvssMetricV2 && cve.metrics.cvssMetricV2.length > 0">
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
          <div v-if="cve.bugzilla">Bugzilla: {{ cve.bugzilla }}</div>
          <div v-if="cve.bugzilla_description">Bugzilla Beschreibung: {{ cve.bugzilla_description }}</div>
          <div v-if="cve.cvss3_score">CVSS3 Score: {{ cve.cvss3_score }}</div>
          <div v-if="cve.cvss3_scoring_vector">CVSS3 Scoring Vector: {{ cve.cvss3_scoring_vector }}</div>
          <div v-if="cve.cvss_score">CVSS Score: {{ cve.cvss_score }}</div>
          <div v-if="cve.cvss_scoring_vector">CVSS Scoring Vector: {{ cve.cvss_scoring_vector }}</div>
          <div v-if="cve.severity">Schweregrad: {{ cve.severity }}</div>
          <div v-if="cve.package_state && cve.package_state.length > 0">
            <p>Paketstatus:</p>
            <ul>
              <li v-for="pkg in cve.package_state" :key="pkg.package_name">
                <p>Produktname: {{ pkg.product_name }}</p>
                <p>Fixstatus: {{ pkg.fix_state }}</p>
                <p>Paketname: {{ pkg.package_name }}</p>
                <p>CPE: {{ pkg.cpe }}</p>
              </li>
            </ul>
          </div>
          <p><strong>Quelle: {{ cve.source }}</strong></p>
          <div v-if="cve.resource_url">
            <button @click="goToCveDetails(cve.resource_url)">Mehr Information</button>
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
import SearchBar from './SearchBar.vue';

export default {
  name: 'HomePage',
  components: {
    SearchBar
  },
  data() {
    return {
      allCVEs: [],
      loading: true,
      error: null,
      page: 1,
      pages: 1,
      limit: 20
    };
  },
  created() {
    this.fetchCVEs();
  },
  methods: {
    async fetchCVEs() {
      try {
        this.loading = true;
        const [nvdResponse, cvssResponse, backupResponse] = await Promise.all([
          fetch(`http://localhost:3000/api/cves?page=${this.page}&limit=${this.limit}`),
          fetch('http://localhost:3000/api/cvss-cves'),
          fetch('http://localhost:3000/api/backup-cves')
        ]);

        if (!nvdResponse.ok || !cvssResponse.ok || !backupResponse.ok) {
          throw new Error(`HTTP-Fehler! Status: ${nvdResponse.status}, ${cvssResponse.status}, ${backupResponse.status}`);
        }

        const nvdData = await nvdResponse.json();
        const cvssData = await cvssResponse.json();
        const backupData = await backupResponse.json();

        const nvdCVEs = nvdData.cves.map(cve => ({ ...cve, source: 'NVD API' }));
        const cvssCVEs = cvssData.map(cve => ({ ...cve, source: 'CVSS API' }));
        const backupCVEs = backupData.map(cve => ({ ...cve, source: 'Red Hat Backup API', resource_url: cve.resource_url }));

        this.allCVEs = [...nvdCVEs, ...cvssCVEs, ...backupCVEs];
        this.pages = Math.ceil(this.allCVEs.length / this.limit);
      } catch (error) {
        this.error = `Fehler beim Abrufen von CVEs: ${error.message}`;
        console.error(this.error);
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
    goToCveDetails(url) {
      this.$router.push({ name: 'RedHatCveDetails', params: { url } });
    }
  },
  computed: {
    currentCVEs() {
      return this.allCVEs;
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
