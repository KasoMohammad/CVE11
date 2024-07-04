<template>
    <div>
      <h2>Red Hat CVEs</h2>
      <div v-if="loading">
        <p>Loading...</p>
      </div>
      <div v-if="error">
        <p>Error: {{ error }}</p>
      </div>
      <div v-else>
        <div v-for="cve in cves" :key="cve._id" class="cve-item">
          <h3>CVE-ID: {{ cve.id || 'N/A' }}</h3>
          <p v-if="cve.descriptions && cve.descriptions.length > 0">Beschreibung: {{ cve.descriptions[0].value }}</p>
          <p v-if="cve.published">Veröffentlichungsdatum: {{ formatPublishedDate(cve.published) }}</p>
          <p v-if="cve.lastModified">Letzte Änderung: {{ formatLastModifiedDate(cve.lastModified) }}</p>
          <p v-if="cve.vulnStatus">Status: {{ cve.vulnStatus }}</p>
          <p v-if="cve.references && cve.references.length > 0">Referenzen: <a :href="cve.references[0]" target="_blank">{{ cve.references[0] }}</a></p>
          
          <div v-if="cve.metrics && cve.metrics.cvssV3">
            <h4>CVSS v3 Metriken</h4>
            <p>Basis-Score: {{ cve.metrics.cvssV3.baseScore }}</p>
            <p>Schweregrad: {{ cve.metrics.cvssV3.baseSeverity }}</p>
            <p>Angriffsvektor: {{ cve.metrics.cvssV3.attackVector }}</p>
            <p>Angriffskomplexität: {{ cve.metrics.cvssV3.attackComplexity }}</p>
            <p>Erforderliche Privilegien: {{ cve.metrics.cvssV3.privilegesRequired }}</p>
            <p>Benutzerinteraktion: {{ cve.metrics.cvssV3.userInteraction }}</p>
            <p>Umfang: {{ cve.metrics.cvssV3.scope }}</p>
            <p>Vertraulichkeitsauswirkung: {{ cve.metrics.cvssV3.confidentialityImpact }}</p>
            <p>Integritätsauswirkung: {{ cve.metrics.cvssV3.integrityImpact }}</p>
            <p>Verfügbarkeitsauswirkung: {{ cve.metrics.cvssV3.availabilityImpact }}</p>
          </div>
  
          <p v-if="cve.severity">Schweregrad: {{ cve.severity }}</p>
          <p v-if="cve.public_date">Veröffentlichungsdatum: {{ formatPublishedDate(cve.public_date) }}</p>
          <p v-if="cve.bugzilla">Bugzilla: <a :href="cve.bugzilla" target="_blank">{{ cve.bugzilla_description }}</a></p>
          <p v-if="cve.cvss3_score">CVSSv3 Score: {{ cve.cvss3_score }}</p>
          <p v-if="cve.cvss3_scoring_vector">CVSSv3 Scoring Vector: {{ cve.cvss3_scoring_vector }}</p>
          <p v-if="cve.resource_url">Resource URL: <a :href="cve.resource_url" target="_blank">{{ cve.resource_url }}</a></p>
          
          <p>Quelle: Red Hat Backup API</p>
          <hr>
        </div>
      </div>
    </div>
  </template>
  
  <script>
  export default {
    data() {
      return {
        cves: [],
        loading: true,
        error: null
      };
    },
    async created() {
      this.fetchRedHatCVEs();
    },
    methods: {
      async fetchRedHatCVEs() {
        try {
          const response = await fetch('http://localhost:3000/api/backup-cves');
          if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
          }
          const data = await response.json();
          this.cves = data;
        } catch (error) {
          this.error = `Fehler beim Abrufen der Red Hat CVEs: ${error.message}`;
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
      }
    }
  };
  </script>
  
  <style>
  .cve-item {
    padding: 10px;
    margin-bottom: 10px;
    border: 1px solid #ccc;
    border-radius: 5px;
  }
  
  .cve-item h3 {
    margin-top: 0;
  }
  
  .cve-item p {
    margin: 5px 0;
  }
  </style>
  