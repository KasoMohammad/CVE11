<template>
    <div>
      <h2>CVSS CVEs</h2>
      <ul>
        <li v-for="cve in cves" :key="cve.id" class="cve-item">
          <h3>{{ cve.id }}</h3>
          <p>{{ cve.descriptions[0]?.value }}</p>
          <p>Published: {{ cve.published }}</p>
          <p>Last Modified: {{ cve.lastModified }}</p>
          <p>Status: {{ cve.vulnStatus }}</p>
        </li>
      </ul>
    </div>
  </template>
  
  <script>
  export default {
    data() {
      return {
        cves: []
      };
    },
    mounted() {
      this.fetchCvssCVEs();
    },
    methods: {
      async fetchCvssCVEs() {
        try {
          const response = await fetch('http://localhost:3000/api/cvss-cves'); // Passen Sie die URL entsprechend an
          const data = await response.json();
          this.cves = data;
        } catch (error) {
          console.error('Fehler beim Abrufen der CVSS CVEs:', error);
        }
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
    margin: 0;
    padding: 0;
  }
  
  .cve-item p {
    margin: 5px 0;
  }
  </style>
  