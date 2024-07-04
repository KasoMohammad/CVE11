<template>
  <div>
    <h2>CVE-Daten</h2>
    <div id="cveFeed"></div>
    <input type="text" id="searchInput" placeholder="Suchen...">
    <select id="severityFilter">
      <option value="All">Alle</option>
      <option value="Low">Niedrig</option>
      <option value="Medium">Mittel</option>
      <option value="High">Hoch</option>
      <option value="Critical">Kritisch</option>
    </select>
    <form id="cveForm">
      <!-- Weitere HTML-Elemente hier einfügen -->
    </form>
  </div>
</template>

<script>
export default {
  name: 'CveScript',
  mounted() {
    document.addEventListener("DOMContentLoaded", async () => {
      const cveListContainer = document.getElementById("cveFeed");
      const searchInput = document.getElementById("searchInput");
      const severitySelect = document.getElementById("severityFilter");

      if (!cveListContainer || !searchInput || !severitySelect) {
        console.error("Fehler: cveFeed-Container, searchInput oder severityFilter nicht gefunden.");
        return;
      }

      try {
        const apiUrl = "http://localhost:3000/api/cves";
        const response = await fetch(apiUrl);
        if (!response.ok) {
          throw new Error(`HTTP-Fehler! Status: ${response.status}`);
        }
        const data = await response.json();
        displayCVEs(data);
      } catch (error) {
        console.error(`Fehler beim Abrufen von CVEs: ${error.message}`);
      }

      function displayCVEs(cves) {
        cveListContainer.innerHTML = "";
        cves.forEach((cve) => {
          const cveItem = document.createElement("div");
          cveItem.classList.add("rss-item");

          const severityColor = getSeverityColor(cve.cvss3_score);
          cveItem.style.backgroundColor = severityColor;

          const formattedDate = formatPublishedDate(cve.datePublished);
          const severityLabel = cveSeverityLabel(cve.cvss3_score);

          cveItem.innerHTML = `
            <h3>CVE-ID: ${cve.cveId || 'N/A'}</h3>
            <p>Beschreibung: ${cve.descriptions[0] || 'N/A'}</p>
            <p>Veröffentlichungsdatum: ${formattedDate}</p>
            <p>Risiko: ${severityLabel}</p>
            <p>Bugzilla: ${cve.references[0] || 'N/A'}</p>
            <p>CVSSv3-Wert: ${cve.cvss3_score || 'N/A'}</p>
            <p>CWE: ${cve.problemTypes[0] || 'N/A'}</p>
            <hr>
          `;
          cveListContainer.appendChild(cveItem);
        });
      }

      function cveSeverityLabel(severity) {
        if (severity >= 0.1 && severity <= 3.9) {
          return "Niedrig";
        } else if (severity >= 4.0 && severity <= 6.9) {
          return "Mittel";
        } else if (severity >= 7.0 && severity <= 8.9) {
          return "Hoch";
        } else if (severity >= 9.0 && severity <= 10.0) {
          return "Kritisch";
        } else {
          return "N/A";
        }
      }

      function formatPublishedDate(dateString) {
        const options = { year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', minute: 'numeric', second: 'numeric' };
        const formattedDate = new Date(dateString).toLocaleString('de-DE', options);
        return formattedDate;
      }

      function getSeverityColor(severity) {
        if (severity >= 0.1 && severity <= 3.9) {
          return 'rgb(169, 255, 142)';
        } else if (severity >= 4.0 && severity <= 6.9) {
          return 'rgb(255, 250, 0)';
        } else if (severity >= 7.0 && severity <= 8.9) {
          return 'rgb(255, 165, 0)';
        } else if (severity >= 9.0 && severity <= 10.0) {
          return 'rgb(255, 80, 80)';
        } else {
          return 'transparent';
        }
      }
    });
  },
};
</script>

<style>
#cveFeed {
  padding: 10px;
}

.rss-item {
 
  border: 1px solid #ccc;
  margin-bottom: 10px;
  padding: 10px;
  border-radius: 4px;
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
