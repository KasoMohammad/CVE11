<template>
  <div>
    <h2>Manage Assets</h2>
    <input type="text" v-model="newAsset" placeholder="Enter asset" />
    <button @click="saveAsset">Save Asset</button>

    <h3>Existing Assets</h3>
    <input type="text" v-model="searchTerm" placeholder="Search assets" />
    <ul>
      <li v-for="asset in filteredAssets" :key="asset._id">
        <div>
          <span>{{ asset.text }}</span>
          <input type="text" v-model="asset.name" placeholder="Enter name" @blur="updateAsset(asset)" />
          <button @click="deleteAsset(asset._id)">Delete</button>
          <button @click="toggleCVEList(asset._id)">Show/Hide CVEs</button>
        </div>
        <div v-if="isCVEListVisible(asset._id)">
          <p v-if="loadingCves[asset._id]">Loading...</p>
          <p v-if="!loadingCves[asset._id] && !assetCves[asset._id]?.length">Keine betroffenen CVEs gefunden.</p>
          <div v-if="assetCves[asset._id]?.length">
            <h4>Associated CVEs:</h4>
            <ul>
              <li v-for="cve in assetCves[asset._id]" :key="cve._id">
                <strong>{{ cve.id }}</strong>: {{ cve.descriptions?.[0]?.value || 'No description' }} <br>
                Last Modified: {{ formatLastModifiedDate(cve.lastModified) }} <br>
                Severity: {{ cve.metrics?.cvssMetricV2?.[0]?.baseSeverity || cve.metrics?.cvssV3?.baseSeverity || 'N/A' }} <br>
                Quelle: {{ cve.source }}
              </li>
            </ul>
          </div>
        </div>
      </li>
    </ul>
  </div>
</template>

<script>
export default {
  data() {
    return {
      newAsset: '',
      assets: [],
      searchTerm: '',
      assetCves: {}, // Store CVEs for each asset
      visibleCVELists: {}, // Track which CVE lists are visible
      loadingCves: {}, // Track loading state for each asset
      error: null,
    };
  },
  created() {
    this.fetchAssets();
  },
  methods: {
    async fetchAssets() {
      try {
        const response = await fetch('http://localhost:3000/api/assets');
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        this.assets = data;
      } catch (error) {
        this.error = `Error fetching assets: ${error.message}`;
        console.error(this.error);
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
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        console.log(data.message);
        this.newAsset = '';
        this.fetchAssets(); // Refresh the asset list
      } catch (error) {
        this.error = `Error saving asset: ${error.message}`;
        console.error(this.error);
      }
    },
    async deleteAsset(assetId) {
      try {
        const response = await fetch(`http://localhost:3000/api/assets/${assetId}`, {
          method: 'DELETE',
        });
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        console.log(data.message);
        this.fetchAssets(); // Refresh the asset list
      } catch (error) {
        this.error = `Error deleting asset: ${error.message}`;
        console.error(this.error);
      }
    },
    async showCVEs(assetId) {
      try {
        this.loadingCves = { ...this.loadingCves, [assetId]: true };
        const response = await fetch(`http://localhost:3000/api/assets/${assetId}/cves`);
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const cves = await response.json();
        this.assetCves = { ...this.assetCves, [assetId]: cves };
      } catch (error) {
        this.error = `Error fetching CVEs: ${error.message}`;
        console.error(this.error);
      } finally {
        this.loadingCves = { ...this.loadingCves, [assetId]: false };
      }
    },
    toggleCVEList(assetId) {
      if (this.visibleCVELists[assetId]) {
        this.visibleCVELists = { ...this.visibleCVELists, [assetId]: false };
      } else {
        this.showCVEs(assetId);
        this.visibleCVELists = { ...this.visibleCVELists, [assetId]: true };
      }
    },
    isCVEListVisible(assetId) {
      return !!this.visibleCVELists[assetId];
    },
    async updateAsset(asset) {
      try {
        const response = await fetch(`http://localhost:3000/api/assets/${asset._id}`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ text: asset.text, name: asset.name }),
        });
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        console.log(data.message);
        this.fetchAssets(); // Refresh the asset list
      } catch (error) {
        this.error = `Error updating asset: ${error.message}`;
        console.error(this.error);
      }
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
  },
  computed: {
    filteredAssets() {
      return this.assets.filter(asset => asset.text.toLowerCase().includes(this.searchTerm.toLowerCase()));
    },
  },
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
