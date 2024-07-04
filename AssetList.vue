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
          <button @click="deleteAsset(asset._id)">Delete</button>
          <button @click="showCVEs(asset._id)">Show CVEs</button>
        </div>
        <div v-if="assetCves[asset._id] && assetCves[asset._id].length">
          <h4>Associated CVEs:</h4>
          <ul>
            <li v-for="cve in assetCves[asset._id]" :key="cve._id">
              <strong>{{ cve.id }}</strong>: {{ cve.descriptions[0].value }}
            </li>
          </ul>
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
  
    async showCVEs() {
    try {
      const response = await fetch('/api/cves');
      const data = await response.json();
      this.cves = data; // Stellt sicher, dass 'this' die Vue-Instanz referenziert
    } catch (error) {
      console.error('Error fetching CVEs:', error);
    }
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
/
</style>
