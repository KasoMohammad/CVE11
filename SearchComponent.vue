<template>
  <div id="searchContainer">
    <label for="searchInput">Search:</label>
    <input type="text" id="searchInput" v-model="searchTerm" @keyup.enter="searchCVEs" placeholder="Enter search term" />
    <button @click="searchCVEs">Search</button>
  </div>
</template>

<script>
export default {
  name: 'SearchComponent',
  data() {
    return {
      searchTerm: ''
    };
  },
  methods: {
    searchCVEs() {
      this.$router.push({
        name: 'SearchResults',
        query: { q: this.searchTerm }
      });
    }
  }
};
</script>

<style scoped>
/* Komponentenspezifische Stile können hier definiert werden */
#searchContainer {
  max-width: 800px;
  margin: 20px auto;
}

label {
  display: block;
  margin-bottom: 5px;
}

input {
  width: 100%;
  padding: 8px;
  margin-bottom: 10px;
}

.rss-feed {
  max-width: 800px;
  margin: 20px auto;
}

.rss-item {
  border: 1px solid #ddd;
  padding: 10px;
  margin-bottom: 20px;
}

.rss-item h3 {
  margin-bottom: 5px;
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
