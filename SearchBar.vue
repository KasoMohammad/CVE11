<template>
    <div>
      <input type="text" v-model="searchQuery" placeholder="Search CVEs" />
      <button @click="searchCVEs">Search</button>
    </div>
  </template>
  
  <script>
  export default {
    data() {
      return {
        searchQuery: ''
      };
    },
    methods: {
      searchCVEs() {
        this.$router.push({
          name: 'SearchResults',
          query: { q: this.searchQuery }
        });
      }
    }
  };
  </script>
  
  <style scoped>
  input[type="text"] {
    padding: 10px;
    margin: 5px;
    border: 1px solid #ccc;
    border-radius: 4px;
  }
  
  button {
    padding: 10px 15px;
    background-color: #4CAF50;
    color: white;
    border: none;
    cursor: pointer;
    margin: 5px;
  }
  
  button:hover {
    background-color: #45a049;
  }
  </style>
  