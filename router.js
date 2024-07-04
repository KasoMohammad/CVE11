import { createRouter, createWebHistory } from 'vue-router';
import HomePage from './components/HomePage.vue';
import ManageAssets from './components/ManageAssets.vue';
import CvssCVEs from './components/CvssCVEs.vue';
import RedHatCVEs from './components/RedHatCVEs.vue';
import SearchResults from './components/SearchResults.vue';
import RedHatCveDetails from './components/RedHatCveDetails.vue';

const routes = [
  {
    path: '/',
    name: 'HomePage',
    component: HomePage
  },
  {
    path: '/manage-assets',
    name: 'ManageAssets',
    component: ManageAssets
  },
  {
    path: '/cvss-cves',
    name: 'CvssCVEs',
    component: CvssCVEs
  },
  {
    path: '/redhat-cves',
    name: 'RedHatCVEs',
    component: RedHatCVEs
  },
  {
    path: '/search-results',
    name: 'SearchResults',
    component: SearchResults
  },
  {
    path: '/redhat-cve-details',
    name: 'RedHatCveDetails',
    component: RedHatCveDetails
  }
];

const router = createRouter({
  history: createWebHistory(),
  routes
});

export default router;
