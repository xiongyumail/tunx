import { createRouter, createWebHistory } from 'vue-router'
import { api, setUnauthorizedHandler } from './lib/api.js'
import { state } from './lib/store.js'
import Layout from './components/MainLayout.vue'

const page = (path, name, loader) => ({ path, name, component: loader })

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', name: 'login', component: () => import('./views/Login.vue'), meta: { public: true } },
    {
      path: '/',
      component: Layout,
      children: [
        { path: '', redirect: '/overview' },
        page('overview', 'overview', () => import('./views/Overview.vue')),
        page('nodes', 'nodes', () => import('./views/Nodes.vue')),
        page('links', 'links', () => import('./views/Links.vue')),
        page('routes', 'routes', () => import('./views/Routes.vue')),
        page('access', 'access', () => import('./views/Access.vue')),
        page('egress', 'egress', () => import('./views/Egress.vue')),
        page('clients', 'clients', () => import('./views/Clients.vue')),
        page('groups', 'groups', () => import('./views/Groups.vue')),
        page('yaml', 'yaml', () => import('./views/Yaml.vue')),
        page('audit', 'audit', () => import('./views/Audit.vue')),
        page('settings', 'settings', () => import('./views/Settings.vue')),
      ],
    },
    { path: '/:rest(.*)*', redirect: '/overview' },
  ],
})

router.beforeEach(async (to) => {
  if (to.meta.public) return true
  if (!state.me) {
    try {
      state.me = await api.me()
    } catch {
      return { name: 'login', query: to.fullPath !== '/overview' && to.fullPath !== '/' ? { next: to.fullPath } : {} }
    }
  }
  return true
})

setUnauthorizedHandler(() => {
  state.me = null
  if (router.currentRoute.value.name !== 'login') router.push({ name: 'login' })
})
