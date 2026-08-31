import {
  createRootRoute,
  createRoute,
  createRouter,
  redirect,
} from '@tanstack/react-router'
import { AppShell } from './components/AppShell'
import { SettingsPage } from './pages/SettingsPage'
import { SourcesPage } from './pages/SourcesPage'
import { TeamPage } from './pages/TeamPage'

const rootRoute = createRootRoute({ component: AppShell })

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  beforeLoad: ({ location }) => {
    if (new URLSearchParams(location.searchStr).get('teardown') === 'review') {
      throw redirect({ to: '/settings', search: location.search, replace: true })
    }
    throw redirect({ to: '/sources', search: location.search, replace: true })
  },
})

const sourcesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/sources',
  component: SourcesPage,
})

const settingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/settings',
  component: SettingsPage,
})

const legacyUpdatesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/updates',
  beforeLoad: ({ location }) => {
    throw redirect({ to: '/settings', search: location.search })
  },
})

const teamRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/team',
  component: TeamPage,
})

const fallbackRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '$',
  beforeLoad: () => {
    throw redirect({ to: '/' })
  },
})

export const routeTree = rootRoute.addChildren([
  indexRoute,
  sourcesRoute,
  teamRoute,
  settingsRoute,
  legacyUpdatesRoute,
  fallbackRoute,
])

export const router = createRouter({
  routeTree,
  defaultPreload: 'intent',
  scrollRestoration: true,
})

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}
