import {
  createRootRoute,
  createRoute,
  createRouter,
  redirect,
} from '@tanstack/react-router'
import { AppShell } from './components/AppShell'
import { OverviewPage } from './pages/OverviewPage'
import { SourcesPage } from './pages/SourcesPage'
import { TeamPage } from './pages/TeamPage'
import { UpdatesPage } from './pages/UpdatesPage'

const rootRoute = createRootRoute({ component: AppShell })

const overviewRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: OverviewPage,
})

const sourcesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/sources',
  component: SourcesPage,
})

const updatesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/updates',
  component: UpdatesPage,
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
  overviewRoute,
  sourcesRoute,
  teamRoute,
  updatesRoute,
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
