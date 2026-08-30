import { describe, expect, it } from 'vitest'
import { SOURCE_CATALOG } from '../catalog'
import {
  formatNativeRecipeSetup,
  NATIVE_CONNECTOR_RECIPES,
  NATIVE_RECIPE_NOTICE,
  NATIVE_RECIPE_RESEARCH_DATE,
  NATIVE_RECIPE_STATUS_LABELS,
  NativeRecipeValidationError,
  parseNativeConnectorRecipes,
  resolveNativeRecipe,
  type NativeConnectorRecipe,
} from './native-recipes'

function recipe(id = 'linear'): NativeConnectorRecipe {
  const resolved = resolveNativeRecipe(id)
  if (!resolved) throw new Error('test_recipe_missing')
  return resolved.recipe
}

function withChanges(changes: Partial<NativeConnectorRecipe>): NativeConnectorRecipe[] {
  return [{ ...recipe(), ...changes }]
}

describe('native connector setup recipes', () => {
  it('validates deterministic data for the researched providers without approving a catalog entry', () => {
    expect(parseNativeConnectorRecipes(NATIVE_CONNECTOR_RECIPES)).toEqual(NATIVE_CONNECTOR_RECIPES)
    expect(NATIVE_CONNECTOR_RECIPES.map((entry) => entry.id)).toEqual([
      'ahrefs', 'airtable', 'bigquery', 'confluence', 'github', 'gitlab',
      'google-drive', 'google-sheets', 'gorgias', 'hubspot', 'intercom-eu',
      'intercom-us', 'jira', 'linear', 'notion', 'salesforce', 'sentry', 'slack', 'stripe',
    ])
    expect(SOURCE_CATALOG.sources).toEqual([])
    expect(NATIVE_RECIPE_RESEARCH_DATE).toBe('2026-08-30')
  })

  it('resolves every current recipe only to setup guidance, never an executable draft', () => {
    for (const entry of NATIVE_CONNECTOR_RECIPES) {
      expect(resolveNativeRecipe(entry.id)).toEqual({
        kind: 'setup_required', recipe: entry, sourceDraft: null,
      })
      expect(Object.hasOwn(entry, 'enabledTools')).toBe(false)
      expect(Object.hasOwn(entry, 'registry')).toBe(false)
      expect(Object.hasOwn(entry, 'onBehalfOfUser')).toBe(false)
      expect(entry.blockers.length).toBeGreaterThanOrEqual(2)
      expect(entry.blockers.join(' ')).toContain('live canary')
      expect(entry.blockers.join(' ')).toContain('Catalog provenance')
    }
  })

  it.each(['', 'unknown', 'LINEAR', ' linear', 'linear ', '__proto__', 'constructor', 'https://mcp.linear.app/mcp/readonly'])('fails closed for an unknown or non-exact ID: %s', (id) => {
    expect(resolveNativeRecipe(id)).toBeNull()
    expect(formatNativeRecipeSetup(id)).toBeNull()
  })

  it('makes validated records and every nested list immutable', () => {
    expect(Object.isFrozen(NATIVE_CONNECTOR_RECIPES)).toBe(true)
    for (const entry of NATIVE_CONNECTOR_RECIPES) {
      expect(Object.isFrozen(entry)).toBe(true)
      expect(Object.isFrozen(entry.upstreamControls)).toBe(true)
      expect(Object.isFrozen(entry.requiredScopes)).toBe(true)
      expect(Object.isFrozen(entry.documentedReadTools)).toBe(true)
      expect(Object.isFrozen(entry.blockers)).toBe(true)
      expect(Object.isFrozen(entry.setupSteps)).toBe(true)
      expect(Object.isFrozen(entry.evidenceUrls)).toBe(true)
    }
    expect(Object.isFrozen(resolveNativeRecipe('linear'))).toBe(true)
    expect(Reflect.set(recipe(), 'endpoint', 'https://mcp.linear.app/mcp')).toBe(false)
    expect(Reflect.set(recipe().requiredScopes, '0', 'write')).toBe(false)
  })

  it('does not freeze or mutate caller data while validating it', () => {
    const scopes = ['read']
    const input = withChanges({ requiredScopes: scopes })
    const before = JSON.stringify(input)
    const parsed = parseNativeConnectorRecipes(input)
    expect(JSON.stringify(input)).toBe(before)
    expect(Object.isFrozen(input)).toBe(false)
    expect(Object.isFrozen(scopes)).toBe(false)
    scopes.push('write')
    expect(parsed[0]?.requiredScopes).toEqual(['read'])
  })

  it('produces stable copyable instructions with warnings, blockers, and cited evidence', () => {
    for (const entry of NATIVE_CONNECTOR_RECIPES) {
      const before = JSON.stringify(entry)
      const formatted = formatNativeRecipeSetup(entry.id)
      expect(formatted).toBe(formatNativeRecipeSetup(entry.id))
      expect(formatted).toContain(NATIVE_RECIPE_NOTICE)
      expect(formatted).toContain(`Provider endpoint: ${entry.endpoint}`)
      expect(formatted).toContain(NATIVE_RECIPE_STATUS_LABELS[entry.status])
      expect(formatted).toContain('not enabled permissions')
      expect(formatted).toContain('Remaining blockers:')
      expect(formatted).toContain('Never put provider credentials in Ankka')
      for (const evidence of entry.evidenceUrls) expect(formatted).toContain(evidence)
      for (const blocker of entry.blockers) expect(formatted).toContain(blocker)
      expect(JSON.stringify(entry)).toBe(before)
    }
    expect(formatNativeRecipeSetup('linear')).toContain('Exact tool discovery and review required.')
    expect(formatNativeRecipeSetup('github')).toContain('No exact scope set established.')
  })

  it('pins the exact provider endpoints, including read-only paths and regional boundaries', () => {
    expect(Object.fromEntries(NATIVE_CONNECTOR_RECIPES.map((entry) => [entry.id, entry.endpoint]))).toEqual({
      ahrefs: 'https://api.ahrefs.com/mcp/mcp',
      airtable: 'https://mcp.airtable.com/mcp',
      bigquery: 'https://bigquery.googleapis.com/mcp',
      confluence: 'https://mcp.atlassian.com/v1/mcp/authv2',
      github: 'https://api.githubcopilot.com/mcp/readonly',
      gitlab: 'https://gitlab.com/api/v4/mcp',
      'google-drive': 'https://drivemcp.googleapis.com/mcp/v1',
      'google-sheets': 'https://sheetsmcp.googleapis.com/mcp/v1',
      gorgias: 'https://mcp.gorgias.com/mcp',
      hubspot: 'https://mcp.hubspot.com/',
      'intercom-eu': 'https://mcp.eu.intercom.com/mcp',
      'intercom-us': 'https://mcp.intercom.com/mcp',
      jira: 'https://mcp.atlassian.com/v1/mcp/authv2',
      linear: 'https://mcp.linear.app/mcp/readonly',
      notion: 'https://mcp.notion.com/mcp',
      salesforce: 'https://api.salesforce.com/platform/mcp/v1/platform/sobject-reads',
      sentry: 'https://mcp.sentry.dev/mcp',
      slack: 'https://mcp.slack.com/mcp',
      stripe: 'https://mcp.stripe.com/',
    })
  })

  it('keeps BigQuery blocked despite its exact public read tools', () => {
    const bigquery = recipe('bigquery')
    expect(bigquery.status).toBe('manual_setup')
    expect(bigquery.authentication).toBe('oauth_manual_client')
    expect(bigquery.requiredScopes).toEqual(['https://www.googleapis.com/auth/bigquery'])
    expect(bigquery.documentedReadTools).toEqual(['execute_sql_readonly', 'get_table_info', 'list_table_ids'])
    expect(bigquery.blockers.join(' ')).toContain('source_google_shared_oauth_unsupported')
    expect(bigquery.scopeNote).toContain('not invent a bigquery.readonly scope')
    expect(resolveNativeRecipe('bigquery')?.sourceDraft).toBeNull()
  })

  it('keeps native manual-client paths separate from supported operator-shared OAuth', () => {
    expect(NATIVE_CONNECTOR_RECIPES.filter((entry) => entry.authentication === 'oauth_manual_client').map((entry) => entry.id)).toEqual([
      'bigquery', 'github', 'google-drive', 'google-sheets', 'hubspot', 'salesforce', 'slack',
    ])
    for (const entry of NATIVE_CONNECTOR_RECIPES.filter((candidate) => candidate.authentication === 'oauth_manual_client')) {
      expect(entry.status).toBe('manual_setup')
      expect(entry.blockers.join(' ')).toContain('required shared operator connection')
    }
  })

  it('does not authorize an Ahrefs canary or fabricate Gorgias tool names', () => {
    expect(recipe('ahrefs').status).toBe('provider_permission_required')
    expect(recipe('ahrefs').setupSteps[0]).toContain('Do not authenticate or run a canary')
    expect(recipe('ahrefs').documentedReadTools).toEqual([])
    expect(recipe('gorgias').documentedReadTools).toEqual([])
    expect(recipe('gorgias').requiredScopes).toEqual([])
    expect(recipe('gorgias').setupSteps.join(' ')).toContain('production support account')
  })

  it('records exact Airtable and Google Workspace read candidates without write scopes', () => {
    expect(recipe('airtable').authentication).toBe('oauth_dynamic_registration')
    expect(recipe('airtable').documentedReadTools).toEqual(['get_table_schema', 'list_bases', 'list_records_for_table', 'list_tables_for_base'])
    expect(recipe('airtable').requiredScopes).toEqual(['data.recordComments:read', 'data.records:read', 'schema.bases:read', 'workspacesAndBases:read'])
    expect(recipe('google-drive').documentedReadTools).toEqual(['get_file_metadata', 'read_file_content', 'search_files'])
    expect(recipe('google-drive').requiredScopes).toEqual(['https://www.googleapis.com/auth/drive.readonly'])
    expect(recipe('google-sheets').documentedReadTools).toEqual(['get_spreadsheet', 'get_values'])
    expect(recipe('google-sheets').requiredScopes).toEqual(['https://www.googleapis.com/auth/spreadsheets.readonly'])
  })

  it('does not treat Sentry skills as OAuth scopes or approve generic executors', () => {
    const sentry = recipe('sentry')
    expect(sentry.requiredScopes).toEqual([])
    expect(sentry.documentedReadTools).toEqual([])
    expect(sentry.upstreamControls.join(' ')).toContain('only the inspect skill')
    expect(sentry.scopeNote).toContain('not an OAuth scope')
    expect(sentry.scopeNote).toContain('all active skills')
    expect(sentry.blockers.join(' ')).toContain('wrapper executors')
  })

  it('uses Atlassian provider controls and explains their organization-wide effect', () => {
    for (const id of ['jira', 'confluence']) {
      expect(recipe(id).endpoint).toBe('https://mcp.atlassian.com/v1/mcp/authv2')
      expect(recipe(id).upstreamControls.join(' ')).toContain('block Write')
      expect(recipe(id).upstreamControls.join(' ')).toContain('other MCP clients may be affected')
      expect(recipe(id).documentedReadTools).toEqual([])
    }
  })

  it('keeps read-capable but mutation-capable providers pending', () => {
    for (const id of ['gitlab', 'notion', 'intercom-eu', 'intercom-us', 'stripe']) {
      expect(recipe(id).status).toBe('compatibility_pending')
      expect(resolveNativeRecipe(id)?.sourceDraft).toBeNull()
    }
    expect(recipe('stripe').documentedReadTools).not.toContain('stripe_api_write')
    expect(recipe('hubspot').documentedReadTools).not.toContain('manage_crm_objects')
    expect(recipe('intercom-us').documentedReadTools).not.toContain('create_article')
    expect(recipe('slack').requiredScopes).toEqual(['channels:history', 'search:read.public'])
  })
})

describe('native recipe validation boundary', () => {
  it.each([
    'http://mcp.example.com/mcp',
    'https://reader:synthetic@mcp.example.com/mcp',
    'https://mcp.example.com/mcp?scope=write',
    'https://mcp.example.com/mcp?',
    'https://mcp.example.com/mcp#fragment',
    'https://mcp.example.com/mcp#',
    'https://mcp.example.com:8443/mcp',
    'https://mcp.example.com:443/mcp',
    'https://127.0.0.1/mcp',
    'https://[::1]/mcp',
    'https://localhost/mcp',
    'https://example.local/mcp',
    'https://example.internal/mcp',
    'https://example.invalid/mcp',
    'https://example.test/mcp',
    'https://example.onion/mcp',
    'https://MCP.example.com/mcp',
    'https://mcp.example.com/a/../mcp',
    'https://mcp.example.com/{tenant}/mcp',
    'https://mcp.example.com/%7Btenant%7D/mcp',
    ' https://mcp.example.com/mcp',
  ])('rejects noncanonical or credential-bearing endpoint: %s', (endpoint) => {
    expect(() => parseNativeConnectorRecipes(withChanges({ endpoint }))).toThrow(NativeRecipeValidationError)
  })

  it('accepts canonical root endpoints only as setup guidance, not catalog compatibility', () => {
    expect(parseNativeConnectorRecipes(withChanges({ endpoint: 'https://mcp.example.com/' }))[0]?.endpoint).toBe('https://mcp.example.com/')
    expect(resolveNativeRecipe('hubspot')?.sourceDraft).toBeNull()
    expect(resolveNativeRecipe('stripe')?.sourceDraft).toBeNull()
  })

  it.each([
    ['*'], ['read*'], ['read data'], ['read\nwrite'], ['z', 'a'], ['read', 'read'],
  ].map((values) => ({ values })))('rejects non-exact, duplicate or unsorted tool names: $values', ({ values }) => {
    expect(() => parseNativeConnectorRecipes(withChanges({ documentedReadTools: values }))).toThrow(NativeRecipeValidationError)
  })

  it.each([
    ['*'], ['read write'], ['read\nwrite'], ['z', 'a'], ['read', 'read'],
  ].map((values) => ({ values })))('rejects ambiguous, duplicate or unsorted scopes: $values', ({ values }) => {
    expect(() => parseNativeConnectorRecipes(withChanges({ requiredScopes: values }))).toThrow(NativeRecipeValidationError)
  })

  it('rejects duplicate IDs, unstable IDs, unsorted records, and empty manifests', () => {
    expect(() => parseNativeConnectorRecipes([recipe(), recipe()])).toThrow(NativeRecipeValidationError)
    expect(() => parseNativeConnectorRecipes(withChanges({ id: 'Linear_1' }))).toThrow(NativeRecipeValidationError)
    expect(() => parseNativeConnectorRecipes([recipe('linear'), recipe('github')])).toThrow(NativeRecipeValidationError)
    expect(() => parseNativeConnectorRecipes([])).toThrow(NativeRecipeValidationError)
  })

  it('requires evidence, control guidance, blockers and setup steps', () => {
    for (const changes of [
      { evidenceUrls: [] }, { upstreamControls: [] }, { blockers: [] }, { setupSteps: [] },
      { scopeNote: '' }, { description: ' injected\ntext' },
      { evidenceUrls: ['https://docs.example.com/?access=synthetic'] },
      { evidenceUrls: ['https://z.example.com/', 'https://a.example.com/'] },
      { evidenceUrls: ['https://docs.example.com/', 'https://docs.example.com/'] },
      { blockers: ['An unrelated note.', 'Another unrelated note.'] },
    ]) {
      expect(() => parseNativeConnectorRecipes(withChanges(changes))).toThrow(NativeRecipeValidationError)
    }
  })

  it('does not permit manual OAuth to be relabelled as compatible', () => {
    expect(() => parseNativeConnectorRecipes(withChanges({ authentication: 'oauth_manual_client', status: 'compatibility_pending' }))).toThrow(NativeRecipeValidationError)
  })

  it('rejects unknown fields, credentials and fabricated approval state without reflecting values', () => {
    for (const extra of [
      { clientSecret: 'synthetic-do-not-reflect' },
      { headers: { Authorization: 'synthetic-do-not-reflect' } },
      { enabledTools: ['*'] },
      { onBehalfOfUser: true },
      { review: { status: 'ankka_reviewed' } },
      { registry: { serverName: 'example/synthetic' } },
      { sourceDraft: { url: 'https://mcp.example.com/' } },
      { status: 'ready' },
      { authentication: 'bearer' },
    ]) {
      const candidate = Object.assign({}, recipe(), extra)
      expect(() => parseNativeConnectorRecipes([candidate])).toThrowError(
        expect.objectContaining({ name: 'NativeRecipeValidationError', message: 'native_recipe_invalid' }),
      )
    }
  })
})
