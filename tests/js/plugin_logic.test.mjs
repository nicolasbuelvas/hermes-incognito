import { test, beforeEach } from 'node:test'
import assert from 'node:assert/strict'

import { setFocused, toasts } from './stubs/sdk.mjs'
import plugin, {
  describeTtl,
  levelRequest,
  planEngage,
  planLevel,
  planToggle,
  requestBurn,
  runPlan,
  toastFor
} from '../../desktop/plugin.js'

const on = (mode, extra = {}) => ({
  incognito: true,
  session_state: { active: true, mode, ttl_minutes: 60, remaining_seconds: 2520, redact_pii: false, ...extra }
})
const off = { incognito: false, session_state: null, armed: null }

function fakeCtx(status = off, responses = {}) {
  const calls = []
  const registered = []
  return {
    calls,
    registered,
    rest: async (path, opts) => {
      calls.push({ path, body: opts?.body })
      if (path.startsWith('/status')) return status
      return responses[path] ?? { ok: true }
    },
    onEvent: () => () => {},
    onDispose: () => {},
    registerMany: items => registered.push(...items),
    storage: { get: () => false, set: () => {} }
  }
}

beforeEach(() => {
  toasts.length = 0
  setFocused('')
  globalThis.window = undefined
})

test('Engage never turns Incognito off', () => {
  assert.equal(planEngage(on('standard'), 's1', 'standard').action, 'noop')
  assert.equal(planEngage(on('strict'), 's1', 'strict').action, 'noop')
  const sw = planEngage(on('standard'), 's1', 'strict')
  assert.equal(sw.action, 'enable')
  assert.equal(sw.switched, true)
  assert.equal(sw.redact_pii, undefined, 'switching keeps the user masking choice')
})

test('Strict means the same thing from every entry point', () => {
  assert.deepEqual(levelRequest('strict', { isNew: true }), { mode: 'strict', redact_pii: true })
  const fresh = planEngage(off, 's1', 'strict')
  const armed = planEngage(off, '', 'strict')
  assert.equal(fresh.redact_pii, true)
  assert.equal(armed.action, 'arm')
  assert.equal(armed.redact_pii, true)
  assert.equal(planEngage(off, 's1', 'standard').redact_pii, undefined)
})

test('Toggle really turns Incognito off, even from Strict', () => {
  assert.deepEqual(planToggle(on('strict'), 's1'), { action: 'disable', session_id: 's1' })
  assert.deepEqual(planToggle(on('standard'), 's1'), { action: 'disable', session_id: 's1' })
  assert.equal(planToggle(off, 's1').action, 'enable')
  assert.equal(planToggle(off, 's1').mode, 'standard')
  assert.equal(planToggle({ armed: { mode: 'strict' } }, '').action, 'disarm')
  assert.equal(planToggle(off, '').action, 'arm')
  assert.equal(planToggle(on('strict', { pending_burn: true }), 's1').action, 'noop')
})

test('Picking Normal keeps the chat or cancels the armed next chat', () => {
  assert.equal(planLevel(on('strict'), 's1', 'off').action, 'disable')
  assert.equal(planLevel(off, 's1', 'off').action, 'noop')
  assert.equal(planLevel({ armed: { mode: 'standard' } }, '', 'off').action, 'disarm')
})

test('Toasts state the final state', () => {
  assert.match(toastFor({ action: 'disable' }), /Incognito off.*kept/)
  assert.match(toastFor({ action: 'enable', mode: 'strict', switched: true }), /Switched to Strict/)
  assert.match(toastFor({ action: 'enable', mode: 'standard', switched: false }), /Incognito on · Standard/)
  assert.match(toastFor({ action: 'noop', reason: 'already', mode: 'standard' }), /Already in Standard/)
  for (const plan of [{ action: 'disable' }, { action: 'arm', mode: 'strict' }, { action: 'disarm' }]) {
    assert.doesNotMatch(toastFor(plan), /toggled/i)
  }
})

test('TTL line shows the idle deadline and time left', () => {
  assert.equal(describeTtl({ ttl_minutes: 60, remaining_seconds: 2520 }), 'Deleted after 60 min idle · 42 min left')
  assert.equal(describeTtl({ ttl_minutes: 30 }), 'Deleted after 30 min idle')
  assert.equal(describeTtl({ ttl_minutes: 0 }), 'Deleted when you close it')
})

test('runPlan calls the explicit endpoints and never hits /toggle', async () => {
  const ctx = fakeCtx(on('standard'))
  await runPlan(ctx, { action: 'enable', session_id: 's1', mode: 'strict', redact_pii: true, switched: false })
  await runPlan(ctx, { action: 'arm', mode: 'standard' })
  await runPlan(ctx, { action: 'noop', reason: 'already', mode: 'standard' })
  assert.deepEqual(ctx.calls.map(c => c.path), ['/enable', '/arm'])
  assert.deepEqual(ctx.calls[0].body, { session_id: 's1', mode: 'strict', redact_pii: true })
  assert.equal(toasts.length, 3)
})

test('Turning Incognito off keeps the chat, so it asks first like Save', async () => {
  const ctx = fakeCtx(on('standard'))
  await runPlan(ctx, { action: 'disable', session_id: 's1' })
  assert.equal(ctx.calls.filter(c => !c.path.startsWith('/status')).length, 0, 'no confirm, no change')
  globalThis.window = { confirm: () => true }
  await runPlan(ctx, { action: 'disable', session_id: 's1' })
  assert.deepEqual(ctx.calls.filter(c => !c.path.startsWith('/status')).map(c => c.path), ['/save'])
})

test('runPlan reports backend failures instead of a success toast', async () => {
  const ctx = fakeCtx(off, { '/enable': { ok: false, error: 'Invalid session ID.' } })
  assert.equal(await runPlan(ctx, { action: 'enable', session_id: 'x', mode: 'standard' }), null)
  assert.deepEqual(toasts.at(-1), { kind: 'warning', message: 'Invalid session ID.' })
})

test('Delete asks for confirmation before burning', async () => {
  const ctx = fakeCtx()
  globalThis.window = { confirm: () => false }
  await requestBurn(ctx, 's1')
  assert.equal(ctx.calls.length, 0, 'declined confirmation must not burn')

  globalThis.window = { confirm: () => true }
  await requestBurn(ctx, 's1')
  assert.deepEqual(ctx.calls.map(c => c.path), ['/burn'])
})

test('Keybind on a Strict chat turns Incognito off', async () => {
  const ctx = fakeCtx(on('strict'))
  plugin.register(ctx)
  const keybind = ctx.registered.find(c => c.id === 'keybind-toggle')
  setFocused('s1')
  globalThis.window = { confirm: () => true }
  await keybind.data.run()
  const writes = ctx.calls.filter(c => !c.path.startsWith('/status'))
  assert.deepEqual(writes, [{ path: '/save', body: { session_id: 's1' } }])
  assert.match(toasts.at(-1).message, /saved to your history/)
  assert.equal(toasts.at(-1).action.label, 'Undo')
})

test('Palette delete goes through the confirmation', async () => {
  const ctx = fakeCtx(on('standard'))
  plugin.register(ctx)
  const burn = ctx.registered.find(c => c.id === 'palette-burn')
  setFocused('s1')
  globalThis.window = { confirm: () => false }
  await burn.data.run()
  assert.equal(ctx.calls.filter(c => c.path === '/burn').length, 0)
})
