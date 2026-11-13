import { test, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

import { setFocused, toasts } from './stubs/sdk.mjs'
import plugin, {
  MASK_BLOCKED,
  Vault,
  _resetMaskingForTests,
  describeMasked,
  findPii,
  forgetChat,
  getLastSend,
  hint,
  makeMaskingMiddleware,
  maskText,
  maskingFor,
  performUndo,
  planSave,
  previewDraft,
  requestSave,
  saveDialogCopy,
  scrambleFrame,
  undoMinutesLeft,
  vaultFor
} from '../../desktop/plugin.js'

const CASES = JSON.parse(readFileSync(new URL('../fixtures/pii_cases.json', import.meta.url), 'utf8'))
const SECRET_TEXT = 'mail canary@example.org, call +57 311 555 0199, card 4111 1111 1111 1111, password: Tigre#2024'
const RAW = ['canary@example.org', '+57 311 555 0199', '4111 1111 1111 1111', 'Tigre#2024']

const status = ({ active = true, redact = true, counts = {}, saved = null, armed = null } = {}) => ({
  ok: true,
  session_state: active ? { active: true, mode: 'standard', redact_pii: redact, masked_counts: counts, ttl_minutes: 60 } : null,
  saved,
  armed
})

function fakeCtx(st, responses = {}) {
  const calls = []
  return {
    calls,
    registered: [],
    rest: async (path, opts) => {
      calls.push({ path, body: opts?.body })
      if (path.startsWith('/status')) {
        if (st instanceof Error) throw st
        return typeof st === 'function' ? st() : st
      }
      return responses[path] ?? { ok: true, mode: 'standard', undo_seconds: 600 }
    },
    onEvent: () => () => {},
    onDispose: () => {},
    registerMany(items) {
      this.registered.push(...items)
    },
    storage: { get: () => false, set: () => {} }
  }
}

beforeEach(() => {
  toasts.length = 0
  setFocused('')
  globalThis.window = undefined
  _resetMaskingForTests()
})

// --- masker ---------------------------------------------------------------------------------------

test('every fixture positive is masked and every negative left alone', () => {
  for (const c of CASES.positives) {
    const out = maskText(c.text, new Vault())
    assert.ok(!out.text.includes(c.value), `${c.kind} leaked: ${c.text}`)
    assert.ok(out.kinds.includes(c.kind), `${c.kind} not detected in: ${c.text}`)
  }
  for (const n of CASES.negatives) assert.deepEqual(maskText(n, new Vault()).kinds, [], n)
})

test('placeholders are stable, idempotent, and never collide with the backend numbering', () => {
  const vault = new Vault()
  vault.seed({ EMAIL: 2 })
  const a = maskText('x@y.io then z@w.io then x@y.io', vault)
  assert.equal(a.text, '[EMAIL_3] then [EMAIL_4] then [EMAIL_3]')
  assert.deepEqual(maskText(a.text, vault).kinds, [])
  assert.deepEqual(findPii('[EMAIL_1] [PHONE_2]'), [])
  assert.equal(maskText('literal [EMAIL_9] and a@b.co', new Vault()).text, 'literal [EMAIL_9] and [EMAIL_10]')
})

test('the segments rebuild the masked text and carry originals only locally', () => {
  const out = maskText(SECRET_TEXT, new Vault())
  assert.equal(out.segments.map(s => s.text).join(''), out.text)
  for (const raw of RAW) assert.ok(!out.text.includes(raw))
  assert.equal(describeMasked(out.kinds), '4 details masked before sending')
  assert.equal(describeMasked(['EMAIL']), '1 detail masked before sending')
  assert.equal(hint('CARD', '4111 1111 1111 1111'), '•••• 1111')
  assert.ok(!hint('EMAIL', 'canary@example.org').includes('canary'))
})

// --- animation ------------------------------------------------------------------------------------

test('the scramble starts from what was typed and ends exactly on what was sent', () => {
  const out = maskText(SECRET_TEXT, new Vault())
  assert.equal(scrambleFrame(out.segments, 0).join(''), SECRET_TEXT)
  assert.equal(scrambleFrame(out.segments, 1).join(''), out.text)
  for (const t of [0.35, 0.5, 0.8, 0.99]) {
    const frame = scrambleFrame(out.segments, t).join('')
    for (const raw of RAW) assert.ok(!frame.includes(raw), `t=${t} still shows ${raw}`)
  }
})

// --- composer middleware: masks before anything is sent, fails closed --------------------------

test('masking on: the draft is masked before it leaves the composer', async () => {
  setFocused('s1')
  const ctx = fakeCtx(status({ counts: { PHONE: 1 } }))
  const handler = makeMaskingMiddleware(ctx)
  const draft = { text: SECRET_TEXT, attachments: [] }
  const sent = await handler(draft)
  for (const raw of RAW) assert.ok(!sent.text.includes(raw))
  assert.match(sent.text, /\[PHONE_2\]/, 'numbering continues after the backend count')
  assert.equal(draft.text, SECRET_TEXT, 'the caller draft object is not mutated')
  const record = getLastSend()
  assert.equal(record.sessionId, 's1')
  assert.equal(record.masked, sent.text)
  assert.equal(record.kinds.length, 4)
})

test('masking off: the draft passes through untouched', async () => {
  setFocused('s1')
  const handler = makeMaskingMiddleware(fakeCtx(status({ redact: false })))
  const draft = { text: SECRET_TEXT, attachments: [] }
  assert.equal(await handler(draft), draft)
  assert.equal(getLastSend(), null)
})

test('masking turned on a moment ago applies to the very next message', async () => {
  setFocused('s1')
  let current = status({ redact: false })
  const handler = makeMaskingMiddleware(fakeCtx(() => current))
  assert.equal((await handler({ text: SECRET_TEXT })).text, SECRET_TEXT)
  current = status({ redact: true })
  const sent = await handler({ text: SECRET_TEXT })
  for (const raw of RAW) assert.ok(!sent.text.includes(raw))
})

test('a new chat armed with masking is masked on its first message', async () => {
  const handler = makeMaskingMiddleware(fakeCtx(status({ active: false, armed: { mode: 'strict', redact_pii: true } })))
  const sent = await handler({ text: SECRET_TEXT })
  for (const raw of RAW) assert.ok(!sent.text.includes(raw))
})

test('a saved chat inside its undo window keeps masking', async () => {
  setFocused('s1')
  const handler = makeMaskingMiddleware(fakeCtx(status({ active: false, saved: { redact_pii: true, undo_remaining_seconds: 300 } })))
  const sent = await handler({ text: SECRET_TEXT })
  for (const raw of RAW) assert.ok(!sent.text.includes(raw))
})

test('attachments are not sent while masking is on (they cannot be checked)', async () => {
  setFocused('s1')
  const handler = makeMaskingMiddleware(fakeCtx(status()))
  assert.equal(await handler({ text: 'see file', attachments: [{ id: 'a1', kind: 'image' }] }), null)
  assert.equal(toasts.at(-1).message, MASK_BLOCKED.attachments)
})

test('fail closed: a masker error cancels the send instead of sending raw text', async () => {
  setFocused('s1')
  const handler = makeMaskingMiddleware(fakeCtx(status()))
  const evil = {
    get text() {
      throw new Error('boom')
    }
  }
  assert.equal(await handler(evil), null)
  assert.equal(toasts.at(-1).message, MASK_BLOCKED.error)
  assert.ok(!JSON.stringify(toasts).includes('canary'))
})

test('fail closed: if masking was on and the status check fails, nothing is sent', async () => {
  setFocused('s1')
  let current = status()
  const ctx = fakeCtx(() => {
    if (current instanceof Error) throw current
    return current
  })
  const handler = makeMaskingMiddleware(ctx, { fetch: async () => { if (current instanceof Error) throw current; return current } })
  await handler({ text: 'hello' })
  current = new Error('offline')
  assert.equal(await handler({ text: SECRET_TEXT }), null)
  assert.equal(toasts.at(-1).message, MASK_BLOCKED.offline)
})

test('a status error with no masking history passes through (the backend gate still checks)', async () => {
  setFocused('s9')
  const handler = makeMaskingMiddleware(fakeCtx(null), { fetch: async () => null })
  const draft = { text: 'hello' }
  assert.equal(await handler(draft), draft)
})

test('burning a chat forgets its local values', () => {
  const vault = vaultFor('s1')
  maskText('a@b.co', vault)
  assert.equal(vault.size, 1)
  forgetChat('s1')
  assert.equal(vault.size, 0)
})

test('live preview counts what will be masked without sending anything', () => {
  const p = previewDraft(SECRET_TEXT, {})
  assert.equal(p.kinds.length, 4)
  assert.match(p.summary, /email/)
  assert.deepEqual(previewDraft('nothing here', {}).kinds, [])
})

test('maskingFor reads chats, saved chats, and the next new chat', () => {
  assert.deepEqual(maskingFor(status({ counts: { EMAIL: 1 } }), 's1'), { on: true, counts: { EMAIL: 1 } })
  assert.equal(maskingFor(status({ redact: false }), 's1').on, false)
  assert.equal(maskingFor(status({ active: false }), 's1').on, false)
  assert.equal(maskingFor(status({ active: false, armed: { redact_pii: true } }), '').on, true)
  assert.equal(maskingFor(null, 's1'), null)
})

test('the masking middleware is registered with the composer', () => {
  const ctx = fakeCtx(status())
  plugin.register(ctx)
  const mw = ctx.registered.find(c => c.id === 'mask-before-send')
  assert.equal(mw.area, 'composer.middleware')
  assert.equal(typeof mw.data.handler, 'function')
  assert.ok(ctx.registered.find(c => c.id === 'composer-masking-feedback'))
})

// --- save / undo ------------------------------------------------------------------------------------

test('planSave only saves a live Incognito chat', () => {
  assert.deepEqual(planSave(status(), 's1'), { action: 'save', session_id: 's1', masked: true })
  assert.equal(planSave(status(), '').reason, 'no_chat')
  assert.equal(planSave(status({ active: false }), 's1').reason, 'not_incognito')
  assert.equal(planSave(status({ active: false, saved: {} }), 's1').reason, 'already_saved')
  const pending = status()
  pending.session_state.pending_burn = true
  assert.equal(planSave(pending, 's1').reason, 'pending')
})

test('the save dialog says what happens, including masked details', () => {
  const masked = saveDialogCopy({ masked: true, undoMinutes: 10 })
  assert.match(masked.title, /Save this chat/)
  assert.match(masked.description, /chat history/)
  assert.match(masked.description, /won't be deleted automatically/)
  assert.match(masked.description, /stay masked/)
  assert.match(masked.description, /undo this for 10 minutes/)
  assert.doesNotMatch(saveDialogCopy({ masked: false }).description, /masked/)
})

test('cancel changes nothing', async () => {
  const ctx = fakeCtx(status())
  globalThis.window = { confirm: () => false }
  assert.equal(await requestSave(ctx, 's1'), null)
  assert.deepEqual(ctx.calls.filter(c => !c.path.startsWith('/status')), [])
})

test('confirm saves and the toast offers Undo, which returns the chat to Incognito', async () => {
  const ctx = fakeCtx(status())
  globalThis.window = { confirm: () => true }
  await requestSave(ctx, 's1')
  assert.deepEqual(ctx.calls.filter(c => !c.path.startsWith('/status')).map(c => c.path), ['/save'])
  const toast = toasts.at(-1)
  assert.equal(toast.kind, 'success')
  assert.equal(toast.action.label, 'Undo')
  await toast.action.onClick()
  assert.deepEqual(ctx.calls.filter(c => !c.path.startsWith('/status')).map(c => c.path), ['/save', '/undo'])
  assert.match(toasts.at(-1).message, /Back in Incognito/)
})

test('undo failures are reported, not hidden', async () => {
  const ctx = fakeCtx(status(), { '/undo': { ok: false, error: 'Undo is no longer available for this chat.' } })
  assert.equal(await performUndo(ctx, 's1'), null)
  assert.equal(toasts.at(-1).message, 'Undo is no longer available for this chat.')
})

test('the banner countdown rounds up', () => {
  assert.equal(undoMinutesLeft({ undo_remaining_seconds: 61 }), 2)
  assert.equal(undoMinutesLeft({ undo_remaining_seconds: 0 }), 0)
  assert.equal(undoMinutesLeft(null), 0)
})

test('palette offers save and undo', () => {
  const ctx = fakeCtx(status())
  plugin.register(ctx)
  assert.ok(ctx.registered.find(c => c.id === 'palette-save'))
  assert.ok(ctx.registered.find(c => c.id === 'palette-undo-save'))
})
