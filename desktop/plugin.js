import {
  Button,
  COMPOSER_AREAS,
  host,
  KEYBINDS_AREA,
  PALETTE_AREA,
  ROUTES_AREA,
  SIDEBAR_NAV_AREA,
  STATUSBAR_AREAS,
  useValue
} from '@hermes/plugin-sdk'
// Newer UI kit pieces are feature-detected through the namespace so the plugin still
// loads on Desktop builds that predate them (a missing named import fails the module).
import * as sdk from '@hermes/plugin-sdk'
import { useState, useEffect, useCallback } from 'react'
import { jsx, jsxs } from 'react/jsx-runtime'

// -----------------------------------------------------------------------------
// Copy. English, sentence case, plain words, like the rest of Hermes Desktop.
// -----------------------------------------------------------------------------

export const LEVELS = {
  off: {
    label: 'Normal',
    title: 'Normal chat',
    summary: 'Saved to your chat history like any other chat.',
    protects: []
  },
  standard: {
    label: 'Standard',
    title: 'Incognito · Standard',
    summary: "Hidden from your chat list and deleted when you're done. Hermes won't save memories or change skills.",
    protects: [
      'Hidden from the chat list and search',
      'Deleted when the chat closes or sits idle too long',
      'No memory writes or skill changes'
    ]
  },
  strict: {
    label: 'Strict',
    title: 'Incognito · Strict',
    summary: "Everything in Standard, and the model doesn't see your profile or notes. Cross-chat search and scheduled tasks are blocked.",
    protects: [
      'Everything in Standard',
      'Your profile and notes are not sent to the model',
      'Cross-chat search and scheduled tasks are blocked',
      'Sending messages to other apps asks for your confirmation',
      'New Strict chats mask personal details by default'
    ]
  }
}

export const WHEN_TO_USE = [
  { level: 'standard', situation: "A quick question you don't want in your history" },
  { level: 'strict', situation: "A sensitive topic, or you don't want the model to know who you are" },
  { level: 'burn', situation: "You're done and want nothing left behind" }
]

const COPY = {
  pageTitle: 'Incognito',
  pageSubtitle: 'Private chats that leave no trace on this computer.',
  thisChat: 'This chat',
  noChat: 'Open a chat to change its privacy level.',
  nextChat: 'Next new chat',
  nextChatHint: 'Choose how your next new chat starts.',
  nextChatNormal: 'Your next new chat will be a normal chat.',
  guideTitle: 'When to use each level',
  burnLabel: 'Delete now',
  burnAction: 'Delete this chat now…',
  maskLabel: 'Mask personal details',
  maskDescription:
    'Replace emails, phone numbers, and card numbers with placeholders before they reach the model. Replies show the real values.',
  advanced: 'Advanced',
  advancedShow: 'Show audit and verification',
  advancedHide: 'Hide audit and verification',
  exitKeep: 'Exit Incognito, keep chat',
  offline: 'The Incognito backend is not running. Enable it with: hermes plugins enable incognito',
  hintTitle: 'Incognito is available',
  hintBody:
    "Chat without leaving a trace. Standard hides the chat and deletes it when you're done. Strict also keeps your profile and notes away from the model.",
  hintTry: 'Try Standard',
  hintCompare: 'Compare levels',
  hintDismiss: 'Dismiss',
  burnTitle: 'Delete this chat permanently?',
  burnDescription:
    "Hermes will erase its messages, transcript files, and in-memory data from this computer. This can't be undone.",
  burnConfirm: 'Delete permanently',
  burnBusy: 'Deleting…',
  burnCancel: 'Cancel'
}

// -----------------------------------------------------------------------------
// Pure decision logic (exported for tests).
// -----------------------------------------------------------------------------

function currentState(status) {
  const state = status?.session_state || status?.current_session || null
  return state && state.active ? state : null
}

/** Level-specific defaults used by every entry point, so "Strict" means the same thing everywhere. */
export function levelRequest(mode, { isNew }) {
  // A new Strict chat masks personal details by default. Switching an existing chat keeps
  // whatever the user chose with the visible toggle.
  if (mode === 'strict' && isNew) return { mode, redact_pii: true }
  return { mode }
}

/** What "Standard"/"Strict" buttons do. They never turn Incognito off. */
export function planEngage(status, sessionId, mode) {
  if (!sessionId) {
    if (status?.armed?.mode === mode) return { action: 'noop', reason: 'already_armed', mode }
    return { action: 'arm', ...levelRequest(mode, { isNew: true }) }
  }
  const state = currentState(status)
  if (state?.pending_burn) return { action: 'noop', reason: 'pending', mode: state.mode }
  if (state && state.mode === mode) return { action: 'noop', reason: 'already', mode }
  if (state) return { action: 'enable', session_id: sessionId, switched: true, ...levelRequest(mode, { isNew: false }) }
  return { action: 'enable', session_id: sessionId, switched: false, ...levelRequest(mode, { isNew: true }) }
}

/** What the status bar, keybind, and palette toggle do: on ⇄ off, never a silent mode change. */
export function planToggle(status, sessionId) {
  if (!sessionId) {
    if (status?.armed) return { action: 'disarm' }
    return { action: 'arm', ...levelRequest('standard', { isNew: true }) }
  }
  const state = currentState(status)
  if (state?.pending_burn) return { action: 'noop', reason: 'pending', mode: state.mode }
  if (state) return { action: 'disable', session_id: sessionId }
  return { action: 'enable', session_id: sessionId, switched: false, ...levelRequest('standard', { isNew: true }) }
}

/** Picking "Normal" on a chat keeps it; on the next-chat selector it cancels the arm. */
export function planLevel(status, sessionId, level) {
  if (level === 'off') {
    if (!sessionId) return status?.armed ? { action: 'disarm' } : { action: 'noop', reason: 'already', mode: 'off' }
    const state = currentState(status)
    if (state?.pending_burn) return { action: 'noop', reason: 'pending', mode: state.mode }
    return state ? { action: 'disable', session_id: sessionId } : { action: 'noop', reason: 'already', mode: 'off' }
  }
  return planEngage(status, sessionId, level)
}

const levelName = mode => LEVELS[mode]?.label || 'Standard'

/** The toast always states the final state, never "toggled". */
export function toastFor(plan) {
  switch (plan.action) {
    case 'enable':
      return plan.switched
        ? `Switched to ${levelName(plan.mode)}.`
        : `Incognito on · ${levelName(plan.mode)}. This chat will be deleted when you're done.`
    case 'disable':
      return 'Incognito off. This chat will be kept in your history.'
    case 'arm':
      return `Your next new chat will start in Incognito · ${levelName(plan.mode)}.`
    case 'disarm':
      return COPY.nextChatNormal
    case 'noop':
      if (plan.reason === 'pending') return 'This chat is being deleted. Hermes is finishing cleanup.'
      if (plan.reason === 'already_armed') return `Your next new chat already starts in ${levelName(plan.mode)}.`
      return plan.mode === 'off' ? 'This chat is already a normal chat.' : `Already in ${levelName(plan.mode)}.`
    default:
      return ''
  }
}

/** Human TTL line: inactivity deadline plus time left when a chat is live. */
export function describeTtl(state) {
  if (!state) return ''
  const ttl = Number(state.ttl_minutes ?? 0)
  if (!ttl) return 'Deleted when you close it'
  const base = `Deleted after ${ttl} min idle`
  if (state.remaining_seconds == null) return base
  const left = Math.max(0, Math.ceil(Number(state.remaining_seconds) / 60))
  return `${base} · ${left} min left`
}

// -----------------------------------------------------------------------------
// Backend calls
// -----------------------------------------------------------------------------

const stateListeners = new Set()

function notifyStateListeners() {
  for (const listener of stateListeners) {
    try {
      listener()
    } catch {
      // Ignore listener errors
    }
  }
}

async function callBackend(ctx, action, payload = {}) {
  try {
    if (ctx && typeof ctx.rest === 'function') {
      const isGet = action === 'status' && Object.keys(payload || {}).every(k => k === 'session_id')
      if (isGet) {
        const query = payload?.session_id ? `?session_id=${encodeURIComponent(payload.session_id)}` : ''
        const res = await ctx.rest(`/${action}${query}`)
        if (res) return res
      } else {
        const res = await ctx.rest(`/${action}`, { method: 'POST', body: payload })
        if (res) return res
      }
    }
  } catch {
    // Fall back to gateway JSON-RPC
  }

  try {
    if (host && typeof host.request === 'function') {
      const res = await host.request(`plugin.incognito.${action}`, payload)
      if (res) return res
    }
  } catch {
    // Both transports unavailable
  }
  return null
}

function notify(kind, message) {
  try {
    host?.notify?.({ kind, message })
  } catch {
    // Toasts are best-effort
  }
}

/** Execute a plan from planEngage/planToggle/planLevel and toast the final state. */
export async function runPlan(ctx, plan) {
  if (plan.action === 'noop') {
    notify('info', toastFor(plan))
    return plan
  }
  let result = null
  if (plan.action === 'enable') {
    const body = { session_id: plan.session_id, mode: plan.mode }
    if (plan.redact_pii !== undefined) body.redact_pii = plan.redact_pii
    result = await callBackend(ctx, 'enable', body)
  } else if (plan.action === 'disable') {
    result = await callBackend(ctx, 'disable', { session_id: plan.session_id })
  } else if (plan.action === 'arm') {
    const body = { mode: plan.mode }
    if (plan.redact_pii !== undefined) body.redact_pii = plan.redact_pii
    result = await callBackend(ctx, 'arm', body)
  } else if (plan.action === 'disarm') {
    result = await callBackend(ctx, 'arm', { disarm: true })
  }
  if (!result?.ok) {
    notify('warning', result?.error || "Couldn't change Incognito. Try again.")
    return null
  }
  notifyStateListeners()
  notify('info', toastFor(plan))
  return result
}

async function fetchStatus(ctx, sessionId) {
  return callBackend(ctx, 'status', { session_id: sessionId || '' })
}

async function toggleFocused(ctx) {
  const sid = host?.state?.focusedSessionId?.get?.() || ''
  const status = await fetchStatus(ctx, sid)
  return runPlan(ctx, planToggle(status, sid))
}

async function engageFocused(ctx, mode) {
  const sid = host?.state?.focusedSessionId?.get?.() || ''
  const status = await fetchStatus(ctx, sid)
  return runPlan(ctx, planEngage(status, sid, mode))
}

async function setMasking(ctx, sessionId, status, on) {
  if (sessionId) {
    const state = currentState(status)
    if (!state) return null
    const res = await callBackend(ctx, 'enable', { session_id: sessionId, mode: state.mode, redact_pii: on })
    if (!res?.ok) return notify('warning', res?.error || "Couldn't change masking.")
  } else if (status?.armed) {
    const res = await callBackend(ctx, 'arm', { mode: status.armed.mode, redact_pii: on })
    if (!res?.ok) return notify('warning', res?.error || "Couldn't change masking.")
  }
  notifyStateListeners()
  notify('info', on ? 'Personal details will be masked.' : 'Personal details will be sent as written.')
}

// -----------------------------------------------------------------------------
// Burn confirmation: one dialog host, used by every delete entry point.
// -----------------------------------------------------------------------------

const burnHosts = new Set()

async function performBurn(ctx, sessionId) {
  const response = await callBackend(ctx, 'burn', { session_id: sessionId })
  const result = response?.receipt || response
  if (!response?.ok || !result?.ok) {
    throw new Error(response?.error || result?.error || "Couldn't delete this chat.")
  }
  notifyStateListeners()
  notify(
    'info',
    result.pending_burn
      ? 'Deleting. Hermes will finish cleanup in a moment; the chat stays protected until then.'
      : 'Chat deleted. Nothing was left on this computer.'
  )
}

/** Ask for confirmation, then burn. Falls back to the native confirm on older Desktop builds. */
export async function requestBurn(ctx, sessionId) {
  if (!sessionId) {
    notify('warning', 'Open a chat to delete it.')
    return
  }
  if (burnHosts.size && sdk.ConfirmDialog) {
    for (const open of burnHosts) open(sessionId)
    return
  }
  const ok = typeof window !== 'undefined' && typeof window.confirm === 'function'
    ? window.confirm(`${COPY.burnTitle}\n\n${COPY.burnDescription}`)
    : false
  if (!ok) return
  try {
    await performBurn(ctx, sessionId)
  } catch (error) {
    notify('warning', error.message)
  }
}

function BurnDialogHost({ ctx }) {
  const [target, setTarget] = useState('')

  useEffect(() => {
    const open = sid => setTarget(sid)
    burnHosts.add(open)
    return () => {
      burnHosts.delete(open)
    }
  }, [])

  const ConfirmDialog = sdk.ConfirmDialog
  if (!ConfirmDialog) return null
  return jsx(ConfirmDialog, {
    open: Boolean(target),
    onClose: () => setTarget(''),
    onConfirm: () => performBurn(ctx, target),
    title: COPY.burnTitle,
    description: COPY.burnDescription,
    confirmLabel: COPY.burnConfirm,
    busyLabel: COPY.burnBusy,
    cancelLabel: COPY.burnCancel,
    destructive: true
  })
}

// -----------------------------------------------------------------------------
// Small UI helpers built on the Hermes UI kit, with plain fallbacks.
// -----------------------------------------------------------------------------

const text = {
  primary: 'var(--ui-text-primary)',
  secondary: 'var(--ui-text-secondary)',
  tertiary: 'var(--ui-text-tertiary)'
}

const levelTone = mode => (mode === 'strict' ? 'var(--ui-purple)' : mode === 'standard' ? 'var(--ui-accent)' : 'var(--ui-text-quaternary)')

function Tip({ label, children }) {
  return sdk.Tip ? jsx(sdk.Tip, { label, children }) : children
}

function Dot({ mode, armed }) {
  return jsx('span', {
    'aria-hidden': true,
    style: {
      display: 'inline-block',
      width: '6px',
      height: '6px',
      borderRadius: '999px',
      flexShrink: 0,
      background: armed ? 'var(--ui-yellow)' : levelTone(mode)
    }
  })
}

function LevelBadge({ mode }) {
  const label = mode === 'off' ? 'Normal' : `Incognito · ${levelName(mode)}`
  if (sdk.Badge) {
    return jsx(sdk.Badge, { variant: mode === 'strict' ? 'solid' : mode === 'standard' ? 'default' : 'muted', children: label })
  }
  return jsx('span', {
    style: {
      fontSize: '11px',
      fontWeight: 500,
      padding: '2px 6px',
      borderRadius: '3px',
      color: mode === 'off' ? text.secondary : levelTone(mode),
      boxShadow: 'inset 0 0 0 1px var(--ui-stroke-secondary)'
    },
    children: label
  })
}

function LevelPicker({ value, onChange, disabled }) {
  const options = ['off', 'standard', 'strict'].map(id => ({ id, label: LEVELS[id].label }))
  if (sdk.SegmentedControl) {
    return jsx(sdk.SegmentedControl, { options, value, onChange, disabled })
  }
  return jsx('div', {
    role: 'radiogroup',
    style: { display: 'inline-flex', gap: '2px' },
    children: options.map(opt =>
      jsx(
        Button,
        {
          size: 'sm',
          variant: opt.id === value ? 'secondary' : 'ghost',
          role: 'radio',
          'aria-checked': opt.id === value,
          disabled,
          onClick: () => onChange(opt.id),
          children: opt.label
        },
        opt.id
      )
    )
  })
}

function MaskToggle({ checked, disabled, onChange }) {
  if (sdk.ToggleRow) {
    return jsx(sdk.ToggleRow, {
      label: COPY.maskLabel,
      description: COPY.maskDescription,
      checked,
      disabled,
      onChange
    })
  }
  const control = sdk.Switch
    ? jsx(sdk.Switch, { checked, disabled, onCheckedChange: onChange, 'aria-label': COPY.maskLabel })
    : jsx('input', { type: 'checkbox', checked, disabled, onChange: e => onChange(e.target.checked), 'aria-label': COPY.maskLabel })
  return jsxs('div', {
    style: { display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '16px', padding: '8px 0' },
    children: [
      jsxs('div', {
        children: [
          jsx('div', { style: { fontSize: '12px', fontWeight: 500, color: text.primary }, children: COPY.maskLabel }),
          jsx('div', { style: { fontSize: '12px', color: text.tertiary, marginTop: '2px' }, children: COPY.maskDescription })
        ]
      }),
      control
    ]
  })
}

function useIncognitoStatus(ctx, sessionId, { poll = false } = {}) {
  const [status, setStatus] = useState(null)
  const [offline, setOffline] = useState(false)

  const refresh = useCallback(async () => {
    const res = await fetchStatus(ctx, sessionId)
    if (res) {
      setStatus(res)
      setOffline(false)
    } else {
      setOffline(true)
    }
  }, [ctx, sessionId])

  useEffect(() => {
    let live = true
    const guarded = () => live && refresh()
    guarded()
    stateListeners.add(guarded)
    // Keep "min left" honest without polling hard (the SDK asks for >= a few seconds).
    const stop = poll && typeof ctx?.setInterval === 'function' ? ctx.setInterval(guarded, 30000) : null
    return () => {
      live = false
      stateListeners.delete(guarded)
      if (typeof stop === 'function') stop()
    }
  }, [ctx, refresh, poll])

  return { status, offline }
}

const HINT_KEY = 'firstRunHintDismissed'

function hintDismissed(ctx) {
  try {
    return Boolean(ctx?.storage?.get?.(HINT_KEY, false))
  } catch {
    return false
  }
}

function dismissHint(ctx) {
  try {
    ctx?.storage?.set?.(HINT_KEY, true)
  } catch {
    // Storage is best-effort
  }
}

const card = {
  background: 'var(--ui-bg-card)',
  boxShadow: 'inset 0 0 0 1px var(--ui-stroke-tertiary)',
  borderRadius: '6px',
  padding: '16px'
}

const heading = { fontSize: '13px', fontWeight: 600, color: text.primary, margin: '0 0 4px 0' }
const caption = { fontSize: '12px', color: text.tertiary, margin: 0, lineHeight: '18px' }

function OfflineNotice() {
  return jsx('div', {
    role: 'status',
    style: { ...caption, color: 'var(--ui-yellow)', fontFamily: 'var(--font-mono)' },
    children: COPY.offline
  })
}

// -----------------------------------------------------------------------------
// Composer: first-run hint and active-chat banner
// -----------------------------------------------------------------------------

function FirstRunHint({ ctx, onDone }) {
  const close = () => {
    dismissHint(ctx)
    onDone()
  }
  return jsxs('div', {
    role: 'note',
    style: { ...card, padding: '10px 12px', marginBottom: '6px', display: 'flex', gap: '12px', alignItems: 'flex-start' },
    children: [
      jsx('div', { style: { paddingTop: '6px' }, children: jsx(Dot, { mode: 'standard' }) }),
      jsxs('div', {
        style: { flex: 1, minWidth: 0 },
        children: [
          jsx('div', { style: { fontSize: '12px', fontWeight: 600, color: text.primary }, children: COPY.hintTitle }),
          jsx('p', { style: { ...caption, marginTop: '2px' }, children: COPY.hintBody }),
          jsxs('div', {
            style: { display: 'flex', gap: '6px', marginTop: '8px', flexWrap: 'wrap' },
            children: [
              jsx(Button, {
                size: 'sm',
                variant: 'secondary',
                onClick: async () => {
                  close()
                  await engageFocused(ctx, 'standard')
                },
                children: COPY.hintTry
              }),
              jsx(Button, {
                size: 'sm',
                variant: 'ghost',
                onClick: () => {
                  close()
                  host?.navigate?.('/incognito')
                },
                children: COPY.hintCompare
              })
            ]
          })
        ]
      }),
      jsx(Button, { size: 'sm', variant: 'text', onClick: close, 'aria-label': COPY.hintDismiss, children: COPY.hintDismiss })
    ]
  })
}

function ComposerPrivacyBanner({ ctx }) {
  const focusedSessionId = useValue(host?.state?.focusedSessionId) || ''
  const { status, offline } = useIncognitoStatus(ctx, focusedSessionId, { poll: true })
  const [hintHidden, setHintHidden] = useState(() => hintDismissed(ctx))

  const state = currentState(status)
  const armedDraft = !focusedSessionId && status?.armed ? status.armed : null

  if (!state && !armedDraft) {
    if (hintHidden || offline || !status) return null
    return jsx(FirstRunHint, { ctx, onDone: () => setHintHidden(true) })
  }

  const mode = state?.mode || armedDraft?.mode || 'standard'
  const other = mode === 'strict' ? 'standard' : 'strict'
  const masking = Boolean(state ? state.redact_pii : armedDraft?.redact_pii)
  const detail = state ? describeTtl(state) : 'Your next new chat starts in Incognito'

  return jsxs('div', {
    role: 'status',
    style: {
      ...card,
      padding: '8px 12px',
      marginBottom: '6px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      flexWrap: 'wrap',
      gap: '8px',
      boxShadow: `inset 2px 0 0 0 ${levelTone(mode)}, inset 0 0 0 1px var(--ui-stroke-tertiary)`
    },
    children: [
      jsxs('div', {
        style: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', minWidth: 0 },
        children: [
          jsx(Tip, { label: LEVELS[mode].summary, children: jsx('span', { children: jsx(LevelBadge, { mode }) }) }),
          jsx('span', { style: { fontSize: '12px', color: text.secondary }, children: detail }),
          masking
            ? jsx(Tip, {
                label: COPY.maskDescription,
                children: jsx('span', { style: { fontSize: '12px', color: text.tertiary }, children: '· Personal details masked' })
              })
            : null,
          state?.pending_burn
            ? jsx('span', { style: { fontSize: '12px', color: 'var(--ui-yellow)' }, children: '· Finishing deletion' })
            : null
        ]
      }),
      armedDraft
        ? jsx(Button, {
            size: 'sm',
            variant: 'ghost',
            onClick: () => runPlan(ctx, { action: 'disarm' }),
            children: 'Start as a normal chat'
          })
        : jsxs('div', {
            style: { display: 'flex', alignItems: 'center', gap: '6px' },
            children: [
              jsx(Tip, {
                label: LEVELS[other].summary,
                children: jsx(Button, {
                  size: 'sm',
                  variant: 'outline',
                  disabled: Boolean(state?.pending_burn),
                  onClick: () => runPlan(ctx, planEngage(status, focusedSessionId, other)),
                  children: `Switch to ${levelName(other)}`
                })
              }),
              jsx(Button, {
                size: 'sm',
                variant: 'ghost',
                disabled: Boolean(state?.pending_burn),
                onClick: () => runPlan(ctx, planToggle(status, focusedSessionId)),
                children: COPY.exitKeep
              }),
              jsx(Button, {
                size: 'sm',
                variant: 'destructive',
                onClick: () => requestBurn(ctx, focusedSessionId),
                children: `${COPY.burnLabel}…`
              })
            ]
          })
    ]
  })
}

// -----------------------------------------------------------------------------
// Status bar
// -----------------------------------------------------------------------------

function StatusbarIndicator({ ctx }) {
  const focusedSessionId = useValue(host?.state?.focusedSessionId) || ''
  const { status } = useIncognitoStatus(ctx, focusedSessionId)
  const state = currentState(status)
  const armed = !focusedSessionId && status?.armed ? status.armed : null

  let label = 'Incognito off'
  let tip = 'Normal chat, saved to your history. Click to turn on Incognito · Standard.'
  let mode = 'off'
  if (state) {
    mode = state.mode
    label = `Incognito · ${levelName(mode)}`
    tip = `${LEVELS[mode].summary} ${describeTtl(state)}. Click to turn off and keep this chat.`
  } else if (armed) {
    mode = armed.mode
    label = `Next chat: Incognito · ${levelName(mode)}`
    tip = 'Your next new chat starts in Incognito. Click to start it as a normal chat instead.'
  }

  return jsxs('span', {
    style: { display: 'inline-flex', alignItems: 'center', height: '100%' },
    children: [
      jsx(Tip, {
        label: tip,
        children: jsxs('button', {
          type: 'button',
          onClick: () => runPlan(ctx, planToggle(status, focusedSessionId)),
          'aria-label': `${label}. ${tip}`,
          style: {
            background: 'transparent',
            border: 'none',
            cursor: 'pointer',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            padding: '0 6px',
            height: '100%',
            font: 'inherit',
            fontSize: '11px',
            color: state || armed ? text.secondary : text.tertiary
          },
          children: [jsx(Dot, { mode, armed: Boolean(armed) }), label]
        })
      }),
      // The status bar is always mounted, so it hosts the shared delete confirmation.
      jsx(BurnDialogHost, { ctx })
    ]
  })
}

// -----------------------------------------------------------------------------
// Privacy center page
// -----------------------------------------------------------------------------

function LevelDetails({ mode }) {
  const level = LEVELS[mode]
  return jsxs('div', {
    style: { marginTop: '10px' },
    children: [
      jsx('p', { style: { ...caption, color: text.secondary }, children: level.summary }),
      level.protects.length
        ? jsx('ul', {
            style: { ...caption, margin: '6px 0 0 0', paddingLeft: '18px' },
            children: level.protects.map(item => jsx('li', { children: item }, item))
          })
        : null
    ]
  })
}

function ThisChatCard({ ctx, sessionId, status }) {
  const state = currentState(status)
  const mode = state?.mode || 'off'

  return jsxs('section', {
    style: card,
    children: [
      jsx('h2', { style: heading, children: COPY.thisChat }),
      sessionId
        ? jsxs('div', {
            style: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', marginBottom: '12px' },
            children: [
              jsx(LevelBadge, { mode }),
              jsx('span', {
                style: { fontSize: '12px', color: text.tertiary },
                children: state ? describeTtl(state) : ''
              })
            ]
          })
        : jsx('p', { style: { ...caption, marginBottom: '12px' }, children: COPY.noChat }),
      jsx(LevelPicker, {
        value: mode,
        disabled: !sessionId || Boolean(state?.pending_burn),
        onChange: level => runPlan(ctx, planLevel(status, sessionId, level))
      }),
      jsx(LevelDetails, { mode }),
      jsx('div', {
        style: { marginTop: '12px' },
        children: jsx(MaskToggle, {
          checked: Boolean(state?.redact_pii),
          disabled: !state || Boolean(state?.pending_burn),
          onChange: on => setMasking(ctx, sessionId, status, on)
        })
      }),
      jsx('div', {
        style: { marginTop: '12px', display: 'flex', gap: '8px' },
        children: jsx(Button, {
          size: 'sm',
          variant: 'destructive',
          disabled: !state,
          onClick: () => requestBurn(ctx, sessionId),
          children: COPY.burnAction
        })
      })
    ]
  })
}

function NextChatCard({ ctx, status }) {
  const armed = status?.armed || null
  const value = armed?.mode || 'off'
  return jsxs('section', {
    style: card,
    children: [
      jsx('h2', { style: heading, children: COPY.nextChat }),
      jsx('p', { style: { ...caption, marginBottom: '12px' }, children: COPY.nextChatHint }),
      jsx(LevelPicker, { value, onChange: level => runPlan(ctx, planLevel(status, '', level)) }),
      jsx('p', {
        style: { ...caption, marginTop: '10px', color: text.secondary },
        children: armed ? `Your next new chat will start in Incognito · ${levelName(armed.mode)}.` : COPY.nextChatNormal
      }),
      armed
        ? jsx('div', {
            style: { marginTop: '8px' },
            children: jsx(MaskToggle, {
              checked: Boolean(armed.redact_pii),
              onChange: on => setMasking(ctx, '', status, on)
            })
          })
        : null
    ]
  })
}

function GuideCard() {
  return jsxs('section', {
    style: card,
    children: [
      jsx('h2', { style: heading, children: COPY.guideTitle }),
      jsx('div', {
        style: { display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) auto', gap: '8px 16px', marginTop: '8px' },
        children: WHEN_TO_USE.flatMap(row => [
          jsx('span', { style: { fontSize: '12px', color: text.secondary }, children: row.situation }, `${row.level}-s`),
          jsxs(
            'span',
            {
              style: { display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '12px', fontWeight: 500, color: text.primary },
              children: [
                row.level === 'burn' ? null : jsx(Dot, { mode: row.level }),
                row.level === 'burn' ? COPY.burnLabel : levelName(row.level)
              ]
            },
            `${row.level}-l`
          )
        ])
      })
    ]
  })
}

function Metric({ value, label }) {
  return jsxs('div', {
    style: { padding: '10px', borderRadius: '4px', background: 'var(--ui-bg-tertiary)' },
    children: [
      jsx('div', { style: { fontSize: '16px', fontWeight: 600, fontFamily: 'var(--font-mono)', color: text.primary }, children: String(value ?? 0) }),
      jsx('div', { style: { fontSize: '11px', color: text.tertiary, marginTop: '2px' }, children: label })
    ]
  })
}

function AdvancedSection({ ctx, status, focusedSessionId }) {
  const [open, setOpen] = useState(false)
  const [verifyId, setVerifyId] = useState(focusedSessionId)
  const [verification, setVerification] = useState(null)
  const [verifying, setVerifying] = useState(false)
  const metrics = status?.metrics || {}

  useEffect(() => {
    if (focusedSessionId && !verifyId) setVerifyId(focusedSessionId)
  }, [focusedSessionId, verifyId])

  const handleVerify = async () => {
    if (!verifyId) return
    setVerifying(true)
    const res = await callBackend(ctx, 'verify', { session_id: verifyId })
    setVerifying(false)
    if (res?.verification) setVerification(res.verification)
    else notify('warning', res?.error || "Couldn't run the check.")
  }

  const clean = verification?.zero_trace
  return jsxs('section', {
    style: card,
    children: [
      jsxs('div', {
        style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' },
        children: [
          jsx('h2', { style: { ...heading, margin: 0 }, children: COPY.advanced }),
          jsx(Button, {
            size: 'sm',
            variant: 'ghost',
            'aria-expanded': open,
            onClick: () => setOpen(!open),
            children: open ? COPY.advancedHide : COPY.advancedShow
          })
        ]
      }),
      open
        ? jsxs('div', {
            style: { marginTop: '12px', display: 'flex', flexDirection: 'column', gap: '16px' },
            children: [
              jsxs('div', {
                children: [
                  jsx('p', { style: { ...caption, marginBottom: '8px' }, children: 'Totals on this computer. No chat content is recorded.' }),
                  jsx('div', {
                    style: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '8px' },
                    children: [
                      jsx(Metric, { value: metrics.sessions_protected, label: 'Incognito chats' }, 'p'),
                      jsx(Metric, { value: metrics.sessions_burned, label: 'Chats deleted' }, 'b'),
                      jsx(Metric, { value: metrics.orphans_swept, label: 'Expired chats cleaned up' }, 'o'),
                      jsx(Metric, { value: metrics.blocked_writes, label: 'Memory writes blocked' }, 'w'),
                      jsx(Metric, { value: metrics.pii_tokens_masked, label: 'Personal details masked' }, 'm'),
                      jsx(Metric, { value: metrics.files_zero_filled, label: 'Files overwritten' }, 'f')
                    ]
                  })
                ]
              }),
              jsxs('div', {
                children: [
                  jsx('div', { style: { fontSize: '12px', fontWeight: 600, color: text.primary }, children: 'Check for leftovers' }),
                  jsx('p', {
                    style: { ...caption, margin: '2px 0 8px 0' },
                    children: 'Confirm a deleted chat left nothing behind in the local database, transcript files, hook outputs, or memory.'
                  }),
                  jsxs('div', {
                    style: { display: 'flex', gap: '8px' },
                    children: [
                      jsx(sdk.Input || 'input', {
                        value: verifyId,
                        placeholder: 'Chat ID',
                        'aria-label': 'Chat ID',
                        onChange: e => setVerifyId(e.target.value),
                        style: { flex: 1, fontFamily: 'var(--font-mono)', fontSize: '12px' }
                      }),
                      jsx(Button, {
                        size: 'sm',
                        variant: 'secondary',
                        disabled: verifying || !verifyId,
                        onClick: handleVerify,
                        children: verifying ? 'Checking…' : 'Check'
                      })
                    ]
                  }),
                  verification
                    ? jsxs('div', {
                        role: 'status',
                        style: { marginTop: '8px', fontSize: '12px', color: text.secondary, fontFamily: 'var(--font-mono)' },
                        children: [
                          jsx('div', {
                            style: { fontFamily: 'inherit', fontWeight: 600, color: clean ? 'var(--ui-green)' : 'var(--ui-yellow)' },
                            children: clean ? 'Nothing left behind.' : 'Leftovers found.'
                          }),
                          jsx('div', {
                            children: `Database rows ${verification.db_rows_found ?? 0} · Transcripts ${verification.session_files_found ?? 0} · Hook files ${verification.hook_files_found ?? 0} · Memory ${verification.ram_vault_entries ?? 0}`
                          }),
                          verification.receipt_id ? jsx('div', { children: `Receipt ${verification.receipt_id}` }) : null
                        ]
                      })
                    : null
                ]
              })
            ]
          })
        : null
    ]
  })
}

function PrivacyControlCenter({ ctx }) {
  const focusedSessionId = useValue(host?.state?.focusedSessionId) || ''
  const { status, offline } = useIncognitoStatus(ctx, focusedSessionId, { poll: true })

  useEffect(() => {
    // Visiting the page counts as having seen the first-run hint.
    dismissHint(ctx)
  }, [ctx])

  return jsxs('div', {
    style: {
      padding: '24px',
      maxWidth: '880px',
      margin: '0 auto',
      display: 'flex',
      flexDirection: 'column',
      gap: '16px',
      color: text.primary
    },
    children: [
      jsxs('header', {
        children: [
          jsx('h1', { style: { fontSize: '18px', fontWeight: 600, margin: '0 0 4px 0' }, children: COPY.pageTitle }),
          jsx('p', { style: caption, children: COPY.pageSubtitle })
        ]
      }),
      offline ? jsx(OfflineNotice, {}) : null,
      jsxs('div', {
        style: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px', alignItems: 'start' },
        children: [
          jsx(ThisChatCard, { ctx, sessionId: focusedSessionId, status }),
          jsxs('div', {
            style: { display: 'flex', flexDirection: 'column', gap: '16px' },
            children: [jsx(GuideCard, {}), jsx(NextChatCard, { ctx, status })]
          })
        ]
      }),
      jsx(AdvancedSection, { ctx, status, focusedSessionId })
    ]
  })
}

// -----------------------------------------------------------------------------
// Registration
// -----------------------------------------------------------------------------

export default {
  id: 'incognito',
  name: 'Incognito Sessions',
  description: 'Private chats that leave no trace: hidden, auto-deleted, with optional profile and PII protection.',
  register(ctx) {
    const refreshAll = () => notifyStateListeners()
    const unbind1 = ctx.onEvent?.('plugin.incognito.state.changed', refreshAll)
    const unbind2 = ctx.onEvent?.('plugin.incognito.settings.changed', refreshAll)

    ctx.onDispose(() => {
      if (typeof unbind1 === 'function') unbind1()
      if (typeof unbind2 === 'function') unbind2()
      stateListeners.clear()
      burnHosts.clear()
    })

    const focused = () => host?.state?.focusedSessionId?.get?.() || ''

    ctx.registerMany([
      {
        id: 'composer-privacy-banner',
        area: COMPOSER_AREAS.top,
        render: () => jsx(ComposerPrivacyBanner, { ctx })
      },
      {
        id: 'statusbar-indicator',
        area: STATUSBAR_AREAS.right,
        order: 115,
        render: () => jsx(StatusbarIndicator, { ctx })
      },
      {
        id: 'route-control-center',
        area: ROUTES_AREA,
        data: { path: '/incognito' },
        render: () => jsx(PrivacyControlCenter, { ctx })
      },
      {
        id: 'nav-control-center',
        area: SIDEBAR_NAV_AREA,
        data: {
          path: '/incognito',
          label: 'Incognito',
          codicon: 'eye-closed'
        }
      },
      {
        id: 'keybind-toggle',
        area: KEYBINDS_AREA,
        data: {
          id: 'incognito.toggle',
          label: 'Turn Incognito on or off for this chat',
          category: 'Privacy',
          defaults: ['mod+shift+i'],
          run: () => toggleFocused(ctx)
        }
      },
      {
        id: 'palette-toggle',
        area: PALETTE_AREA,
        data: {
          id: 'incognito.palette.toggle',
          label: 'Incognito: Turn on or off for this chat',
          keywords: ['incognito', 'privacy', 'private', 'ephemeral', 'toggle'],
          run: () => toggleFocused(ctx)
        }
      },
      {
        id: 'palette-standard',
        area: PALETTE_AREA,
        data: {
          id: 'incognito.palette.standard',
          label: 'Incognito: Use Standard for this chat',
          keywords: ['incognito', 'standard', 'privacy'],
          run: () => engageFocused(ctx, 'standard')
        }
      },
      {
        id: 'palette-strict',
        area: PALETTE_AREA,
        data: {
          id: 'incognito.palette.strict',
          label: 'Incognito: Use Strict for this chat',
          keywords: ['incognito', 'strict', 'clean-room', 'privacy'],
          run: () => engageFocused(ctx, 'strict')
        }
      },
      {
        id: 'palette-arm',
        area: PALETTE_AREA,
        data: {
          id: 'incognito.palette.arm',
          label: 'Incognito: Start my next new chat in Incognito',
          keywords: ['incognito', 'next', 'new', 'draft', 'arm'],
          run: async () => runPlan(ctx, planEngage(await fetchStatus(ctx, ''), '', 'standard'))
        }
      },
      {
        id: 'palette-burn',
        area: PALETTE_AREA,
        data: {
          id: 'incognito.palette.burn',
          label: 'Incognito: Delete this chat now…',
          keywords: ['incognito', 'burn', 'delete', 'purge', 'scrub'],
          run: () => requestBurn(ctx, focused())
        }
      },
      {
        id: 'palette-open',
        area: PALETTE_AREA,
        data: {
          id: 'incognito.palette.open',
          label: 'Incognito: Open privacy levels',
          keywords: ['incognito', 'privacy', 'levels', 'audit', 'verify'],
          run: () => host?.navigate?.('/incognito')
        }
      }
    ])
  }
}
