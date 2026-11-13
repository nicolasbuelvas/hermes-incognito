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
    summary: "Hidden from your chat list. Hermes won't save memories or change skills.",
    protects: [
      'Hidden from the chat list and search',
      'Cleanup on close or on a sweep after the idle limit',
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
    'Before anything is sent, emails, phones, card numbers, IBANs, IDs, IP addresses, passwords, API keys, and street addresses become placeholders like [EMAIL_1]. The real values stay on this computer. If a message can\'t be checked, it isn\'t sent.',
  advanced: 'Advanced',
  advancedShow: 'Show audit and verification',
  advancedHide: 'Hide audit and verification',
  offline: 'The Incognito backend is not running. Enable it with: hermes plugins enable incognito',
  hintTitle: 'Incognito is available',
  hintBody:
    "Standard hides the chat and supports local cleanup. Strict also keeps your profile and notes away from the model.",
  hintTry: 'Try Standard',
  hintCompare: 'Compare levels',
  hintDismiss: 'Dismiss',
  burnTitle: 'Delete this chat permanently?',
  burnDescription:
    "Hermes will erase its messages, transcript files, and in-memory data from this computer. This can't be undone.",
  burnConfirm: 'Delete permanently',
  burnBusy: 'Deleting…',
  burnCancel: 'Cancel',
  saveAction: 'Save this chat…',
  saveTitle: 'Save this chat to your history?',
  saveConfirm: 'Save chat',
  saveBusy: 'Saving…',
  saveCancel: 'Keep in Incognito',
  undoSave: 'Return to Incognito'
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
        : `Incognito on · ${levelName(plan.mode)}. Incognito protections are active.`
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
  if (!ttl) return state.auto_purge_on_exit === false ? 'Manual cleanup' : 'Cleanup on close'
  const base = `Eligible for cleanup after ${ttl} min idle`
  if (state.remaining_seconds == null) return base
  const left = Math.max(0, Math.ceil(Number(state.remaining_seconds) / 60))
  return left === 0 ? 'Idle limit reached · Cleanup on next sweep' : `${base} · ${left} min to eligibility`
}

// -----------------------------------------------------------------------------
// Masking personal details before a message leaves the composer.
//
// Same detectors as the backend (pii.py; the table below is generated from it) so a value the
// backend would mask is already a placeholder before the text reaches Hermes. The originals stay
// in this window's memory only: never sent, never written to storage, dropped with the chat.
// -----------------------------------------------------------------------------

export const PII_KINDS = ['SECRET', 'PASSWORD', 'EMAIL', 'IBAN', 'CARD', 'NIT', 'ID', 'SSN', 'IP', 'PHONE', 'ADDRESS']
export const KIND_LABELS = {
  SECRET: 'API key or token',
  PASSWORD: 'password',
  EMAIL: 'email',
  IBAN: 'IBAN',
  CARD: 'card number',
  NIT: 'NIT',
  ID: 'ID number',
  SSN: 'SSN',
  IP: 'IP address',
  PHONE: 'phone',
  ADDRESS: 'address'
}
const PLACEHOLDER_SOURCE = `\\[(${PII_KINDS.join('|')})_(\\d+)\\]`
const PLACEHOLDER_FULL = new RegExp(`^${PLACEHOLDER_SOURCE}$`)

const onlyDigits = value => String(value).replace(/\D/g, '')

export function luhnOk(number) {
  const digits = onlyDigits(number)
  if (digits.length < 13 || digits.length > 19 || new Set(digits).size === 1) return false
  let total = 0
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i])
    if (i % 2 === 1) {
      d *= 2
      if (d > 9) d -= 9
    }
    total += d
  }
  return total % 10 === 0
}

const IBAN_LENGTHS = {
  AD: 24, AE: 23, AL: 28, AT: 20, AZ: 28, BA: 20, BE: 16, BG: 22, BH: 22, BR: 29, CH: 21, CR: 22, CY: 28,
  CZ: 24, DE: 22, DK: 18, DO: 28, EE: 20, ES: 24, FI: 18, FO: 18, FR: 27, GB: 22, GE: 22, GI: 23, GL: 18,
  GR: 27, GT: 28, HR: 21, HU: 28, IE: 22, IL: 23, IS: 26, IT: 27, JO: 30, KW: 30, KZ: 20, LB: 28, LI: 21,
  LT: 20, LU: 20, LV: 21, MC: 27, MD: 24, ME: 22, MK: 19, MR: 27, MT: 31, MU: 30, NL: 18, NO: 15, PK: 24,
  PL: 28, PS: 29, PT: 25, QA: 29, RO: 24, RS: 22, SA: 24, SE: 24, SI: 19, SK: 24, SM: 27, TN: 24, TR: 26,
  UA: 29, VG: 24, XK: 20
}

export function ibanOk(value) {
  const iban = String(value).replace(/\s/g, '').toUpperCase()
  const expected = IBAN_LENGTHS[iban.slice(0, 2)]
  if (!expected || iban.length !== expected || !/^\d\d$/.test(iban.slice(2, 4))) return false
  let rest = 0
  for (const ch of iban.slice(4) + iban.slice(0, 4)) {
    const n = parseInt(ch, 36)
    if (Number.isNaN(n)) return false
    for (const d of String(n)) rest = (rest * 10 + Number(d)) % 97
  }
  return rest === 1
}

const NIT_WEIGHTS = [3, 7, 13, 17, 19, 23, 29, 37, 41, 43, 47, 53, 59, 67, 71]

export function nitOk(value) {
  const digits = onlyDigits(value)
  if (digits.length < 2) return false
  const body = digits.slice(0, -1).split('').reverse()
  const check = Number(digits.at(-1))
  let total = 0
  for (let i = 0; i < Math.min(body.length, NIT_WEIGHTS.length); i++) total += Number(body[i]) * NIT_WEIGHTS[i]
  const rest = total % 11
  return (rest === 0 || rest === 1 ? rest : 11 - rest) === check
}

function ipv4Parts(value) {
  const parts = String(value).split('.')
  if (parts.length !== 4) return null
  const nums = []
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part) || (part.length > 1 && part[0] === '0')) return null
    const n = Number(part)
    if (n > 255) return null
    nums.push(n)
  }
  return nums
}

export function ipv4Ok(value) {
  const nums = ipv4Parts(value)
  if (!nums) return false
  return nums[0] !== 127 && !nums.every(n => n === 0)
}

export function ipv6Ok(value) {
  let v = String(value)
  if ((v.match(/:/g) || []).length < 2) return false
  v = v.split('%')[0]
  let tailGroups = []
  const lastColon = v.lastIndexOf(':')
  const tail = v.slice(lastColon + 1)
  if (tail.includes('.')) {
    const nums = ipv4Parts(tail)
    if (!nums) return false
    tailGroups = [((nums[0] << 8) | nums[1]).toString(16), ((nums[2] << 8) | nums[3]).toString(16)]
    v = v.slice(0, lastColon + 1)
    if (!v.endsWith('::')) v = v.slice(0, -1)
  }
  const halves = v.split('::')
  if (halves.length > 2) return false
  const parse = s => (s === '' ? [] : s.split(':'))
  const head = parse(halves[0])
  const rest = halves.length === 2 ? parse(halves[1]) : []
  const groups = [...head, ...rest]
  if (groups.some(g => !/^[0-9A-Fa-f]{1,4}$/.test(g))) return false
  const count = groups.length + tailGroups.length
  if (halves.length === 2 ? count > 7 : count !== 8) return false
  const full =
    halves.length === 2
      ? [...head, ...Array(8 - count).fill('0'), ...rest, ...tailGroups]
      : [...groups, ...tailGroups]
  const values = full.map(g => parseInt(g, 16))
  const zeroPrefix = values.slice(0, 7).every(n => n === 0)
  return !(zeroPrefix && (values[7] === 0 || values[7] === 1))
}

export function phoneOk(value) {
  const digits = onlyDigits(value)
  return digits.length >= 7 && digits.length <= 15 && new Set(digits).size > 2
}

// <generated:pii-detectors> (tools/gen_js_detectors.py; do not edit by hand)
const DETECTOR_SPECS = [
  ["SECRET", "-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\\s\\S]+?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----", "gud", 0, null],
  ["SECRET", "(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))eyJ[A-Za-z0-9_\\-]{8,}\\.eyJ[A-Za-z0-9_\\-]{8,}\\.[A-Za-z0-9_\\-]*", "gud", 0, null],
  ["SECRET", "(?<![A-Za-z0-9])sk-(?:proj-|ant-(?:api\\d{2}-)?|live-|test-|or-v1-)?[A-Za-z0-9_\\-]{20,}", "gud", 0, null],
  ["SECRET", "(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))", "gud", 0, null],
  ["SECRET", "(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))github_pat_[A-Za-z0-9_]{22,}(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))", "gud", 0, null],
  ["SECRET", "(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{12,}(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))", "gud", 0, null],
  ["SECRET", "(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))xox[abposr]-[A-Za-z0-9\\-]{10,}(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))", "gud", 0, null],
  ["SECRET", "(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))AIza[0-9A-Za-z_\\-]{30,}", "gud", 0, null],
  ["SECRET", "(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))glpat-[A-Za-z0-9_\\-]{20,}(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))", "gud", 0, null],
  ["SECRET", "(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))", "gud", 0, null],
  ["SECRET", "(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))hf_[A-Za-z0-9]{20,}(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))", "gud", 0, null],
  ["SECRET", "(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))npm_[A-Za-z0-9]{20,}(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))", "gud", 0, null],
  ["SECRET", "(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))ya29\\.[A-Za-z0-9_\\-]{20,}", "gud", 0, null],
  ["SECRET", "(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))SG\\.[A-Za-z0-9_\\-]{16,}\\.[A-Za-z0-9_\\-]{16,}", "gud", 0, null],
  ["SECRET", "(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))bearer\\s+(?!\\[(?:SECRET|PASSWORD|EMAIL|IBAN|CARD|NIT|ID|SSN|IP|PHONE|ADDRESS)_\\d+\\])([A-Za-z0-9_\\-.~+/=]{16,})", "gudi", 1, null],
  ["SECRET", "(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))[a-z][a-z0-9+.\\-]*://[^\\s:/@\\[\\]]+:((?!\\[(?:SECRET|PASSWORD|EMAIL|IBAN|CARD|NIT|ID|SSN|IP|PHONE|ADDRESS)_\\d+\\])[^\\s@/\\[\\]]+)@", "gudi", 1, null],
  ["SECRET", "(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))(?:api[_\\-\\s]?key|apikey|access[_\\-\\s]?token|auth[_\\-\\s]?token|refresh[_\\-\\s]?token|secret(?:[_\\-\\s]?key)?|client[_\\-\\s]?secret|private[_\\-\\s]?key|token)(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))\\s*[:=]\\s*[\"']?(?!\\[(?:SECRET|PASSWORD|EMAIL|IBAN|CARD|NIT|ID|SSN|IP|PHONE|ADDRESS)_\\d+\\])([^\\s\"',;]{6,})", "gudi", 1, null],
  ["PASSWORD", "(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))(?:password|passwd|pwd|passcode|pass|contrase[\u00f1n]a|clave|pin)(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))\\s*[:=]\\s*[\"']?(?!\\[(?:SECRET|PASSWORD|EMAIL|IBAN|CARD|NIT|ID|SSN|IP|PHONE|ADDRESS)_\\d+\\])([^\\s\"',;]{3,})", "gudi", 1, null],
  ["PASSWORD", "(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))(?:password|passcode|contrase[\u00f1n]a|clave|pin)\\s+(?:is|es|era|was)\\s*[:=]?\\s*[\"']?(?!\\[(?:SECRET|PASSWORD|EMAIL|IBAN|CARD|NIT|ID|SSN|IP|PHONE|ADDRESS)_\\d+\\])([^\\s\"',;]{3,})", "gudi", 1, null],
  ["EMAIL", "(?<![\\p{L}\\p{N}_.+\\-])[A-Za-z0-9][A-Za-z0-9._%+\\-]{0,63}@(?:[A-Za-z0-9](?:[A-Za-z0-9\\-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z]{2,24}(?![\\p{L}\\p{N}_\\-])", "gud", 0, null],
  ["EMAIL", "(?<![\\p{L}\\p{N}_.+\\-])[a-z0-9][a-z0-9._%+\\-]*\\s*(?:\\[\\s*(?:at|arroba)\\s*\\]|\\(\\s*(?:at|arroba)\\s*\\)|\\{\\s*(?:at|arroba)\\s*\\}|<\\s*(?:at|arroba)\\s*>)\\s*[a-z0-9\\-]+(?:\\s*(?:\\[\\s*(?:dot|punto)\\s*\\]|\\(\\s*(?:dot|punto)\\s*\\)|\\{\\s*(?:dot|punto)\\s*\\}|<\\s*(?:dot|punto)\\s*>|\\s+(?:dot|punto)\\s+|\\.)\\s*[a-z0-9\\-]+)+", "gudi", 0, null],
  ["EMAIL", "(?<![\\p{L}\\p{N}_.+\\-])[a-z0-9][a-z0-9._%+\\-]*\\s+(?:at|arroba)\\s+(?:gmail|googlemail|hotmail|outlook|live|msn|yahoo|ymail|icloud|me|mac|aol|proton|protonmail|pm|gmx|yandex|zoho|mail|fastmail|tutanota|une|etb|unal|udea|javeriana|uniandes)(?:\\s*(?:\\s(?:dot|punto)\\s|\\.)\\s*[a-z]{2,6}){1,2}(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))", "gudi", 0, null],
  ["EMAIL", "(?<![\\p{L}\\p{N}_.+\\-])[a-z0-9]*[._+\\d][a-z0-9._%+\\-]*\\s+(?:at|arroba)\\s+[a-z0-9\\-]+(?:\\s*(?:\\s(?:dot|punto)\\s|\\.)\\s*[a-z0-9\\-]+)*\\s*(?:\\s(?:dot|punto)\\s|\\.)\\s*(?:com|org|net|edu|gov|mil|int|info|biz|io|co|ai|app|dev|me|us|uk|ca|au|de|fr|es|it|nl|be|ch|at|se|no|dk|fi|pl|pt|br|mx|ar|cl|pe|ec|ve|uy|py|bo|cr|pa|gt|do|cu|jp|cn|in|ru|xyz|online|site|tech|email|mail)(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))", "gudi", 0, null],
  ["IBAN", "(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))[A-Z]{2}\\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))", "gud", 0, ibanOk],
  ["CARD", "(?<![\\d\\-])\\d{4}([ \\-])\\d{4}\\1\\d{4}\\1\\d{4}(?:\\1\\d{1,3})?(?![\\d\\-]|[ \\-]\\d)", "gud", 0, null],
  ["CARD", "(?<![\\d\\-])\\d(?:[ \\-]?\\d){12,18}(?![\\d\\-]|[ \\-]\\d)", "gud", 0, luhnOk],
  ["NIT", "(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))NIT\\.?\\s*(?:(?:es|is)\\s+)?(?:n[\u00b0\u00bao]\\.?|no\\.?|:|#)?\\s*(\\d{3}\\.?\\d{3}\\.?\\d{3}\\d?(?:\\s?-\\s?\\d)?)(?!\\d)", "gudi", 1, null],
  ["NIT", "(?<![\\d.])\\d{3}\\.\\d{3}\\.\\d{3}-\\d(?!\\d)", "gud", 0, nitOk],
  ["ID", "(?<![\\p{L}\\p{N}_])(?:c\\.\\s?c\\.?|cc|c[\u00e9e]dula(?:\\s+de\\s+(?:ciudadan[\u00edi]a|extranjer[\u00edi]a))?|documento(?:\\s+de\\s+identidad)?|n[\u00fau]mero\\s+de\\s+identificaci[\u00f3o]n|identificaci[\u00f3o]n|tarjeta\\s+de\\s+identidad|t\\.\\s?i\\.?|dni|pasaporte|passport(?:\\s+(?:no|number))?)\\.?\\s*(?:(?:es|is|was|era)\\s+)?(?:n[\u00b0\u00bao]\\.?|no\\.?|num\\.?|n[\u00fau]mero|#|:)?\\s*(\\d{1,3}(?:[.\\s]\\d{3}){1,3}|\\d{5,12}|[A-Z]{1,2}\\d{6,9})(?![\\d.]\\d)", "gudi", 1, null],
  ["SSN", "(?<![\\d\\-])(?!000|666|9\\d\\d)\\d{3}([\\- ])(?!00)\\d{2}\\1(?!0000)\\d{4}(?![\\d\\-])", "gud", 0, null],
  ["SSN", "(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))(?:ssn|social\\s+security(?:\\s+(?:no|number|#))?)\\s*[:#]?\\s*(\\d{9})(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))", "gudi", 1, null],
  ["IP", "(?<![\\d.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![\\d]|\\.\\d)", "gud", 0, ipv4Ok],
  ["IP", "(?<![\\p{L}\\p{N}_:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9A-Fa-f]{1,4}|(?:\\d{1,3}\\.){3}\\d{1,3})?(?:%[\\p{L}\\p{N}_]+)?(?![\\p{L}\\p{N}_:])", "gud", 0, ipv6Ok],
  ["PHONE", "(?<![\\p{L}\\p{N}_+])\\+\\s?\\d{1,3}(?:[ .\\-]?\\(?\\d{1,4}\\)?){2,5}(?![\\p{L}\\p{N}_])", "gud", 0, phoneOk],
  ["PHONE", "(?<![\\p{L}\\p{N}_+])00\\d{1,3}(?:[ .\\-]?\\(?\\d{1,4}\\)?){2,5}(?![\\p{L}\\p{N}_])", "gud", 0, phoneOk],
  ["PHONE", "(?<![\\p{L}\\p{N}_.\\-])3[0-5]\\d[ .\\-]?\\d{3}[ .\\-]?\\d{4}(?![\\p{L}\\p{N}_]|[.\\-]\\d)", "gud", 0, null],
  ["PHONE", "(?<![\\p{L}\\p{N}_.\\-])\\(?60[1-8]\\)?[ .\\-]?\\d{3}[ .\\-]?\\d{4}(?![\\p{L}\\p{N}_]|[.\\-]\\d)", "gud", 0, null],
  ["PHONE", "(?<![\\p{L}\\p{N}_.\\-])(?:\\(\\d{3}\\)\\s?|\\d{3}[ .\\-])\\d{3}[ .\\-]\\d{4}(?![\\p{L}\\p{N}_]|[.\\-]\\d)", "gud", 0, phoneOk],
  ["ADDRESS", "(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))(?:calle|cl|cll|carrera|cra|kra|kr|cr|avenida(?:\\s+calle|\\s+carrera)?|av|ak|ac|diagonal|dg|transversal|tv|tr|circular|autopista)\\.?\\s*\\d{1,3}\\s?[a-z]?(?:\\s?bis)?(?:\\s?[a-z])?(?:\\s(?:sur|norte|este|oeste))?\\s*(?:#|no\\.?|n[\u00b0\u00ba]|n[\u00fau]mero)\\s*\\d{1,3}\\s?[a-z]?\\s*-\\s*\\d{1,3}(?:\\s?(?:sur|norte|este|oeste)(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_])))?", "gudi", 0, null],
  ["ADDRESS", "(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))\\d{1,6}\\s+(?:[NSEW]\\.?\\s+)?(?:[A-Z][a-z]+\\s){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Parkway|Pkwy|Highway|Hwy)(?:(?<![\\p{L}\\p{N}_])(?=[\\p{L}\\p{N}_])|(?<=[\\p{L}\\p{N}_])(?![\\p{L}\\p{N}_]))\\.?(?:,?\\s*(?:Apt|Suite|Unit|#)\\.?\\s*[\\p{L}\\p{N}_]+)?", "gud", 0, null],
]
// </generated:pii-detectors>

const DETECTORS = DETECTOR_SPECS.map(([kind, source, flags, group, validator]) => ({
  kind,
  pattern: new RegExp(source, flags),
  group,
  validator
}))

/** Every non-overlapping finding, earlier detectors first (same rules as pii.find_pii). */
export function findPii(text) {
  if (!text) return []
  const taken = []
  const found = []
  for (const det of DETECTORS) {
    det.pattern.lastIndex = 0
    for (const match of String(text).matchAll(det.pattern)) {
      const span = match.indices?.[det.group]
      if (!span) continue
      const [start, end] = span
      if (end <= start) continue
      const value = match[det.group]
      if (det.validator && !det.validator(value)) continue
      if (PLACEHOLDER_FULL.test(value)) continue
      if (taken.some(([s, e]) => start < e && s < end)) continue
      taken.push([start, end])
      found.push({ kind: det.kind, start, end, value })
    }
  }
  return found.sort((a, b) => a.start - b.start)
}

function normalizeValue(kind, value) {
  if (kind === 'EMAIL') return value.replace(/\s+/g, '').toLowerCase()
  if (['CARD', 'PHONE', 'NIT', 'ID', 'SSN'].includes(kind)) return onlyDigits(value) || value
  if (kind === 'IBAN') return value.replace(/\s/g, '').toUpperCase()
  return value
}

/** RAM-only map between originals and stable placeholders for one chat. */
export class Vault {
  constructor() {
    this.forward = new Map()
    this.originals = new Map()
    this.counters = {}
  }

  reserve(text) {
    for (const m of String(text || '').matchAll(new RegExp(PLACEHOLDER_SOURCE, 'g'))) {
      const n = Number(m[2])
      if (n > (this.counters[m[1]] || 0)) this.counters[m[1]] = n
    }
  }

  /** Start numbering after what the backend already used, so placeholders never collide. */
  seed(counts) {
    for (const [kind, n] of Object.entries(counts || {})) {
      if (PII_KINDS.includes(kind) && Number(n) > (this.counters[kind] || 0)) this.counters[kind] = Number(n)
    }
  }

  placeholder(kind, value) {
    const key = `${kind}\u0000${normalizeValue(kind, value)}`
    const existing = this.forward.get(key)
    if (existing) return existing
    this.counters[kind] = (this.counters[kind] || 0) + 1
    const ph = `[${kind}_${this.counters[kind]}]`
    this.forward.set(key, ph)
    this.originals.set(ph, value)
    return ph
  }

  get(placeholder) {
    return this.originals.get(placeholder)
  }

  get size() {
    return this.originals.size
  }

  clear() {
    this.forward.clear()
    this.originals.clear()
    this.counters = {}
  }
}

/**
 * Mask ``text``. Returns the masked text, the kinds masked, and segments describing which parts
 * changed (used by the send animation and the local legend; never sent anywhere).
 */
export function maskText(text, vault) {
  if (typeof text !== 'string' || !text) return { text, kinds: [], segments: text ? [{ text }] : [] }
  vault.reserve(text)
  const kinds = []
  const known = [...vault.originals.entries()].sort((a, b) => b[1].length - a[1].length)
  // Values masked before are swapped first (same as the backend), then fresh findings.
  const pieces = [{ text, original: null }]
  for (const [ph, original] of known) {
    if (original.length < 4) continue
    for (let i = 0; i < pieces.length; i++) {
      const piece = pieces[i]
      if (piece.placeholder || !piece.text.includes(original)) continue
      const parts = piece.text.split(original)
      const replaced = []
      parts.forEach((part, idx) => {
        if (idx > 0) {
          replaced.push({ text: ph, placeholder: ph, original, kind: PLACEHOLDER_FULL.exec(ph)?.[1] || 'SECRET' })
          kinds.push(PLACEHOLDER_FULL.exec(ph)?.[1] || 'SECRET')
        }
        if (part) replaced.push({ text: part })
      })
      pieces.splice(i, 1, ...replaced)
      i += replaced.length - 1
    }
  }
  const segments = []
  for (const piece of pieces) {
    if (piece.placeholder) {
      segments.push(piece)
      continue
    }
    let cursor = 0
    for (const f of findPii(piece.text)) {
      if (f.start > cursor) segments.push({ text: piece.text.slice(cursor, f.start) })
      const ph = vault.placeholder(f.kind, f.value)
      segments.push({ text: ph, placeholder: ph, original: f.value, kind: f.kind })
      kinds.push(f.kind)
      cursor = f.end
    }
    if (cursor < piece.text.length) segments.push({ text: piece.text.slice(cursor) })
  }
  return { text: segments.map(s => s.text).join(''), kinds, segments }
}

/** "3 details masked before sending" style summary; content-free. */
export function describeMasked(kinds) {
  const n = kinds.length
  if (!n) return 'Nothing to mask in this message'
  return `${n} ${n === 1 ? 'detail' : 'details'} masked before sending`
}

export function kindSummary(kinds) {
  const counts = {}
  for (const k of kinds) counts[k] = (counts[k] || 0) + 1
  return Object.entries(counts)
    .map(([k, n]) => `${n} ${KIND_LABELS[k] || k.toLowerCase()}${n > 1 && !KIND_LABELS[k]?.endsWith('s') ? 's' : ''}`)
    .join(', ')
}

/** Show a value without revealing it in full: "j•••@g•••.com", "•••• 1111". */
export function hint(kind, value) {
  const v = String(value)
  if (kind === 'CARD' || kind === 'IBAN') return `•••• ${onlyDigits(v).slice(-4) || v.slice(-4)}`
  if (kind === 'EMAIL' && v.includes('@')) return `${v[0]}•••@${v.split('@')[1].slice(0, 1)}•••`
  if (kind === 'PASSWORD' || kind === 'SECRET') return '••••••'
  return `${v.slice(0, 1)}•••${v.slice(-2)}`
}

// Hermes' decode charset (DecodeText): even-weight mono glyphs, so widths never jump.
const SCRAMBLE_GLYPHS = '/\\|-_=+<>~:*'

/**
 * One frame of the send animation, drawn on this computer only: each value the user typed breaks
 * into scramble glyphs, then its placeholder decodes out of them the way Hermes' DecodeText
 * resolves text, as t goes 0 → 1. At t = 1 the line is exactly what was sent.
 */
export function scrambleFrame(segments, t, rand = Math.random) {
  const progress = Math.max(0, Math.min(1, t))
  const glyph = () => SCRAMBLE_GLYPHS[Math.floor(rand() * SCRAMBLE_GLYPHS.length)]
  return segments.map(seg => {
    if (!seg.placeholder) return seg.text
    if (progress >= 1) return seg.placeholder
    const original = String(seg.original ?? '')
    const target = seg.placeholder
    if (progress < 0.3) {
      const broken = Math.floor(original.length * (progress / 0.3))
      return Array.from(original, (ch, i) => (i < broken ? glyph() : ch)).join('')
    }
    const p = (progress - 0.3) / 0.7
    const len = Math.max(1, Math.round(original.length + (target.length - original.length) * Math.min(1, p * 2)))
    const resolved = Math.floor(target.length * p)
    let out = ''
    for (let i = 0; i < len; i++) out += i < resolved ? target[i] || '' : glyph()
    return out
  })
}

export function prefersReducedMotion() {
  try {
    return Boolean(typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches)
  } catch {
    return false
  }
}

// Per-chat vaults and the last masked send, kept in this window's memory only.
const vaults = new Map()
const sendListeners = new Set()
// The first draft has no session ID. Keep only its counter high-water mark
// so later sends cannot reuse its placeholders for different values.
const firstDraftCounts = {}
let lastSend = null

export function vaultFor(sessionId, counts) {
  const key = sessionId || '__next__'
  let vault = vaults.get(key)
  if (!vault) {
    vault = new Vault()
    vaults.set(key, vault)
  }
  vault.seed(counts)
  return vault
}

export function forgetChat(sessionId) {
  const key = sessionId || '__next__'
  vaults.get(key)?.clear()
  vaults.delete(key)
  if (lastSend && (lastSend.sessionId || '__next__') === key) setLastSend(null)
}

export function getLastSend() {
  return lastSend
}

function setLastSend(record) {
  lastSend = record
  for (const listener of sendListeners) {
    try {
      listener(record)
    } catch {
      // Listener errors never affect sending
    }
  }
}

export const MASK_BLOCKED = {
  error: "Incognito didn't send this message: it couldn't mask your personal details. Nothing left this computer.",
  attachments:
    "Incognito didn't send this message: masking is on and it can't check attachments for personal details. Remove the attachment or turn off Mask personal details.",
  offline:
    "Incognito didn't send this message: it couldn't confirm whether masking is on. Nothing left this computer. Try again in a moment."
}

/** Whether a chat (or the next new chat) masks before sending, from a status response. */
export function maskingFor(status, sessionId) {
  if (!status || status.ok === false || status.status === 'unavailable') return null
  if (sessionId) {
    const state = status.session_state || status.current_session
    if (state?.active) return { on: Boolean(state.redact_pii), counts: state.masked_counts || {} }
    if (status.saved?.redact_pii) return { on: true, counts: status.saved.masked_counts || {} }
    return { on: false, counts: {} }
  }
  const mode = status.armed?.mode ?? status.settings?.default_mode
  const enabled = status.armed
    ? status.armed.redact_pii
    : (mode === 'standard' || mode === 'strict') && status.settings?.redact_outbound_pii
  return { on: Boolean(enabled), counts: {} }
}

/**
 * Composer middleware: runs on every send, before the text reaches Hermes. It reads the chat's
 * status at send time (so masking turned on a moment ago applies to this very message) and
 * fails closed: on any error, or when masking is on and the draft has attachments, it cancels
 * the send (returns null) and says why. Desktop treats a throwing handler as pass-through, so
 * nothing here may throw.
 */
export function makeMaskingMiddleware(ctx, { getSessionId = () => host?.state?.focusedSessionId?.get?.() || '', fetch = fetchStatus } = {}) {
  return async function maskBeforeSend(draft) {
    try {
      const sessionId = getSessionId()
      let masking = null
      try {
        const status = await fetch(ctx, sessionId)
        if (sessionId && status?.burned) {
          forgetChat(sessionId)
          return null
        }
        masking = maskingFor(status, sessionId)
      } catch {
        masking = null
      }
      if (!masking) {
        notify('warning', MASK_BLOCKED.offline)
        return null
      }
      if (!masking.on) return draft
      if (Array.isArray(draft?.attachments) && draft.attachments.length) {
        notify('warning', MASK_BLOCKED.attachments)
        return null
      }
      const vault = sessionId ? vaultFor(sessionId, masking.counts) : new Vault()
      vault.seed(firstDraftCounts)
      const result = maskText(String(draft?.text ?? ''), vault)
      if (findPii(result.text).length) throw new Error('residual')
      if (!sessionId) {
        Object.assign(firstDraftCounts, vault.counters)
        // The host has not assigned this draft to a chat yet.
        setLastSend(null)
        return { ...draft, text: result.text }
      }
      setLastSend({
        sessionId,
        at: Date.now(),
        kinds: result.kinds,
        segments: result.segments,
        masked: result.text
      })
      return { ...draft, text: result.text }
    } catch {
      notify('warning', MASK_BLOCKED.error)
      return null
    }
  }
}

export function _resetMaskingForTests() {
  for (const vault of vaults.values()) vault.clear()
  vaults.clear()
  for (const kind of Object.keys(firstDraftCounts)) delete firstDraftCounts[kind]
  sendListeners.clear()
  lastSend = null
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
  if (plan.action === 'disable') {
    // Turning Incognito off keeps the chat, so it is the same as saving it: ask first, and
    // offer Undo afterwards. Every entry point (banner, status bar, keybind, picker) lands here.
    return requestSave(ctx, plan.session_id)
  }
  let result = null
  if (plan.action === 'enable') {
    const body = { session_id: plan.session_id, mode: plan.mode }
    if (plan.redact_pii !== undefined) body.redact_pii = plan.redact_pii
    result = await callBackend(ctx, 'enable', body)
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
  forgetChat(sessionId)
  notifyStateListeners()
  notify(
    'info',
    result.pending_burn
      ? 'Deleting. Hermes will finish cleanup in a moment; the chat stays protected until then.'
      : 'Chat cleanup completed.'
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
      if (sessionId && res.burned) forgetChat(sessionId)
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

  if (!state && focusedSessionId && status?.saved) {
    return jsx(SavedBanner, { ctx, sessionId: focusedSessionId, saved: status.saved })
  }

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
              jsx(Tip, {
                label: 'Keep this chat in your history. You can undo for a few minutes.',
                children: jsx(Button, {
                  size: 'sm',
                  variant: 'ghost',
                  disabled: Boolean(state?.pending_burn),
                  onClick: () => requestSave(ctx, focusedSessionId, status),
                  children: COPY.saveAction
                })
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
// Save an Incognito chat: confirm, then Undo for a few minutes.
// -----------------------------------------------------------------------------

/** What "Save this chat…" does for the current status. */
export function planSave(status, sessionId) {
  if (!sessionId) return { action: 'noop', reason: 'no_chat' }
  const state = currentState(status)
  if (state?.pending_burn) return { action: 'noop', reason: 'pending' }
  if (!state) return { action: 'noop', reason: status?.saved ? 'already_saved' : 'not_incognito' }
  return { action: 'save', session_id: sessionId, masked: Boolean(state.redact_pii) }
}

/** Confirmation copy; says what happens to masked details. */
export function saveDialogCopy({ masked, undoMinutes = 10 }) {
  const parts = [
    "This chat moves to your chat history and won't be deleted automatically.",
    masked
      ? 'Personal details stay masked in the saved messages. The real values were never sent and are not added back.'
      : null,
    `You can undo this for ${undoMinutes} minutes, or until you close the chat.`
  ]
  return { title: COPY.saveTitle, description: parts.filter(Boolean).join(' ') }
}

export function undoMinutesLeft(saved) {
  if (!saved) return 0
  return Math.max(0, Math.ceil(Number(saved.undo_remaining_seconds || 0) / 60))
}

const saveHosts = new Set()

export async function performUndo(ctx, sessionId) {
  const res = await callBackend(ctx, 'undo', { session_id: sessionId })
  if (!res?.ok) {
    notify('warning', res?.error || "Couldn't return this chat to Incognito.")
    return null
  }
  notifyStateListeners()
  notify('info', `Back in Incognito · ${levelName(res.mode)}. Incognito protections are active.`)
  return res
}

export async function performSave(ctx, sessionId) {
  const res = await callBackend(ctx, 'save', { session_id: sessionId })
  if (!res?.ok) {
    notify('warning', res?.error || "Couldn't save this chat.")
    return null
  }
  notifyStateListeners()
  try {
    host?.notify?.({
      kind: 'success',
      message: 'Chat saved to your history.',
      detail: `Undo is available for ${Math.round((res.undo_seconds || 600) / 60)} minutes.`,
      action: { label: 'Undo', onClick: () => performUndo(ctx, sessionId) }
    })
  } catch {
    // Toasts are best-effort; the banner keeps "Return to Incognito" visible.
  }
  return res
}

/** Ask first. Cancel changes nothing. Falls back to the native confirm on older builds. */
export async function requestSave(ctx, sessionId, status) {
  const plan = planSave(status ?? (await fetchStatus(ctx, sessionId)), sessionId)
  if (plan.action !== 'save') {
    const why = {
      no_chat: 'Open a chat to save it.',
      pending: 'This chat is being deleted.',
      already_saved: 'This chat is already saved.',
      not_incognito: 'This chat is already in your history.'
    }
    notify('info', why[plan.reason] || '')
    return null
  }
  if (saveHosts.size && sdk.ConfirmDialog) {
    for (const open of saveHosts) open(plan)
    return plan
  }
  const copy = saveDialogCopy(plan)
  const ok = typeof window !== 'undefined' && typeof window.confirm === 'function'
    ? window.confirm(`${copy.title}\n\n${copy.description}`)
    : false
  if (!ok) return null
  return performSave(ctx, sessionId)
}

function SaveDialogHost({ ctx }) {
  const [plan, setPlan] = useState(null)

  useEffect(() => {
    const open = next => setPlan(next)
    saveHosts.add(open)
    return () => {
      saveHosts.delete(open)
    }
  }, [])

  const ConfirmDialog = sdk.ConfirmDialog
  if (!ConfirmDialog) return null
  const copy = saveDialogCopy(plan || {})
  return jsx(ConfirmDialog, {
    open: Boolean(plan),
    onClose: () => setPlan(null),
    onConfirm: () => performSave(ctx, plan.session_id),
    title: copy.title,
    description: copy.description,
    confirmLabel: COPY.saveConfirm,
    busyLabel: COPY.saveBusy,
    cancelLabel: COPY.saveCancel
  })
}

function SavedBanner({ ctx, sessionId, saved }) {
  const left = undoMinutesLeft(saved)
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
      boxShadow: 'inset 2px 0 0 0 var(--ui-green, var(--ui-accent)), inset 0 0 0 1px var(--ui-stroke-tertiary)'
    },
    children: [
      jsxs('div', {
        style: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', minWidth: 0 },
        children: [
          jsx(LevelBadge, { mode: 'off' }),
          jsx('span', { style: { fontSize: '12px', color: text.secondary }, children: 'Saved to your history' }),
          jsx('span', {
            style: { fontSize: '12px', color: text.tertiary },
            children: `· You can return it to Incognito for ${left} more min${saved?.redact_pii ? ' · Personal details still masked' : ''}`
          })
        ]
      }),
      jsx(Button, {
        size: 'sm',
        variant: 'outline',
        onClick: () => performUndo(ctx, sessionId),
        children: COPY.undoSave
      })
    ]
  })
}

// -----------------------------------------------------------------------------
// Masking feedback: live preview while typing, and what was sent after each send.
// -----------------------------------------------------------------------------

const mono = { fontFamily: 'var(--font-mono)', fontSize: '12px', lineHeight: '18px', fontVariantLigatures: 'none' }
const chip = {
  ...mono,
  fontSize: '11px',
  padding: '1px 6px',
  borderRadius: '3px',
  color: 'var(--ui-accent)',
  boxShadow: 'inset 0 0 0 1px var(--ui-stroke-secondary)',
  background: 'var(--ui-bg-tertiary, transparent)'
}

function useLastSend(sessionId) {
  const [record, setRecord] = useState(() => getLastSend())
  useEffect(() => {
    const listener = next => setRecord(next)
    sendListeners.add(listener)
    return () => {
      sendListeners.delete(listener)
    }
  }, [])
  if (!record || (record.sessionId || '') !== (sessionId || '')) return null
  return record
}

/** Animates the masked message once; reduced motion shows the final frame right away. */
function ScrambleLine({ segments, startedAt }) {
  const [frame, setFrame] = useState(() => (prefersReducedMotion() ? 1 : 0))
  useEffect(() => {
    if (prefersReducedMotion() || typeof window === 'undefined') {
      setFrame(1)
      return undefined
    }
    const duration = 900
    const id = window.setInterval(() => {
      const t = (Date.now() - startedAt) / duration
      setFrame(Math.min(1, t))
      if (t >= 1) window.clearInterval(id)
    }, 45)
    return () => window.clearInterval(id)
  }, [startedAt])
  const pieces = scrambleFrame(segments, frame)
  return jsx('div', {
    'aria-hidden': true,
    style: { ...mono, color: text.secondary, whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: '72px', overflow: 'hidden' },
    children: pieces.map((piece, i) =>
      segments[i].placeholder
        ? jsx('span', { style: { color: 'var(--ui-accent)', fontWeight: 600 }, children: piece }, i)
        : jsx('span', { children: piece }, i)
    )
  })
}

function SentToModelCard({ record, onDismiss }) {
  const [open, setOpen] = useState(false)
  const [reveal, setReveal] = useState(false)
  const masked = record.segments.filter(s => s.placeholder)
  const unique = []
  for (const seg of masked) if (!unique.some(u => u.placeholder === seg.placeholder)) unique.push(seg)
  const summary = describeMasked(record.kinds)
  return jsxs('div', {
    role: 'status',
    'aria-live': 'polite',
    'data-incognito': 'sent-to-model',
    style: {
      ...card,
      padding: '8px 12px',
      marginBottom: '6px',
      boxShadow: 'inset 2px 0 0 0 var(--ui-accent), inset 0 0 0 1px var(--ui-stroke-tertiary)'
    },
    children: [
      jsxs('div', {
        style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px', flexWrap: 'wrap' },
        children: [
          jsxs('div', {
            style: { display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 },
            children: [
              jsx('span', { style: chip, children: `${record.kinds.length} masked` }),
              jsx('span', { style: { fontSize: '12px', color: text.primary, fontWeight: 500 }, children: summary }),
              jsx('span', { style: { fontSize: '12px', color: text.tertiary }, children: kindSummary(record.kinds) })
            ]
          }),
          jsxs('div', {
            style: { display: 'flex', gap: '4px' },
            children: [
              jsx(Button, {
                size: 'sm',
                variant: 'ghost',
                'aria-expanded': open,
                onClick: () => setOpen(!open),
                children: open ? 'Hide what was sent' : 'Sent to model'
              }),
              jsx(Button, { size: 'sm', variant: 'text', onClick: onDismiss, 'aria-label': 'Dismiss', children: 'Dismiss' })
            ]
          })
        ]
      }),
      jsx('div', { style: { marginTop: '6px' }, children: jsx(ScrambleLine, { segments: record.segments, startedAt: record.at }) }),
      open
        ? jsxs('div', {
            style: { marginTop: '8px', paddingTop: '8px', borderTop: '1px solid var(--ui-stroke-tertiary)' },
            children: [
              jsx('div', { style: { ...caption, marginBottom: '4px' }, children: 'Text passed to Hermes after masking:' }),
              jsx('pre', {
                'data-incognito': 'sent-text',
                style: { ...mono, margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word', color: text.primary },
                children: record.masked
              }),
              unique.length
                ? jsxs('div', {
                    style: { marginTop: '8px' },
                    children: [
                      jsxs('div', {
                        style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' },
                        children: [
                          jsx('span', { style: caption, children: 'Only on this computer, never sent or saved:' }),
                          jsx(Button, {
                            size: 'sm',
                            variant: 'ghost',
                            'aria-pressed': reveal,
                            onClick: () => setReveal(!reveal),
                            children: reveal ? 'Hide values' : 'Show values'
                          })
                        ]
                      }),
                      jsx('ul', {
                        style: { ...mono, listStyle: 'none', padding: 0, margin: '4px 0 0 0' },
                        children: unique.map(seg =>
                          jsxs('li', {
                            style: { display: 'flex', gap: '8px' },
                            children: [
                              jsx('span', { style: { color: 'var(--ui-accent)' }, children: seg.placeholder }),
                              jsx('span', { style: { color: text.tertiary }, children: '→' }),
                              jsx('span', { style: { color: text.secondary }, children: reveal ? seg.original : hint(seg.kind, seg.original) })
                            ]
                          }, seg.placeholder)
                        )
                      })
                    ]
                  })
                : null
            ]
          })
        : null
    ]
  })
}

/** While masking is on: what will be masked in the draft, before pressing send. */
export function previewDraft(textValue, counts) {
  const vault = new Vault()
  vault.seed(counts)
  const result = maskText(String(textValue || ''), vault)
  return { kinds: result.kinds, summary: kindSummary(result.kinds) }
}

function DraftMaskPreview({ sessionId, counts }) {
  const [preview, setPreview] = useState(null)
  useEffect(() => {
    if (typeof window === 'undefined' || typeof host?.composer?.getDraft !== 'function') return undefined
    let live = true
    let reading = false
    const tick = async () => {
      if (reading) return
      reading = true
      try {
        const draft = await host.composer.getDraft(sessionId || null)
        if (live) setPreview(draft ? previewDraft(draft, counts) : null)
      } catch {
        if (live) setPreview(null)
      } finally {
        reading = false
      }
    }
    tick()
    const id = window.setInterval(tick, 700)
    return () => {
      live = false
      window.clearInterval(id)
    }
  }, [sessionId, counts])
  if (!preview || !preview.kinds.length) return null
  return jsxs('div', {
    'data-incognito': 'draft-preview',
    style: { display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap', padding: '2px 4px' },
    children: [
      jsx('span', { style: { fontSize: '11px', color: text.tertiary }, children: 'Will be masked before sending:' }),
      jsx('span', { style: chip, children: preview.summary })
    ]
  })
}

function MaskingFeedback({ ctx }) {
  const focusedSessionId = useValue(host?.state?.focusedSessionId) || ''
  const { status } = useIncognitoStatus(ctx, focusedSessionId)
  const record = useLastSend(focusedSessionId)
  const [dismissedAt, setDismissedAt] = useState(0)
  const masking = maskingFor(status, focusedSessionId)
  return jsxs('div', {
    children: [
      record && record.kinds.length && record.at !== dismissedAt
        ? jsx(SentToModelCard, { record, onDismiss: () => setDismissedAt(record.at) }, record.at)
        : null,
      masking?.on ? jsx(DraftMaskPreview, { sessionId: focusedSessionId, counts: masking.counts }) : null
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
    tip = `${LEVELS[mode].summary} ${describeTtl(state)}. Click to save this chat to your history (asks first).`
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
      // The status bar is always mounted, so it hosts the shared confirmations.
      jsx(BurnDialogHost, { ctx }),
      jsx(SaveDialogHost, { ctx })
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
      jsxs('div', {
        style: { marginTop: '12px', display: 'flex', gap: '8px', flexWrap: 'wrap' },
        children: [
          !state && sessionId && status?.saved
            ? jsx(Button, { size: 'sm', variant: 'outline', onClick: () => performUndo(ctx, sessionId), children: COPY.undoSave })
            : jsx(Button, {
                size: 'sm',
                variant: 'outline',
                disabled: !state || Boolean(state?.pending_burn),
                onClick: () => requestSave(ctx, sessionId, status),
                children: COPY.saveAction
              }),
          jsx(Button, {
            size: 'sm',
            variant: 'destructive',
            disabled: !state,
            onClick: () => requestBurn(ctx, sessionId),
            children: COPY.burnAction
          })
        ]
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
                    children: 'Check the session rows, known transcript and hook files, and this process’s masking vault.'
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
                            children: clean ? 'No artifacts found in these checks.' : verification.db_rows_found == null ? 'Database check unavailable.' : 'Artifacts or an active lease remain.'
                          }),
                          jsx('div', {
                            children: `Database rows ${verification.db_rows_found ?? 'unavailable'} · Transcripts ${verification.session_files_found ?? 0} · Hook files ${verification.hook_files_found ?? 0} · Memory ${verification.ram_vault_entries ?? 0}`
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
  description: 'Hidden chats with local cleanup and optional profile and personal detail protection.',
  register(ctx) {
    const refreshAll = () => notifyStateListeners()
    const unbind1 = ctx.onEvent?.('plugin.incognito.state.changed', event => {
      const payload = event?.payload
      if (payload?.burned === true && typeof payload.session_id === 'string' && payload.session_id) {
        forgetChat(payload.session_id)
      }
      refreshAll()
    })
    const unbind2 = ctx.onEvent?.('plugin.incognito.settings.changed', refreshAll)
    let checkingVaults = false
    const stopVaultCheck = ctx.setInterval?.(async () => {
      if (checkingVaults || !vaults.size) return
      checkingVaults = true
      try {
        for (const [sid, vault] of vaults) {
          const status = await fetchStatus(ctx, sid)
          if (vaults.get(sid) === vault && (status?.burned || maskingFor(status, sid)?.on === false)) {
            forgetChat(sid)
          }
        }
      } finally {
        checkingVaults = false
      }
    }, 30000)

    ctx.onDispose(() => {
      if (typeof unbind1 === 'function') unbind1()
      if (typeof unbind2 === 'function') unbind2()
      if (typeof stopVaultCheck === 'function') stopVaultCheck()
      stateListeners.clear()
      burnHosts.clear()
      saveHosts.clear()
      _resetMaskingForTests()
    })

    const focused = () => host?.state?.focusedSessionId?.get?.() || ''

    const composerExtras = []
    if (COMPOSER_AREAS.middleware) {
      composerExtras.push({
        id: 'mask-before-send',
        area: COMPOSER_AREAS.middleware,
        data: { handler: makeMaskingMiddleware(ctx) }
      })
    }

    ctx.registerMany([
      ...composerExtras,
      {
        id: 'composer-privacy-banner',
        area: COMPOSER_AREAS.top,
        render: () => jsx(ComposerPrivacyBanner, { ctx })
      },
      {
        id: 'composer-masking-feedback',
        area: COMPOSER_AREAS.underside || COMPOSER_AREAS.top,
        order: 5,
        render: () => jsx(MaskingFeedback, { ctx })
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
        id: 'palette-save',
        area: PALETTE_AREA,
        data: {
          id: 'incognito.palette.save',
          label: 'Incognito: Save this chat to my history…',
          keywords: ['incognito', 'save', 'keep', 'rescue', 'history'],
          run: () => requestSave(ctx, focused())
        }
      },
      {
        id: 'palette-undo-save',
        area: PALETTE_AREA,
        data: {
          id: 'incognito.palette.undoSave',
          label: 'Incognito: Return this saved chat to Incognito',
          keywords: ['incognito', 'undo', 'unsave', 'return'],
          run: () => performUndo(ctx, focused())
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
