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
import { useState, useEffect, useCallback } from 'react'
import { jsx, jsxs } from 'react/jsx-runtime'

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
      const isGet = action === 'status' && !payload?.method && Object.keys(payload || {}).every(k => k === 'session_id')
      if (isGet) {
        const query = payload?.session_id ? `?session_id=${encodeURIComponent(payload.session_id)}` : ''
        const res = await ctx.rest(`/${action}${query}`)
        if (res) return res
      } else {
        const res = await ctx.rest(`/${action}`, {
          method: 'POST',
          body: payload
        })
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

function NoticeBanner() {
  return jsx('div', {
    style: {
      padding: '6px 12px',
      fontSize: '11px',
      lineHeight: '16px',
      fontFamily: 'var(--font-mono, monospace)',
      background: 'rgba(239, 68, 68, 0.1)',
      color: '#f87171',
      border: '1px solid rgba(239, 68, 68, 0.3)',
      borderRadius: '4px',
      marginBottom: '6px'
    },
    children: 'Enable the incognito Python plugin in config (hermes plugins enable incognito) to enforce session scrubbing.'
  })
}

function ComposerPrivacyBanner({ ctx }) {
  const focusedSessionId = useValue(host?.state?.focusedSessionId) || ''
  const [status, setStatus] = useState(null)
  const [unmounted, setUnmounted] = useState(false)
  const [offline, setOffline] = useState(false)

  const refresh = useCallback(async () => {
    const res = await callBackend(ctx, 'status', { session_id: focusedSessionId })
    if (unmounted) return
    if (res) {
      setStatus(res)
      setOffline(false)
    } else {
      setOffline(true)
    }
  }, [ctx, focusedSessionId, unmounted])

  useEffect(() => {
    setUnmounted(false)
    refresh()
    stateListeners.add(refresh)
    return () => {
      setUnmounted(true)
      stateListeners.delete(refresh)
    }
  }, [refresh])

  const isIncognito = Boolean(status?.incognito)
  const isArmedDraft = !focusedSessionId && Boolean(status?.armed)

  if (!isIncognito && !isArmedDraft) {
    return null
  }

  const mode = (status?.session_state?.mode || status?.mode || status?.armed?.mode || 'standard').toLowerCase()
  const isStrict = mode === 'strict'
  const modeLabel = isStrict ? 'INCOGNITO · STRICT CLEAN-ROOM' : 'INCOGNITO · STANDARD'
  const blockedWrites = status?.metrics?.blocked_writes ?? status?.blocked_writes ?? 0
  const ramRedactions = status?.metrics?.ram_redactions ?? status?.ram_redactions ?? 0
  const ttlMinutes = status?.session_state?.ttl_minutes ?? status?.ttl_minutes ?? status?.armed?.ttl_minutes ?? 60

  return jsxs('div', {
    style: {
      display: 'flex',
      flexDirection: 'column',
      gap: '6px',
      padding: '8px 12px',
      background: isStrict ? 'rgba(220, 38, 38, 0.08)' : 'rgba(37, 99, 235, 0.08)',
      border: `1px solid ${isStrict ? 'rgba(220, 38, 38, 0.4)' : 'rgba(37, 99, 235, 0.4)'}`,
      borderRadius: '6px',
      marginBottom: '6px'
    },
    children: [
      offline ? jsx(NoticeBanner, {}) : null,
      jsxs('div', {
        style: {
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '8px'
        },
        children: [
          jsxs('div', {
            style: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' },
            children: [
              jsx('span', {
                style: {
                  fontFamily: 'var(--font-mono, monospace)',
                  fontSize: '11px',
                  fontWeight: 700,
                  letterSpacing: '0.06em',
                  padding: '2px 8px',
                  borderRadius: '3px',
                  background: isStrict ? '#dc2626' : '#2563eb',
                  color: '#ffffff'
                },
                children: modeLabel
              }),
              jsx('span', {
                style: {
                  fontFamily: 'var(--font-mono, monospace)',
                  fontSize: '11px',
                  color: 'var(--ui-text-secondary, #a1a1aa)'
                },
                children: `blocked writes: ${blockedWrites} | RAM redactions: ${ramRedactions} | TTL: ${ttlMinutes}m`
              })
            ]
          }),
          jsxs('div', {
            style: { display: 'flex', alignItems: 'center', gap: '6px' },
            children: [
              jsx(Button, {
                size: 'sm',
                variant: 'outline',
                onClick: async () => {
                  const nextMode = isStrict ? 'standard' : 'strict'
                  await callBackend(ctx, 'toggle', { session_id: focusedSessionId, mode: nextMode })
                  notifyStateListeners()
                  host.notify({ kind: 'info', message: `Switched to ${nextMode} mode` })
                },
                children: isStrict ? 'Switch Standard' : 'Switch Strict'
              }),
              jsx(Button, {
                size: 'sm',
                variant: 'ghost',
                onClick: async () => {
                  await callBackend(ctx, 'toggle', { session_id: focusedSessionId, mode: 'off' })
                  notifyStateListeners()
                  host.notify({ kind: 'info', message: 'Incognito disabled (retained session)' })
                },
                children: 'Keep & Exit'
              }),
              jsx(Button, {
                size: 'sm',
                variant: 'destructive',
                onClick: async () => {
                  await callBackend(ctx, 'burn', { session_id: focusedSessionId })
                  notifyStateListeners()
                  host.notify({ kind: 'warning', message: 'Session burned: zero trace remains' })
                },
                children: 'Burn Now'
              })
            ]
          })
        ]
      })
    ]
  })
}

function StatusbarIndicator({ ctx }) {
  const focusedSessionId = useValue(host?.state?.focusedSessionId) || ''
  const [status, setStatus] = useState(null)

  const refresh = useCallback(async () => {
    const res = await callBackend(ctx, 'status', { session_id: focusedSessionId })
    if (res) setStatus(res)
  }, [ctx, focusedSessionId])

  useEffect(() => {
    refresh()
    stateListeners.add(refresh)
    return () => {
      stateListeners.delete(refresh)
    }
  }, [refresh])

  const isIncognito = Boolean(status?.incognito)
  const isArmedDraft = !focusedSessionId && Boolean(status?.armed)
  const mode = (status?.session_state?.mode || status?.mode || status?.armed?.mode || 'standard').toLowerCase()
  const isStrict = mode === 'strict'

  let label = 'INCOGNITO: OFF'
  let color = 'var(--ui-text-tertiary, #71717a)'
  if (isIncognito) {
    label = isStrict ? 'INCOGNITO: ON (STRICT)' : 'INCOGNITO: ON (STANDARD)'
    color = isStrict ? '#ef4444' : '#3b82f6'
  } else if (isArmedDraft) {
    label = isStrict ? 'INCOGNITO: ARMED (STRICT)' : 'INCOGNITO: ARMED'
    color = '#f59e0b'
  }

  const handleClick = async () => {
    const res = await callBackend(ctx, 'toggle', {
      session_id: focusedSessionId,
      mode: 'standard'
    })
    notifyStateListeners()
    const active = res?.incognito || res?.armed
    host.notify({
      kind: 'info',
      message: active ? 'Incognito mode engaged' : 'Incognito mode disengaged'
    })
  }

  return jsx('button', {
    type: 'button',
    onClick: handleClick,
    title: 'Toggle Incognito Mode',
    style: {
      background: 'transparent',
      border: 'none',
      cursor: 'pointer',
      display: 'inline-flex',
      alignItems: 'center',
      gap: '4px',
      padding: '0 6px',
      height: '100%',
      fontFamily: 'var(--font-mono, monospace)',
      fontSize: '11px',
      fontWeight: 600,
      letterSpacing: '0.04em',
      color
    },
    children: label
  })
}

function PrivacyControlCenter({ ctx }) {
  const focusedSessionId = useValue(host?.state?.focusedSessionId) || ''
  const [status, setStatus] = useState(null)
  const [verifyId, setVerifyId] = useState(focusedSessionId)
  const [verification, setVerification] = useState(null)
  const [verifying, setVerifying] = useState(false)
  const [offline, setOffline] = useState(false)

  const refresh = useCallback(async () => {
    const res = await callBackend(ctx, 'status', { session_id: focusedSessionId })
    if (res) {
      setStatus(res)
      setOffline(false)
    } else {
      setOffline(true)
    }
  }, [ctx, focusedSessionId])

  useEffect(() => {
    refresh()
    stateListeners.add(refresh)
    return () => {
      stateListeners.delete(refresh)
    }
  }, [refresh])

  useEffect(() => {
    if (focusedSessionId && !verifyId) {
      setVerifyId(focusedSessionId)
    }
  }, [focusedSessionId, verifyId])

  const handleVerify = async () => {
    if (!verifyId) return
    setVerifying(true)
    const res = await callBackend(ctx, 'verify', { session_id: verifyId })
    setVerifying(false)
    if (res?.verification) {
      setVerification(res.verification)
    }
  }

  const isIncognito = Boolean(status?.incognito)
  const mode = status?.session_state?.mode || status?.mode || 'off'
  const isArmed = Boolean(status?.armed)
  const telemetry = status?.metrics || {}

  const cardStyle = {
    background: 'var(--ui-panel-bg, #18181b)',
    border: '1px solid var(--ui-border, #27272a)',
    borderRadius: '8px',
    padding: '16px'
  }

  const headingStyle = {
    fontFamily: 'var(--font-sans, sans-serif)',
    fontSize: '13px',
    fontWeight: 600,
    letterSpacing: '0.04em',
    textTransform: 'uppercase',
    color: 'var(--ui-text-primary, #f4f4f5)',
    marginBottom: '12px'
  }

  return jsxs('div', {
    style: {
      padding: '24px',
      maxWidth: '1040px',
      margin: '0 auto',
      display: 'flex',
      flexDirection: 'column',
      gap: '20px',
      color: 'var(--ui-text-primary, #f4f4f5)'
    },
    children: [
      jsxs('div', {
        style: { borderBottom: '1px solid var(--ui-border, #27272a)', paddingBottom: '16px' },
        children: [
          jsx('h1', {
            style: {
              fontSize: '20px',
              fontWeight: 700,
              letterSpacing: '-0.02em',
              margin: '0 0 4px 0'
            },
            children: 'Incognito Privacy Control Center'
          }),
          jsx('p', {
            style: {
              fontSize: '13px',
              color: 'var(--ui-text-secondary, #a1a1aa)',
              margin: 0
            },
            children: 'Zero-trace session lifecycle management, outbound PII vaulting, and forensic verification.'
          })
        ]
      }),
      offline ? jsx(NoticeBanner, {}) : null,
      jsxs('div', {
        style: {
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
          gap: '16px'
        },
        children: [
          jsxs('div', {
            style: cardStyle,
            children: [
              jsx('div', { style: headingStyle, children: 'Focused Session Shield' }),
              jsxs('div', {
                style: {
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                  fontSize: '12px',
                  fontFamily: 'var(--font-mono, monospace)',
                  marginBottom: '16px'
                },
                children: [
                  jsxs('div', {
                    children: [
                      jsx('span', { style: { color: 'var(--ui-text-secondary, #a1a1aa)' }, children: 'Session ID: ' }),
                      jsx('span', { children: focusedSessionId || '(none / fresh draft)' })
                    ]
                  }),
                  jsxs('div', {
                    children: [
                      jsx('span', { style: { color: 'var(--ui-text-secondary, #a1a1aa)' }, children: 'Status: ' }),
                      jsx('span', {
                        style: {
                          fontWeight: 700,
                          color: isIncognito ? (mode === 'strict' ? '#ef4444' : '#3b82f6') : 'var(--ui-text-tertiary, #71717a)'
                        },
                        children: isIncognito ? `ACTIVE (${mode.toUpperCase()})` : 'STANDARD STORAGE (OFF)'
                      })
                    ]
                  })
                ]
              }),
              jsxs('div', {
                style: { display: 'flex', gap: '8px', flexWrap: 'wrap' },
                children: [
                  jsx(Button, {
                    size: 'sm',
                    variant: isIncognito && mode === 'standard' ? 'outline' : 'default',
                    onClick: async () => {
                      await callBackend(ctx, 'toggle', { session_id: focusedSessionId, mode: 'standard' })
                      notifyStateListeners()
                      host.notify({ kind: 'info', message: 'Standard Incognito engaged' })
                    },
                    children: 'Engage Standard'
                  }),
                  jsx(Button, {
                    size: 'sm',
                    variant: isIncognito && mode === 'strict' ? 'outline' : 'default',
                    onClick: async () => {
                      await callBackend(ctx, 'toggle', { session_id: focusedSessionId, mode: 'strict' })
                      notifyStateListeners()
                      host.notify({ kind: 'info', message: 'Strict Clean-Room engaged' })
                    },
                    children: 'Engage Strict'
                  }),
                  jsx(Button, {
                    size: 'sm',
                    variant: 'destructive',
                    disabled: !focusedSessionId,
                    onClick: async () => {
                      if (!focusedSessionId) return
                      await callBackend(ctx, 'burn', { session_id: focusedSessionId })
                      notifyStateListeners()
                      host.notify({ kind: 'warning', message: 'Session burned: zero trace remains' })
                    },
                    children: 'Burn Session'
                  })
                ]
              })
            ]
          }),
          jsxs('div', {
            style: cardStyle,
            children: [
              jsx('div', { style: headingStyle, children: 'Next-Session Arming' }),
              jsx('p', {
                style: {
                  fontSize: '12px',
                  color: 'var(--ui-text-secondary, #a1a1aa)',
                  margin: '0 0 12px 0'
                },
                children: 'Arm the next created session to automatically initialize in Incognito clean-room mode.'
              }),
              jsxs('div', {
                style: {
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                  marginBottom: '16px'
                },
                children: [
                  jsx('span', {
                    style: {
                      fontFamily: 'var(--font-mono, monospace)',
                      fontSize: '12px',
                      color: isArmed ? '#f59e0b' : 'var(--ui-text-secondary, #a1a1aa)'
                    },
                    children: isArmed ? `ARMED (${status.armed.mode.toUpperCase()})` : 'DISARMED'
                  })
                ]
              }),
              jsxs('div', {
                style: { display: 'flex', gap: '8px', flexWrap: 'wrap' },
                children: [
                  jsx(Button, {
                    size: 'sm',
                    variant: 'default',
                    onClick: async () => {
                      await callBackend(ctx, 'arm', { mode: 'standard', ttl_minutes: 60 })
                      notifyStateListeners()
                      host.notify({ kind: 'info', message: 'Next session armed: Standard' })
                    },
                    children: 'Arm Standard'
                  }),
                  jsx(Button, {
                    size: 'sm',
                    variant: 'default',
                    onClick: async () => {
                      await callBackend(ctx, 'arm', { mode: 'strict', ttl_minutes: 30, redact_pii: true })
                      notifyStateListeners()
                      host.notify({ kind: 'info', message: 'Next session armed: Strict (Redact PII)' })
                    },
                    children: 'Arm Strict'
                  }),
                  jsx(Button, {
                    size: 'sm',
                    variant: 'outline',
                    disabled: !isArmed,
                    onClick: async () => {
                      await callBackend(ctx, 'arm', { disarm: true })
                      notifyStateListeners()
                      host.notify({ kind: 'info', message: 'Disarmed next session' })
                    },
                    children: 'Disarm'
                  })
                ]
              })
            ]
          })
        ]
      }),
      jsxs('div', {
        style: cardStyle,
        children: [
          jsx('div', { style: headingStyle, children: 'Content-Free Audit Telemetry' }),
          jsxs('div', {
            style: {
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
              gap: '12px'
            },
            children: [
              jsxs('div', {
                style: {
                  padding: '12px',
                  background: 'rgba(255, 255, 255, 0.03)',
                  borderRadius: '6px',
                  textAlign: 'center'
                },
                children: [
                  jsx('div', {
                    style: { fontSize: '20px', fontWeight: 700, fontFamily: 'var(--font-mono, monospace)' },
                    children: String(telemetry.sessions_protected ?? 0)
                  }),
                  jsx('div', {
                    style: { fontSize: '11px', color: 'var(--ui-text-secondary, #a1a1aa)', marginTop: '4px' },
                    children: 'Protected Chats'
                  })
                ]
              }),
              jsxs('div', {
                style: {
                  padding: '12px',
                  background: 'rgba(255, 255, 255, 0.03)',
                  borderRadius: '6px',
                  textAlign: 'center'
                },
                children: [
                  jsx('div', {
                    style: { fontSize: '20px', fontWeight: 700, fontFamily: 'var(--font-mono, monospace)' },
                    children: String(telemetry.sessions_burned ?? 0)
                  }),
                  jsx('div', {
                    style: { fontSize: '11px', color: 'var(--ui-text-secondary, #a1a1aa)', marginTop: '4px' },
                    children: 'Burned Chats'
                  })
                ]
              }),
              jsxs('div', {
                style: {
                  padding: '12px',
                  background: 'rgba(255, 255, 255, 0.03)',
                  borderRadius: '6px',
                  textAlign: 'center'
                },
                children: [
                  jsx('div', {
                    style: { fontSize: '20px', fontWeight: 700, fontFamily: 'var(--font-mono, monospace)' },
                    children: String(telemetry.orphans_swept ?? 0)
                  }),
                  jsx('div', {
                    style: { fontSize: '11px', color: 'var(--ui-text-secondary, #a1a1aa)', marginTop: '4px' },
                    children: 'Orphans Swept'
                  })
                ]
              }),
              jsxs('div', {
                style: {
                  padding: '12px',
                  background: 'rgba(255, 255, 255, 0.03)',
                  borderRadius: '6px',
                  textAlign: 'center'
                },
                children: [
                  jsx('div', {
                    style: { fontSize: '20px', fontWeight: 700, fontFamily: 'var(--font-mono, monospace)' },
                    children: String(telemetry.blocked_writes ?? 0)
                  }),
                  jsx('div', {
                    style: { fontSize: '11px', color: 'var(--ui-text-secondary, #a1a1aa)', marginTop: '4px' },
                    children: 'Writes Blocked'
                  })
                ]
              }),
              jsxs('div', {
                style: {
                  padding: '12px',
                  background: 'rgba(255, 255, 255, 0.03)',
                  borderRadius: '6px',
                  textAlign: 'center'
                },
                children: [
                  jsx('div', {
                    style: { fontSize: '20px', fontWeight: 700, fontFamily: 'var(--font-mono, monospace)' },
                    children: String(telemetry.pii_tokens_masked ?? 0)
                  }),
                  jsx('div', {
                    style: { fontSize: '11px', color: 'var(--ui-text-secondary, #a1a1aa)', marginTop: '4px' },
                    children: 'PII Tokens Masked'
                  })
                ]
              }),
              jsxs('div', {
                style: {
                  padding: '12px',
                  background: 'rgba(255, 255, 255, 0.03)',
                  borderRadius: '6px',
                  textAlign: 'center'
                },
                children: [
                  jsx('div', {
                    style: { fontSize: '20px', fontWeight: 700, fontFamily: 'var(--font-mono, monospace)' },
                    children: String(telemetry.files_zero_filled ?? 0)
                  }),
                  jsx('div', {
                    style: { fontSize: '11px', color: 'var(--ui-text-secondary, #a1a1aa)', marginTop: '4px' },
                    children: 'Files Zero-Filled'
                  })
                ]
              })
            ]
          })
        ]
      }),
      jsxs('div', {
        style: cardStyle,
        children: [
          jsx('div', { style: headingStyle, children: 'Forensic Zero-Trace Verifier' }),
          jsx('p', {
            style: {
              fontSize: '12px',
              color: 'var(--ui-text-secondary, #a1a1aa)',
              margin: '0 0 16px 0'
            },
            children: 'Inspect local SQLite database, transcript JSONL files, hook outputs, and RAM vault keys for residual artifacts.'
          }),
          jsxs('div', {
            style: { display: 'flex', gap: '8px', marginBottom: '16px' },
            children: [
              jsx('input', {
                type: 'text',
                value: verifyId,
                placeholder: 'Enter session_id to audit…',
                onChange: e => setVerifyId(e.target.value),
                style: {
                  flex: 1,
                  padding: '8px 12px',
                  fontFamily: 'var(--font-mono, monospace)',
                  fontSize: '12px',
                  background: 'rgba(0, 0, 0, 0.3)',
                  border: '1px solid var(--ui-border, #27272a)',
                  borderRadius: '6px',
                  color: 'var(--ui-text-primary, #f4f4f5)'
                }
              }),
              jsx(Button, {
                size: 'sm',
                variant: 'default',
                disabled: verifying || !verifyId,
                onClick: handleVerify,
                children: verifying ? 'Verifying…' : 'Run Audit'
              })
            ]
          }),
          verification
            ? jsxs('div', {
                style: {
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                  padding: '12px',
                  background: verification.zero_trace ? 'rgba(34, 197, 94, 0.08)' : 'rgba(239, 68, 68, 0.08)',
                  border: `1px solid ${verification.zero_trace ? 'rgba(34, 197, 94, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
                  borderRadius: '6px',
                  fontFamily: 'var(--font-mono, monospace)',
                  fontSize: '12px'
                },
                children: [
                  jsxs('div', {
                    style: {
                      fontWeight: 700,
                      color: verification.zero_trace ? '#4ade80' : '#f87171'
                    },
                    children: [
                      'AUDIT VERDICT: ',
                      verification.zero_trace ? 'PASS (ZERO TRACE CONFIRMED)' : 'FAIL (ARTIFACTS DETECTED)'
                    ]
                  }),
                  jsx('div', {
                    style: { color: 'var(--ui-text-secondary, #a1a1aa)' },
                    children: `Receipt ID: ${verification.receipt_id || verification.id || '(none)'}`
                  }),
                  jsxs('div', {
                    style: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '8px', marginTop: '4px' },
                    children: [
                      jsx('div', { children: `state.db rows: ${verification.db_rows_found ?? 0}` }),
                      jsx('div', { children: `JSONL transcripts: ${verification.session_files_found ?? 0}` }),
                      jsx('div', { children: `hook_outputs: ${verification.hook_files_found ?? 0}` }),
                      jsx('div', { children: `RAM vault keys: ${verification.ram_vault_entries ?? 0}` })
                    ]
                  })
                ]
              })
            : null
        ]
      })
    ]
  })
}

export default {
  id: 'incognito',
  name: 'Incognito Sessions',
  description: 'Zero-trace ephemeral sessions, outbound PII redaction, and memory scrubbing.',
  register(ctx) {
    const refreshAll = () => notifyStateListeners()
    const unbind1 = ctx.onEvent?.('plugin.incognito.state.changed', refreshAll)
    const unbind2 = ctx.onEvent?.('plugin.incognito.settings.changed', refreshAll)

    ctx.onDispose(() => {
      if (typeof unbind1 === 'function') unbind1()
      if (typeof unbind2 === 'function') unbind2()
      stateListeners.clear()
    })

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
          label: 'Toggle Incognito Mode on Focused Chat',
          category: 'Privacy',
          defaults: ['mod+shift+i'],
          run: async () => {
            const sid = host?.state?.focusedSessionId?.get?.() || ''
            await callBackend(ctx, 'toggle', { session_id: sid, mode: 'standard' })
            notifyStateListeners()
            host.notify({ kind: 'info', message: 'Toggled Incognito mode' })
          }
        }
      },
      {
        id: 'palette-toggle',
        area: PALETTE_AREA,
        data: {
          id: 'incognito.palette.toggle',
          label: 'Incognito: Toggle Private Session',
          keywords: ['incognito', 'privacy', 'ephemeral', 'toggle'],
          run: async () => {
            const sid = host?.state?.focusedSessionId?.get?.() || ''
            await callBackend(ctx, 'toggle', { session_id: sid, mode: 'standard' })
            notifyStateListeners()
            host.notify({ kind: 'info', message: 'Toggled Incognito mode' })
          }
        }
      },
      {
        id: 'palette-strict',
        area: PALETTE_AREA,
        data: {
          id: 'incognito.palette.strict',
          label: 'Incognito: Enable Strict Clean-Room Mode',
          keywords: ['incognito', 'strict', 'clean-room', 'privacy'],
          run: async () => {
            const sid = host?.state?.focusedSessionId?.get?.() || ''
            await callBackend(ctx, 'toggle', { session_id: sid, mode: 'strict' })
            notifyStateListeners()
            host.notify({ kind: 'info', message: 'Strict Clean-Room mode enabled' })
          }
        }
      },
      {
        id: 'palette-arm',
        area: PALETTE_AREA,
        data: {
          id: 'incognito.palette.arm',
          label: 'Incognito: Arm Next New Chat as Incognito',
          keywords: ['incognito', 'arm', 'next', 'draft'],
          run: async () => {
            await callBackend(ctx, 'arm', { mode: 'standard', ttl_minutes: 60 })
            notifyStateListeners()
            host.notify({ kind: 'info', message: 'Armed next new session as Incognito' })
          }
        }
      },
      {
        id: 'palette-burn',
        area: PALETTE_AREA,
        data: {
          id: 'incognito.palette.burn',
          label: 'Incognito: Burn Current Session Immediately',
          keywords: ['incognito', 'burn', 'delete', 'purge', 'scrub'],
          run: async () => {
            const sid = host?.state?.focusedSessionId?.get?.() || ''
            if (!sid) {
              host.notify({ kind: 'warning', message: 'No active session to burn' })
              return
            }
            await callBackend(ctx, 'burn', { session_id: sid })
            notifyStateListeners()
            host.notify({ kind: 'warning', message: 'Session burned: zero trace remains' })
          }
        }
      },
      {
        id: 'palette-open',
        area: PALETTE_AREA,
        data: {
          id: 'incognito.palette.open',
          label: 'Incognito: Open Privacy Control Center',
          keywords: ['incognito', 'privacy', 'center', 'audit', 'verify'],
          run: () => {
            if (host?.navigate) {
              host.navigate('/incognito')
            }
          }
        }
      }
    ])
  }
}
