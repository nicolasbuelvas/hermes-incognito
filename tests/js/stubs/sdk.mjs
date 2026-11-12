// Minimal @hermes/plugin-sdk stand-in for logic tests. Only the named imports plugin.js
// uses are provided; optional UI kit pieces are absent, like on an older Desktop build.
export const toasts = []
let focused = ''
export function setFocused(sid) {
  focused = sid
}
export const host = {
  state: { focusedSessionId: { get: () => focused } },
  notify: t => toasts.push(t),
  navigate: () => {}
}
export const Button = props => ({ type: 'Button', props })
export const COMPOSER_AREAS = { top: 'composer.top' }
export const KEYBINDS_AREA = 'keybinds'
export const PALETTE_AREA = 'palette'
export const ROUTES_AREA = 'routes'
export const SIDEBAR_NAV_AREA = 'sidebar.nav'
export const STATUSBAR_AREAS = { right: 'statusbar.right' }
export const useValue = atom => (atom && typeof atom.get === 'function' ? atom.get() : atom)
