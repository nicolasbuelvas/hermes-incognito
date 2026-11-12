// Resolve the three specifiers a Hermes desktop plugin may import to local stubs.
import { register } from 'node:module'

register('./hooks.mjs', import.meta.url)
