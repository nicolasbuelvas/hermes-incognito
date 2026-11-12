// Masks every text in the JSON file given as argv[2] with the Desktop masker and prints the
// results as JSON, so tests/test_desktop_js.py can compare them with pii.mask_text.
import { readFileSync } from 'node:fs'
import { Vault, maskText } from '../../desktop/plugin.js'

const texts = JSON.parse(readFileSync(process.argv[2], 'utf8'))
const shared = new Vault()
const out = texts.map(text => {
  const fresh = maskText(text, new Vault())
  return { text: fresh.text, kinds: fresh.kinds, shared: maskText(text, shared).text }
})
process.stdout.write(JSON.stringify(out))
