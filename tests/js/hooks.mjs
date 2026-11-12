const STUBS = {
  '@hermes/plugin-sdk': new URL('./stubs/sdk.mjs', import.meta.url).href,
  react: new URL('./stubs/react.mjs', import.meta.url).href,
  'react/jsx-runtime': new URL('./stubs/jsx-runtime.mjs', import.meta.url).href
}

export async function resolve(specifier, context, next) {
  if (specifier in STUBS) return { url: STUBS[specifier], shortCircuit: true }
  return next(specifier, context)
}
