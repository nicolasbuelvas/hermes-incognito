export const useState = init => [typeof init === 'function' ? init() : init, () => {}]
export const useEffect = () => {}
export const useCallback = fn => fn
export default { useState, useEffect, useCallback }
