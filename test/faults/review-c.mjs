// F03.11 security review, group c (branding, logos and the registry): one seeded fault per fix, in the format of
// test/faults/registry.mjs. Each `from` is copied exactly from the current file and occurs there once; `to` puts the
// reviewed fault back, and test/review-c.test.mjs fails with it.

const TESTS = ['test/review-c.test.mjs'];

export const FAULTS = Object.freeze([
  {id: 'review-c-authz-2-hold', step: 'F03.11', name: 'Enabling production lets branding set while production was off go live without the operator\'s review (authz-2).',
    file: 'lib/tenant/registry.mjs', from: 'if (Object.keys(held).length) {', to: 'if (false) {', tests: TESTS},
  {id: 'review-c-brw-1-pairs', step: 'F03.11', name: 'Check only the accent, and the ink on both surfaces, so muted, danger and attention text can match the page (BRW-1).',
    file: 'lib/tenant/brand.mjs', from: '    for (const [a, b, what] of PAIRS) {',
    to: "    for (const [a, b, what] of [['accent', 'onAccent', 'the accent and the text on it'], ['ink', 'surface', 'the text and the page'], ['ink', 'surfaceRaised', 'the text and the cards']]) {", tests: TESTS},
  {id: 'review-c-brw-1-stored', step: 'F03.11', name: 'Serve a stored brand set that fails the readability checks (BRW-1).',
    file: 'lib/tenant/brand.mjs', from: 'const readable = scheme => { try { return checkedBrand({[scheme]: brand[scheme]})[scheme]; } catch { return null; } };',
    to: 'const readable = scheme => brand[scheme];', tests: TESTS},
  {id: 'review-c-iso-6-scan', step: 'F03.11', name: 'Prune a project\'s logos by listing every project\'s stored logo bytes (ISO-6).',
    file: 'lib/tenant/registry.mjs', from: 'for (const hash of new Set([before?.logo?.hash, before?.pendingBranding?.logo?.hash])) if (hash && !keep.has(hash)) this.#store.delete(\'projectLogos\', `${projectId}.${hash}`);',
    to: 'for (const logo of this.list(\'projectLogos\').filter(item => item.projectId === projectId && !keep.has(item.hash))) this.#store.delete(\'projectLogos\', logo.id);', tests: TESTS},
]);
