// Seeded faults for the security review's group b1 fixes (docs/F03-SECURITY-REVIEW.md): the agent endpoint opens its
// environment before pinning it, every provider await holds its environment, and busy environments never lock out the
// rest. Same shape as test/faults/registry.mjs; `from` occurs exactly once in `file`, and `to` is the fault.
// Data only: nothing here reads or changes a file.

const TESTS = ['test/review-b1.test.mjs'];

export const FAULTS = Object.freeze([
  {id: 'review-b1-agent-pin-before-open', step: 'F03.11', name: 'The agent endpoint pins its environment before anything opens it (ISO-1, ROB-2).',
    file: 'developer-server.mjs', from: 'try { bundle = runtimes.bundle(scope); stores.pin(scope); }', to: 'try { stores.pin(scope); bundle = runtimes.bundle(scope); }', tests: TESTS},
  {id: 'review-b1-agent-busy-500', step: 'F03.11', name: 'An agent call that finds every environment busy gets a bare 500 instead of a fabric/0.1 503 (ISO-1).',
    file: 'developer-server.mjs', from: "if (!(error instanceof EnvironmentError && error.code === 'too_many_open')) throw error;", to: 'throw error;', tests: TESTS},
  {id: 'review-b1-hold-no-pin', step: 'F03.11', name: 'EnvironmentStores.hold opens the environment but never pins it (ROB-1, ISO-2, secrets-2).',
    file: 'lib/tenant/environments.mjs', from: '    this.pin(scope);\n    try { return await work(handle); } finally { this.unpin(scope); }', to: '    try { return await work(handle); } finally { /* seeded: nothing pinned */ }', tests: TESTS},
  {id: 'review-b1-callback-unpinned', step: 'F03.11', name: 'The sign-in callback waits on the token exchange with its environment unpinned (secrets-2, ISO-2, ROB-1).',
    file: 'lib/tenant/connect-sessions.mjs', from: 'return this.stores.hold(this.#byRoute(route), () => this.#signedIn(route, routeId, providerId, {state, code, error, flowId}));', to: 'return this.#signedIn(route, routeId, providerId, {state, code, error, flowId});', tests: TESTS},
  {id: 'review-b1-drop-unpinned', step: 'F03.11', name: 'Dropping a signed-in account waits on the provider\'s revoke with its environment unpinned (ISO-2, ROB-1).',
    file: 'lib/tenant/connect-sessions.mjs', from: '    await this.stores.hold(env.scope, async () => {\n      if (owner)', to: '    await (async () => {\n      if (owner)',
    also: [{from: "      env.vault.delete(stored.id); env.repository.delete('connections', stored.id);\n    });", to: "      env.vault.delete(stored.id); env.repository.delete('connections', stored.id);\n    })();"}], tests: TESTS},
  {id: 'review-b1-release-unpinned', step: 'F03.11', name: 'Releasing a link\'s waiting account pins nothing, in #release or in the #drop it calls (ISO-2, ROB-1).',
    file: 'lib/tenant/connect-sessions.mjs', from: 'return this.stores.hold(scope, async env => {\n      const pending = env.repository.get(\'connections\', session.pendingAccountRef);', to: 'return (async env => {\n      const pending = env.repository.get(\'connections\', session.pendingAccountRef);',
    also: [{from: '      this.#pendingRoute(session.id, false);\n      return released;\n    });', to: '      this.#pendingRoute(session.id, false);\n      return released;\n    })(this.stores.open(scope));'},
      {from: '    await this.stores.hold(env.scope, async () => {\n      if (owner)', to: '    await (async () => {\n      if (owner)'},
      {from: "      env.vault.delete(stored.id); env.repository.delete('connections', stored.id);\n    });", to: "      env.vault.delete(stored.id); env.repository.delete('connections', stored.id);\n    })();"}],
    note: 'The hold in #drop covers the same provider await, so only both removed together are caught; #release\'s own hold keeps the writes after the revoke inside the pin.', tests: TESTS},
  {id: 'review-b1-check-unpinned', step: 'F03.11', name: 'An account check refreshes the token with its environment unpinned (ROB-1).',
    file: 'lib/tenant/accounts.mjs', from: 'return this.stores.hold(caller.scope, async env => {\n      const owner = this.#named(env, externalUserId)', to: 'return (async env => {\n      const owner = this.#named(env, externalUserId)',
    also: [{from: '      return this.#row(env, owner, stored);\n    });', to: '      return this.#row(env, owner, stored);\n    })(this.stores.open(caller.scope));'}], tests: TESTS},
  {id: 'review-b1-disconnect-unpinned', step: 'F03.11', name: 'A disconnect waits on the provider\'s revoke with its environment unpinned (ROB-1, ISO-2).',
    file: 'lib/tenant/accounts.mjs', from: 'return this.stores.hold(env.scope, async () => {\n      const result = await this.disconnectRecord(', to: 'return (async () => {\n      const result = await this.disconnectRecord(',
    also: [{from: '      return result;\n    });\n  }', to: '      return result;\n    })();\n  }'}], tests: TESTS},
  {id: 'review-b1-delete-unpinned', step: 'F03.11', name: 'Deleting a user waits on the provider revokes with its environment unpinned (ROB-1, ISO-2).',
    file: 'lib/tenant/users.mjs', from: 'return this.stores.hold(caller.scope, env => this.#delete(caller, env, externalUserId));', to: 'return this.#delete(caller, this.stores.open(caller.scope), externalUserId);', tests: TESTS},
  {id: 'review-b1-hard-cap', step: 'F03.11', name: 'Sixteen busy environments fill the store cache and lock every other environment out (ISO-3).',
    file: 'lib/tenant/environments.mjs', from: 'if (this.#open.size >= this.#maxOpen * 4) fail(', to: 'if (this.#open.size >= this.#maxOpen) fail(', tests: TESTS},
  {id: 'review-b1-no-trim', step: 'F03.11', name: 'Idle environments past maxOpen are never closed again (ISO-3).',
    file: 'lib/tenant/environments.mjs', from: 'this.#trim(this.#maxOpen - 1);', to: 'this.#trim(this.#maxOpen * 4);', tests: TESTS},
]);
