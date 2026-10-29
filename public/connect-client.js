// The page can request a handoff, never grant browser permissions itself.
export function requestBrowserBridge(type, payload = {}, { target = window, timeoutMs = 1800 } = {}) {
  const requestId = target.crypto.randomUUID();
  return new Promise((resolve, reject) => {
    let timer;
    const finish = (error, result) => {
      clearTimeout(timer);
      target.removeEventListener('message', receive);
      if (error) reject(error); else resolve(result);
    };
    const receive = event => {
      const result = event.data;
      if (event.source !== target || event.origin !== target.location.origin || result?.source !== 'fabric-extension' || result.type !== 'fabric:bridge:result' || result.requestId !== requestId) return;
      if (!result.ok) finish(new Error(typeof result.error === 'string' ? result.error : result.error?.message || 'The browser helper could not continue.'));
      else finish(null, result);
    };
    target.addEventListener('message', receive);
    timer = setTimeout(() => finish(new Error('The Fabric browser helper is not available in this browser.')), timeoutMs);
    target.postMessage({ source: 'fabric-page', type: `fabric:bridge:${type}`, requestId, ...payload }, target.location.origin);
  });
}

export function inputValue(spec, raw) {
  if (spec.type === 'boolean') return Boolean(raw);
  if (spec.type === 'integer' || spec.type === 'number') {
    const value = Number(raw);
    if (!Number.isFinite(value) || (spec.type === 'integer' && !Number.isInteger(value))) throw new Error('Enter a valid number.');
    return value;
  }
  if (spec.type === 'object' || spec.type === 'array') {
    let value;
    try { value = JSON.parse(raw); } catch { throw new Error(`Enter valid JSON for this ${spec.type}.`); }
    if (spec.type === 'array' ? !Array.isArray(value) : value === null || Array.isArray(value) || typeof value !== 'object') throw new Error(`Expected a JSON ${spec.type}.`);
    return value;
  }
  return raw;
}

// Directory entries describe identities, never established account connections.
export function directoryCandidates(result) {
  return (Array.isArray(result?.candidates) ? result.candidates : []).filter(candidate => candidate && typeof candidate.id === 'string' && candidate.id && typeof candidate.name === 'string' && candidate.name);
}

export function connectionKind(connection) {
  if (connection.driver === 'device') return 'This computer';
  if (connection.driver === 'workspace') return 'Local folder';
  if (isPersistentBrowser(connection)) return 'Saved browser session';
  if (isDurableBrowser(connection)) return 'Saved app access';
  if (connection.driver === 'browser') return 'Browser session';
  if (connection.authMethod === 'oauth') return 'Provider account';
  return 'API connection';
}

export function isPersistentBrowser(connection) {
  return connection?.driver === 'browser' && (connection.transport === 'persistent' || connection.persistentSession === true || connection.lifecycle?.kind === 'persistent-browser');
}

export function isDurableBrowser(connection) {
  // A newer helper version alone must never widen an older tab-only grant.
  return connection?.driver === 'browser' && !isPersistentBrowser(connection) &&
    (connection.sessionScope === 'browser-profile' || connection.browserEvidence?.bridge?.scope === 'browser-profile');
}

export function browserCapabilityMatches(capability, connection) {
  if (capability.driver !== 'browser' || capability.appId !== connection.appId) return false;
  const route = connection.transport || 'helper', target = capability.transport || 'helper';
  return ['helper', 'persistent'].includes(route) && route === target && (route !== 'persistent' || capability.effect === 'read');
}

// Display wording follows the selected scope; immutable definitions and grants do not change.
export function browserOperationPresentation(capability, connection) {
  if (!isDurableBrowser(connection) || !capability || !browserCapabilityMatches(capability, connection) || capability.effect !== 'read' || !['observe', 'read'].includes(capability.action?.op)) return {};
  return {
    name: capability.action.op === 'observe' ? 'Inspect app page' : 'Read a page element',
    description: 'Read from this app in your normal browser profile. Each approved read can open a temporary tab when needed; no account identity is verified.'
  };
}

export function isConnectedService(connection) {
  return !!connection && connection.driver !== 'browser' && connection.status === 'ready';
}

// Pairing, helper heartbeat, page observation, and provider identity are separate facts.
export function browserConnectionState(connection, now = Date.now()) {
  const evidence = connection?.browserEvidence || {};
  const persistent = isPersistentBrowser(connection);
  const durable = isDurableBrowser(connection);
  const sessionState = connection?.lifecycle?.sessionState || evidence.session?.state;
  const heartbeatAt = Date.parse(evidence.bridge?.lastHeartbeatAt || '');
  let status = ['waiting', 'alive', 'stale', 'revoked', 'unavailable'].includes(evidence.bridge?.status) ? evidence.bridge.status : 'waiting';
  if (connection?.status === 'revoked' || (persistent && sessionState === 'revoked')) status = 'revoked';
  else if (!persistent && status === 'alive' && (!Number.isFinite(heartbeatAt) || heartbeatAt > now)) status = 'waiting';
  else if (!persistent && status === 'alive' && now - heartbeatAt >= 90000) status = 'stale';
  const observedAt = Date.parse(evidence.observedPage?.observedAt || '');
  const pageObserved = status === 'alive' && (!persistent || sessionState === 'available') && (!durable || evidence.bridge?.executionState === 'open') && evidence.page?.status === 'observed' && Number.isFinite(observedAt) && observedAt <= now && now - observedAt <= 120000;
  const labels = persistent ? { waiting: 'Waiting for saved session status', alive: 'Saved browser window available', stale: 'Saved browser session needs attention', revoked: 'Saved browser session removed', unavailable: 'Saved browser unavailable' } : durable ? { waiting: 'Waiting for browser helper', alive: 'Ready on demand', stale: 'Browser needs attention', revoked: 'Saved app access removed', unavailable: 'Browser helper unavailable' } : { waiting: 'Waiting for paired tab', alive: 'Browser helper available', stale: 'Paired tab needs attention', revoked: 'Browser pairing removed', unavailable: 'Paired tab unavailable' };
  // A saved profile can reopen after approval. It does not require a fabricated helper heartbeat.
  const canTest = persistent ? !['revoked', 'unavailable'].includes(status) && ['available', 'dormant', 'needs_sign_in'].includes(sessionState) : status === 'alive';
  const label = persistent && !['revoked', 'unavailable'].includes(status) ? ({ dormant: 'Saved session · reopens when needed', opening: 'Opening saved browser window…', needs_sign_in: 'Sign in again on the application’s website' }[sessionState] || labels[status]) : labels[status];
  return { status, label, canTest, accountVerified: false, pageObserved,
    pageLabel: pageObserved ? 'Page access observed' : evidence.observedPage ? 'Previous page observation is no longer current' : 'Page access not tested',
    origin: evidence.bridge?.origin || connection?.allowedOrigins?.[0] || '', lastHeartbeatAt: evidence.bridge?.lastHeartbeatAt || null,
    observedAt: evidence.observedPage?.observedAt || null };
}

export function buildSummary(report) {
  if (!report) return 'No action discovery has been run yet.';
  const count = Array.isArray(report.capabilityIds) ? report.capabilityIds.length : 0;
  if (report.status === 'failed') return 'Action discovery did not finish. No new access was granted.';
  if (report.status === 'blocked' || !count) return 'No executable actions were established by this check. See More details for the reported limitations.';
  const unsupported = Array.isArray(report.unsupported) ? report.unsupported.length : 0;
  return `${count} action definition${count === 1 ? '' : 's'} prepared${unsupported ? `; ${unsupported} other operation${unsupported === 1 ? ' is' : 's are'} not executable yet` : ''}. Account access and live execution still require a supported connection.`;
}
