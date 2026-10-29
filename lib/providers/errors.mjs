// Shared error identity preserves the public ConnectionError facade without
// a provider/connection-manager module cycle.
export class ConnectionError extends Error {
  constructor(message, code = 'unavailable') { super(message); this.code = code; }
}
