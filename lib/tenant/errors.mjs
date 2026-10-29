// F03.5: the one error shape the developer API turns into {error: {code, message, requestId, details?}}.
export class TenantError extends Error {
  constructor(status, code, message, details, headers) { super(message); this.status = status; this.code = code; if (details) this.details = details; if (headers) this.headers = headers; }
}
export const notFound = () => new TenantError(404, 'not_found', 'Nothing with that id exists here.');
export const invalid = message => new TenantError(400, 'invalid_request', message);
