// F03.10 (N13, D5): who made a change for an end user, and where. The developer's server relays from its own screens
// (developer_app, the key's decision power decides what it may relay); Fabric's hosted page decides as the person who
// holds a link the developer's server minted (fabric_page, named by the key that minted it and the session).

/** The party behind a developer's /v1 request. */
export const developerParty = caller => Object.freeze({decidedIn: 'developer_app', keyId: caller.keyId, serviceClientId: caller.serviceClientId, canDecide: caller.scopes.includes('decisions:write')});

/** The fields every recorded change carries about its party. */
export const partyFields = party => ({decidedIn: party.decidedIn, byKey: party.keyId, serviceClientId: party.serviceClientId, ...(party.sessionId ? {sessionId: party.sessionId} : {})});
