# Fabric browser bridge 0.3

This is an executable browser adapter, not a provider API login or native desktop controller. It saves **separate, explicitly approved app connections in the current browser profile**. The app uses that browser profile's normal sign-in session; the helper never reads or exports cookies, passwords or website session storage. Visible page text may nevertheless contain private account data. Provider login can expire independently of saved Fabric consent.

## Development setup

1. In Chrome or Edge (Chromium 120 or later), open the extensions page, enable Developer mode and **Load unpacked** this `extensionsk` directory. After a code update, reload the extension.
2. Open **http://127.0.0.1:4188/#connectors in that same browser profile** and reload the page. Safari and the Codex in-app browser cannot use this Chrome/Edge extension.
3. Choose an app and Connect. The extension opens its own confirmation page. Approve the declared website permission and saved connection. Consent is saved before opening an active, user-owned sign-in tab; a failed tab opening or incomplete login does not erase consent.
4. Sign in on the app website yourself if required. Pairing proves approved browser-profile access to an origin, **not** provider account identity. Inspect the page in Fabric to discover current controls. Each click/fill requires a separate exact-action approval.
5. App tabs may be closed. Only an approved read/inspection may open a replacement inactive tab. A pending click/fill whose inspected tab closed fails and requires a fresh inspection; it is never reopened or replayed.

The popup lists saved apps and can remove one connection without removing others. Browser removal stops local dispatch immediately; also disconnect in Fabric to revoke the runtime pairing. Shared website permissions remain while another saved or legacy grant uses that origin. Website permissions or login cannot be silently granted, and sites may restrict synthetic DOM interactions.

The popup's advanced code-entry form remains an explicitly **v0.2 tab-only** developer recovery path. Its existing `fabricPair` is not migrated or widened. Closing its selected tab still requires re-pairing. It coexists with saved v0.3 apps.

## Page-to-extension setup contract

The content script is declared only for `http://127.0.0.1:4188/*`, top frame, and checks the exact origin and window sender. It accepts only setup messages, never operation commands.

```js
const requestId = crypto.randomUUID();
window.postMessage({
  source: 'fabric-page',
  type: 'fabric:bridge:ping', // or fabric:bridge:connect
  requestId,
  // connect only: unmodified response from POST /api/pair
  // pairing: {pairingId, code, appName, launchUrl, origins, expiresAt, ...}
}, 'http://127.0.0.1:4188');
```

Listen for same-window, same-origin responses with `source: 'fabric-extension'`, `type: 'fabric:bridge:result'` and the same requestId. Ping returns `{ok:true,version:'0.3'}`. Connect returns `{ok:true,pairingId,confirmationOpened:true}` after the extension confirmation opens. **That is not connection completion.** Poll `GET /api/pair/:pairingId/status`; only the exact setup ID becoming `paired` establishes completion. No bearer credential is returned to the page.

The extension confirmation button requests optional host permission, then calls `POST /api/browser/pair` with `{code,origin,label,bridgeVersion:'0.3',sessionScope:'browser-profile'}`. The response must include the matching pairingId, bridge version and scope. Setup requests lacking that explicit v0.3 scope cannot silently create durable consent. A secret code is single-use, short-lived, kept in extension storage only during setup, and deleted when setup completes or fails. Opening the app does not mean it is signed in.

## Connection and tab lifecycle

- `storage.local.fabricConnections` is keyed by connection ID and stores token, origin, label, version and scope, never a tab ID. Storage access is restricted to trusted extension contexts.
- `storage.session.fabricLeases` is keyed by connection ID and stores `{tabId,owned,lastUsedAt}`. Worker restart may reuse a verified same-origin current-session lease. Browser restart/extension reload clears leases, so recycled IDs and arbitrary matching tabs are never adopted.
- Durable polls send `{execution:{state:'idle'|'open'}}`. Health/idle polling never opens a tab. Reads may create one inactive same-origin tab, subject to a global limit of three helper-owned tabs. The helper processes at most two app connections concurrently; it does not promise unlimited simultaneous throughput.
- Idle cleanup after three minutes closes only helper-owned, inactive tabs still on their approved origin. Activating, navigating or reloading an owned tab relinquishes cleanup ownership. User-owned sign-in tabs are not closed. Idle leases are a convenience, not a way to extend a snapshot's lifetime.
- Poll/result requests have a seven-second network deadline; opening a page waits at most twenty seconds. Durable command expiry is checked before opening and immediately before injection. Expired/failed commands are not automatically replayed.
- The exact runtime response HTTP 401 with `code: 'browser_revoked'` removes that local grant and its safe owned lease. Other HTTP failures retain consent. Local grant presence is rechecked before dispatch and receipt; receipt data is suppressed if consent was removed during execution.

## Operation contract

Runtime jobs still use `/api/browser/poll` and `/api/browser/result`, authenticated by the locally stored pairing token. No arbitrary JavaScript, shell command, cookie access, desktop access or browser-wide browsing is exposed.

| Capability | Arguments | Outcome |
| --- | --- | --- |
| `<app>.browser.observe.v1` | `{}` | Visible text, `snapshotId`, page URL, and controls with opaque `targetId`, label, role, `canClick` and `canFill`. No field values. |
| `<app>.browser.read.v1` | `{selector}` | Text of exactly one visible, non-sensitive DOM element. |
| `<app>.browser.click.v2` | `{snapshotId,targetId}` | A bounded click of that inspected control. |
| `<app>.browser.fill.v2` | `{snapshotId,targetId,value}` | Native value setter and input/change events for an inspected ordinary input or textarea. Does not submit a form. |

Snapshots expire after two minutes and are bound to the document, exact URL, origin, DOM node, label/attributes and enabled/visible state. Document mutations and input/change events invalidate them conservatively, including changes around an otherwise unchanged control. Each dispatched write consumes its snapshot, preventing replay. Inspect again before the next action. Passwords, OTP, token/key, payment and marked-sensitive controls are excluded. Rich-text/contenteditable fields, file upload, cross-origin/native-app navigation and credential-form submission are not supported. Form destinations and submitter overrides must stay same-origin and in the current tab. Only top-document controls are inspected; iframe/shadow-root controls are not discovered.

Writes require the runtime's exact-job authorization callback, checked on queueing, dispatch and result acceptance. The extension does not accept action instructions via page messages. Browser write permissions must always be Ask or Off, never unattended/standing approval. Pairings with bridge version 0.1 cannot perform writes.

**Successful DOM dispatch always reports `persistentEffect: "unverified"`.** It never proves that a provider saved a record, sent a message or completed another business action. A new readback/application-specific assertion is required before semantic success can be reported. Failed/expired/unknown write outcomes must not automatically replay. Changed/revoked authority cancels pending commands. This bridge does not verify provider identity or repair expired provider sessions.

## Tests

```sh
node --test extensionsk/test/*.test.mjs test/browser-actions.test.mjs test/browser-pairing.test.mjs
```

These are synthetic fixtures covering permissions, message provenance, exact pairing, multi-app consent, worker/browser restart state, idle cleanup, closure recovery, expiry, revocation, control dispatch, stale targets, sensitive inputs and conservative verification. `test/durable-browser-live.test.mjs` provides the separate installed-extension synthetic Chromium lifecycle proof. Neither fixture suite is evidence of connection to a user's live app account, acceptance by a real identity provider, or a successful provider-side write.
