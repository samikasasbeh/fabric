const base = 'http://127.0.0.1:4188';
const status = document.querySelector('#status');
const pairButton = document.querySelector('#pair');
let selectedTab = null;
let selectedOrigin = null;
function showStatus(message, error = false) { status.textContent = message; status.classList.toggle('error', error); }
function errorText(error) { return typeof error === 'string' ? error : error?.message || 'The request could not be completed.'; }
document.querySelector('#open-fabric').addEventListener('click', async () => {
  try { await chrome.tabs.create({url:`${base}/#connectors`,active:true}); }
  catch(error) { showStatus(errorText(error),true); }
});
async function showPairing() {
  const { fabricPair: pairing, fabricBridgeStatus: latest, fabricConnections = {}, fabricConnectionStatus = {} } = await chrome.storage.local.get(['fabricPair', 'fabricBridgeStatus', 'fabricConnections', 'fabricConnectionStatus']);
  const saved = Object.values(fabricConnections).filter(connection => connection.bridgeVersion === '0.3' && connection.sessionScope === 'browser-profile');
  document.querySelector('#saved-section').hidden = saved.length === 0;
  const list = document.querySelector('#saved-connections'); list.replaceChildren();
  for (const connection of saved) {
    const row = document.createElement('div'); row.className = 'saved-app';
    const title = document.createElement('strong'); title.textContent = connection.label || connection.origin;
    const origin = document.createElement('p'); origin.className = 'origin hint'; origin.textContent = connection.origin;
    const detail = document.createElement('p'); detail.className = 'hint';
    const latest = fabricConnectionStatus[connection.connectionId];
    detail.textContent = latest?.error || (latest?.state === 'completed' ? 'The last requested operation returned. Its result is shown in Fabric.' : 'Saved until you remove it. App tabs may be closed. Sign-in can still expire.');
    const actions = document.createElement('div'); actions.className = 'connection-actions';
    const check = document.createElement('button'); check.type = 'button'; check.textContent = 'Check requests';
    check.addEventListener('click', async () => {
      check.disabled = true;
      try { const result = await chrome.runtime.sendMessage({ type: 'fabric-poll', connectionId: connection.connectionId }); showStatus(result?.error || (result?.state === 'completed' ? 'Requested operation returned. Review the result in Fabric.' : 'No operation completed. This check does not open a tab unless an approved read is waiting.'), Boolean(result?.error)); await showPairing(); }
      catch (error) { showStatus(errorText(error), true); }
      finally { check.disabled = false; }
    });
    const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'subtle'; remove.textContent = 'Remove connection';
    remove.addEventListener('click', async () => {
      remove.disabled = true;
      try { const result = await chrome.runtime.sendMessage({ type: 'fabric-disconnect', connectionId: connection.connectionId }); if (!result?.ok) throw new Error(result?.error || 'Connection could not be removed.'); await showPairing(); showStatus('Connection removed from this browser. Your own tabs stay open. Disconnect it in Fabric too to revoke its runtime pairing.'); }
      catch (error) { showStatus(errorText(error), true); }
      finally { remove.disabled = false; }
    });
    actions.append(check, remove); row.append(title, origin, detail, actions); list.append(row);
  }
  document.querySelector('#paired-section').hidden = !pairing;
  document.querySelector('#replace-note').hidden = !pairing;
  if (!pairing) return;
  document.querySelector('#paired-origin').textContent = pairing.origin;
  document.querySelector('#paired-detail').textContent = pairing.tabId === selectedTab?.id ? 'Only this tab is paired. Closing it requires a new pairing. Saved app connections are separate.' : 'A different tab has an older tab-only pairing. Recovery replaces only that pairing.';
  document.querySelector('#last-check').textContent = latest?.connectionId === pairing.connectionId && latest.at ? `Last check: ${new Date(latest.at).toLocaleTimeString()}. ${latest.error || (latest.state === 'completed' ? 'A requested read was returned.' : latest.state === 'idle' ? 'No read was waiting.' : 'No completed read reported.')}` : 'No observed check yet.';
}
async function removeUnusedPermission(origin) {
  const { fabricConnections = {}, fabricPair } = await chrome.storage.local.get(['fabricConnections', 'fabricPair']);
  if (fabricPair?.origin !== origin && !Object.values(fabricConnections).some(connection => connection.origin === origin)) await chrome.permissions.remove({ origins: [`${origin}/*`] });
}
async function initialize() {
  try {
    [selectedTab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = new URL(selectedTab?.url || '');
    document.querySelector('#tab-title').textContent = selectedTab.title || url.hostname;
    document.querySelector('#tab-origin').textContent = url.origin;
    if (url.protocol !== 'https:') throw new Error('Open the app’s HTTPS website and click the Fabric extension on that tab.');
    selectedOrigin = url.origin;
    pairButton.disabled = false;
  } catch (error) {
    document.querySelector('#tab-title').textContent = 'Choose an application tab';
    document.querySelector('#tab-help').textContent = 'Switch to the app in Chrome or Edge, then open this extension again.';
    showStatus('Open Fabric to choose an app. Advanced recovery is only available on an HTTPS app tab.');
  }
  try { await showPairing(); } catch (error) { showStatus(errorText(error), true); }
}
document.querySelector('#pair-form').addEventListener('submit', async event => {
  event.preventDefault();
  const codeField = document.querySelector('#code');
  const code = codeField.value.trim().toUpperCase();
  if (!/^[A-F0-9]{12}$/.test(code)) { showStatus('Enter the 12-character pairing code shown in Fabric. It is not an API key.', true); return; }
  if (!selectedTab || !selectedOrigin) { showStatus('Open the app’s HTTPS tab first.', true); return; }
  pairButton.disabled = true;
  pairButton.textContent = 'Connecting…';
  let newlyGranted = false;
  let savedPairing = false;
  try {
    const origins = [`${selectedOrigin}/*`];
    const alreadyGranted = await chrome.permissions.contains({ origins });
    const granted = await chrome.permissions.request({ origins });
    if (!granted) throw new Error('Access to this application tab was not granted. Nothing was connected.');
    newlyGranted = !alreadyGranted;
    const currentTab = await chrome.tabs.get(selectedTab.id);
    if (new URL(currentTab.url).origin !== selectedOrigin) throw new Error('The selected tab changed application. Reopen the extension on the intended tab.');
    const response = await fetch(`${base}/api/browser/pair`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code, origin: selectedOrigin, label: currentTab.title, bridgeVersion:'0.2' }) });
    const data = await response.json();
    if (!response.ok) throw new Error(errorText(data.error));
    if (typeof data.token !== 'string' || !data.connection?.id) throw new Error('Fabric did not return a valid pairing. Try a new code.');
    const { fabricPair: previousPair } = await chrome.storage.local.get('fabricPair');
    await chrome.storage.local.set({ fabricPair: { token: data.token, tabId: selectedTab.id, origin: selectedOrigin, connectionId: data.connection.id, bridgeVersion:'0.2', pairingId:data.pairingId } });
    savedPairing = true;
    if (previousPair?.origin && previousPair.origin !== selectedOrigin) await removeUnusedPermission(previousPair.origin);
    codeField.value = '';
    showStatus('Tab-only pairing saved. Closing this tab requires pairing again. Saved app connections are unchanged. Inspect in Fabric before requesting separately approved clicks or fills.');
    await showPairing();
    const result = await chrome.runtime.sendMessage({ type: 'fabric-poll' });
    if (result?.error) showStatus(`Paired, but the first check needs attention: ${result.error}`, true);
    await showPairing();
  } catch (error) {
    showStatus(error instanceof TypeError ? 'Cannot reach local Fabric. Start it at http://127.0.0.1:4188 and try again.' : errorText(error), true);
    if (newlyGranted && !savedPairing) await removeUnusedPermission(selectedOrigin).catch(() => {});
  } finally { pairButton.disabled = !selectedOrigin; pairButton.textContent = 'Pair this tab only'; }
});
document.querySelector('#check').addEventListener('click', async () => {
  const check = document.querySelector('#check'); check.disabled = true;
  try {
    const result = await chrome.runtime.sendMessage({ type: 'fabric-poll' });
    showStatus(result?.error || (result?.state === 'completed' ? 'The requested read was returned to Fabric.' : result?.state === 'not_paired' ? 'No browser tab is paired.' : result?.state === 'busy' ? 'A read check is already in progress.' : 'Fabric is reachable. No requested read was waiting.'), !!result?.error);
    await showPairing();
  } catch (error) { showStatus(errorText(error), true); }
  finally { check.disabled = false; }
});
document.querySelector('#disconnect').addEventListener('click', async () => {
  try {
    const { fabricPair: pairing } = await chrome.storage.local.get('fabricPair');
    await chrome.storage.local.remove(['fabricPair', 'fabricBridgeStatus']);
    if (pairing) await removeUnusedPermission(pairing.origin);
    await showPairing();
    showStatus('Tab-only sharing stopped here. Saved app connections remain. Also disconnect this old pairing in Fabric to revoke its runtime authority.');
  } catch (error) { showStatus(errorText(error), true); }
});
initialize();
