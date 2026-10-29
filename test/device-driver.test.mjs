import test from 'node:test';
import assert from 'node:assert/strict';
import {DeviceDriver, deviceCapabilities, validateDeviceCapability} from '../lib/device-driver.mjs';

const cap = operation => deviceCapabilities.find(capability => capability.action.op === operation);
const system = {platform:()=>'darwin', type:()=>'Darwin', release:()=>'25.0', arch:()=>'arm64', cpus:()=>[{},{}], totalmem:()=>16_000_000_000, uptime:()=>120.9};

test('connect creates an opaque local authority without reading a hardware report', async () => {
  let commands = 0;
  const driver = new DeviceDriver({system, executeFile:async()=>{commands++;}});
  const state = await driver.init();
  const connection = driver.connect();
  assert.equal(state.capabilities.length, 3);
  assert.equal(connection.appId, 'local-device');
  assert.equal(connection.driver, 'device');
  assert.equal(connection.status, 'ready');
  assert.equal(connection.identity.id, connection.id);
  assert.equal(connection.authMethod, 'local-consent');
  assert.equal(commands, 0);
});

test('computer overview is a real observation with no username, hostname, network or serial fields', async () => {
  const driver = new DeviceDriver({system});
  const outcome = await driver.execute(cap('system'));
  assert.deepEqual(outcome.data, {platform:'darwin', operatingSystem:'Darwin', release:'25.0', architecture:'arm64', logicalProcessors:2, totalMemoryBytes:16_000_000_000, uptimeSeconds:120, readOnly:true});
  assert.equal(outcome.verification.status, 'observed');
});

test('restricted system observations are identified as unavailable rather than fabricated', async () => {
  const driver = new DeviceDriver({system:{...system, uptime:()=>{throw new Error('operation not permitted');}}});
  const outcome = await driver.execute(cap('system'));
  assert.equal(outcome.data.platform, 'darwin');
  assert.equal(Object.hasOwn(outcome.data, 'uptimeSeconds'), false);
  assert.deepEqual(outcome.data.unavailableFields, ['uptimeSeconds']);
});

test('capability mutation, unsupported operations and injected arguments fail before dispatch', async () => {
  let commands = 0;
  const driver = new DeviceDriver({system, executeFile:async()=>{commands++;}});
  for (const mutated of [{...cap('usb'), action:{op:'usb', command:'curl'}}, {...cap('usb'), effect:'write'}, {...cap('usb'), appId:'notion'}, {...cap('usb'), id:'custom.system'}, {...cap('usb'), status:'candidate'}]) {
    assert.throws(()=>validateDeviceCapability(mutated), /built-in/);
    await assert.rejects(driver.execute(mutated));
  }
  await assert.rejects(driver.execute(cap('usb'), {command:'cat /etc/passwd'}), /undeclared/);
  assert.equal(commands, 0);
  assert.ok(Object.isFrozen(cap('usb').action));
});

test('USB inventory runs only the fixed shell-free bounded command and drops private fields', async () => {
  const driver = new DeviceDriver({system, executeFile:async (file, args, options) => {
    assert.equal(file, '/usr/sbin/system_profiler');
    assert.deepEqual(args, ['SPUSBDataType', '-json', '-detailLevel', 'mini']);
    assert.equal(options.shell, false);
    assert.equal(options.timeout, 6000);
    assert.equal(options.maxBuffer, 512 * 1024);
    assert.equal(options.killSignal, 'SIGKILL');
    assert.deepEqual(Object.keys(options.env).sort(), ['LANG','LC_ALL','PATH']);
    return {stdout:JSON.stringify({SPUSBDataType:[{_name:'USB Bus', host_controller:'controller-unique-id', serial_num:'secret', _items:[{_name:'Test keyboard', vendor_id:'0x0001', product_id:'0x0002', manufacturer:'Test maker', serial_num:'super-secret', location_id:'private-location', volume_name:'Private files', _items:[{_name:'Hub', serial_number:'also-secret'}]}]}]})};
  }});
  const outcome = await driver.execute(cap('usb'));
  assert.equal(outcome.data.count, 3);
  assert.equal(outcome.data.devices[1].name, 'Test keyboard');
  assert.equal(outcome.data.devices[0].kind, 'controller');
  assert.doesNotMatch(JSON.stringify(outcome), /super-secret|private-location|Private files|also-secret|controller-unique-id/);
});

test('USB output is bounded, malformed reports fail, and subprocess errors do not leak output', async () => {
  const outputs = ['not json', '{}', ' '.repeat(512 * 1024 + 1)];
  for (const stdout of outputs) await assert.rejects(new DeviceDriver({system, executeFile:async()=>({stdout})}).execute(cap('usb')), /report/);
  await assert.rejects(new DeviceDriver({system, executeFile:async()=>{throw new Error('private serial 123');}}).execute(cap('usb')), error => /time\/output limits/.test(error.message) && !error.message.includes('123'));
});

test('platform support is explicit and never runs a macOS command on another platform', async () => {
  let calls = 0;
  const driver = new DeviceDriver({system:{...system, platform:()=>'linux'}, executeFile:async()=>{calls++;}});
  assert.equal((await driver.init()).capabilities.includes(cap('usb').id), false);
  await assert.rejects(driver.execute(cap('usb')), /macOS only/);
  assert.equal(calls, 0);
});

test('installed tools are checked in fixed paths without executing or probing accounts', async () => {
  const paths = [];
  const driver = new DeviceDriver({system, executeFile:async()=>assert.fail('must not execute discovered programs'), fileStat:async path=>{paths.push(path); if (path !== '/usr/bin/git') throw new Error('not found'); return {isFile:()=>true};}, fileAccess:async()=>{}});
  const result = await driver.execute(cap('tools'));
  assert.deepEqual(result.data.tools, [{name:'git', executablePath:'/usr/bin/git', executable:true, accountConnected:false, runnableByFabric:false}]);
  assert.equal(result.data.count, 1);
  assert.ok(paths.length <= 18);
  assert.ok(paths.every(path => /^\/(opt\/homebrew\/bin|usr\/local\/bin|usr\/bin)\/(git|gh|node|python3|docker|ffmpeg)$/.test(path)));
});

test('authorization is enforced before reads and again after a pending command', async () => {
  let calls = 0;
  const driver = new DeviceDriver({system, executeFile:async()=>{calls++; return {stdout:'{"SPUSBDataType":[]}'};}});
  await assert.rejects(driver.execute(cap('usb'), {}, ()=>{throw new Error('revoked');}), /revoked/);
  assert.equal(calls, 0);
  let checks = 0;
  await assert.rejects(driver.execute(cap('usb'), {}, ()=>{if (++checks === 2) throw new Error('revoked');}), /revoked/);
  assert.equal(calls, 1);
});

test('real local computer observation executes without a subprocess or secret discovery', async () => {
  const driver = new DeviceDriver();
  const observation = await driver.execute(cap('system'));
  assert.ok(observation.data.logicalProcessors > 0);
  assert.ok(observation.data.totalMemoryBytes > 0);
  assert.ok(observation.data.uptimeSeconds >= 0 || observation.data.unavailableFields?.includes('uptimeSeconds'));
  assert.equal(observation.verification.status, 'observed');
});
