import test from 'node:test';
import assert from 'node:assert/strict';
import {TRANSFORMS, runTransform} from '../lib/transforms/index.mjs';
import {TransformError} from '../lib/transforms/_shared/error.v1.mjs';
import {utcMillis, utcParts} from '../lib/transforms/_shared/utc.v1.mjs';
import {vectorTests} from './fixtures/transform-vectors.mjs';

// F10.8 (docs/F10.8-BUILD-MAP.md parts b and g): _shared/utc.v1.mjs, the only file of the transform library that names Date, the eleven
// time transforms, and the vectors of test/fixtures/transforms/time.json. Zone facts are tz 2026a, as measured in section 1 of the map.
const SECONDS = 'time.rfc3339ToEpochSeconds@1', MILLIS = 'time.rfc3339ToEpochMillisString@1', FROM_MILLIS = 'time.epochMillisStringToRfc3339@1';
const ALL_DAY = 'time.allDayEnd@1', ZONE = 'time.zone@1', ZONED = 'time.zonedToRfc3339@1', TS = 'time.slackTs@1', DECIMAL = 'time.decimalCompare@1';
const WINDOW = 'time.window@1', FREE = 'time.freeSlots@1', RRULE = 'time.rrule@1';
const IDS = [SECONDS, MILLIS, FROM_MILLIS, ALL_DAY, ZONE, ZONED, TS, DECIMAL, WINDOW, FREE, RRULE];
const DAY = 86_400_000;
// A now far from the machine's clock, so a transform that read the clock instead of its input would be seen.
const NOW = Date.UTC(2031, 0, 1);
const refused = code => error => {
  assert.ok(error instanceof TransformError, `expected a TransformError, got ${error}`);
  assert.equal(error.code, code);
  return true;
};
const run = (id, args) => runTransform(id, args);
const seconds = time => run(SECONDS, {time}).seconds;
const zoned = (local, zone, offset) => run(ZONED, {local, zone, ...(offset === undefined ? {} : {offset})}).time;
const iso = ms => new Date(ms).toISOString();

test('utcParts() refuses anything but a safe integer within Date\'s range before calling new Date', () => {
  for (const value of ['2026', '2026-10-20T10:00:00Z', 1.5, NaN, Infinity, 2 ** 53, -(2 ** 53), 8_640_000_000_000_001, null, undefined, {valueOf: () => 0}]) {
    assert.equal(utcParts(value), null, String(value));
  }
  assert.deepEqual(utcParts(0), {year: 1970, month: 1, day: 1, hour: 0, minute: 0, second: 0, millisecond: 0, weekday: 4});
  assert.deepEqual(utcParts(1_792_504_800_123), {year: 2026, month: 10, day: 20, hour: 14, minute: 0, second: 0, millisecond: 123, weekday: 2});
  assert.equal(utcParts(8_640_000_000_000_000).year, 275_760);
});

test('utcMillis() builds UTC instants by calendar, refusing days, hours, minutes and seconds that do not exist', () => {
  assert.equal(utcMillis({year: 2026, month: 10, day: 20, hour: 14}), Date.UTC(2026, 9, 20, 14));
  assert.equal(utcMillis({year: 2028, month: 2, day: 29}), Date.UTC(2028, 1, 29));
  assert.equal(utcMillis({year: 2026, month: 12, day: 31, hour: 23, minute: 59, second: 59, millisecond: 999}), Date.UTC(2026, 11, 31, 23, 59, 59, 999));
  assert.equal(utcMillis({year: 50, month: 1, day: 1}), Date.parse('0050-01-01T00:00:00Z'), 'two-digit years are years, not 1900 plus the year');
  assert.equal(utcMillis({year: 0, month: 3, day: 1}), Date.parse('0000-03-01T00:00:00Z'));
  for (const bad of [{year: 2026, month: 2, day: 29}, {year: 2026, month: 2, day: 30}, {year: 2026, month: 13, day: 1}, {year: 2026, month: 0, day: 1}, {year: 2026, month: 1, day: 0},
    {year: 2026, month: 1, day: 1, hour: 24}, {year: 2026, month: 1, day: 1, minute: 60}, {year: 2026, month: 1, day: 1, second: 60}, {year: 2026, month: 1, day: 1, millisecond: 1000},
    {year: 2026.5, month: 1, day: 1}, {year: '2026', month: 1, day: 1}, {year: 10_000, month: 1, day: 1}, {year: -1, month: 1, day: 1}, {month: 1, day: 1}]) {
    assert.equal(utcMillis(bad), null, JSON.stringify(bad));
  }
  for (const ms of [0, 951_782_400_000, 1_792_504_800_123, 1_835_395_199_999]) {
    const {weekday, ...parts} = utcParts(ms);
    assert.equal(utcMillis(parts), ms, 'a round trip');
  }
});

vectorTests('time');

test('part g registers eleven transforms, each with the kind, clock, step data, codes and runtime facts of the map', () => {
  for (const id of IDS) assert.ok(TRANSFORMS.has(id), id);
  const entry = id => TRANSFORMS.get(id), sorted = list => [...list].sort();
  for (const id of IDS) {
    assert.deepEqual(sorted(entry(id).runtimeFacts), [ZONE, ZONED].includes(id) ? ['tz'] : [], `${id}: only the zone transforms read zone data, through Intl`);
    assert.equal(entry(id).kind, [WINDOW, RRULE].includes(id) ? 'guard' : 'map', id);
    assert.equal(entry(id).usesClock, id === WINDOW, id);
  }
  const refuses = {[SECONDS]: ['time_invalid'], [MILLIS]: ['time_invalid'], [FROM_MILLIS]: ['time_invalid'], [ALL_DAY]: ['time_invalid'], [ZONE]: ['zone_invalid'],
    [ZONED]: ['time_ambiguous', 'time_invalid', 'time_nonexistent', 'zone_invalid'], [TS]: ['ts_invalid'], [DECIMAL]: ['time_invalid'],
    [WINDOW]: ['time_invalid', 'window_order', 'window_past', 'window_too_far'], [FREE]: ['busy_unknown', 'time_invalid', 'window_order'], [RRULE]: ['time_invalid']};
  for (const id of IDS) assert.deepEqual(sorted(entry(id).refuses), refuses[id], id);
  assert.deepEqual(entry(FREE).stepData, {freeBusy: {maxBytes: 1_048_576}}, 'Calendar\'s freeBusy answer is keyed by calendar id, so the transform parses it');
  assert.deepEqual(Object.keys(entry(TS).stepData), ['ts'], 'a ts is provider data, so a number refuses with ts_invalid');
  for (const id of IDS.filter(id => ![FREE, TS].includes(id))) assert.deepEqual(entry(id).stepData, {}, id);
  // Open point Minor 4: every window field but now is optional, so the cancel path of Schedule or cancel, which has no instant, passes.
  assert.deepEqual(entry(WINDOW).input.required, ['now']);
  assert.deepEqual(sorted(Object.keys(entry(WINDOW).input.properties)), ['end', 'instant', 'maxDays', 'now', 'start']);
});

test('RFC 3339: an hour outside 00 to 23, a minute or second outside 00 to 59, an offset beyond ±23:59 and a day that does not exist refuse', () => {
  const bad = ['2026-10-20T24:00:00Z', '2026-10-20T25:00:00Z', '2026-10-20T99:00:00Z', '2026-10-20T10:60:00Z', '2026-10-20T10:99:00Z', '2026-10-20T10:00:60Z',
    '2026-10-20T10:00:00+24:00', '2026-10-20T10:00:00+23:60', '2026-10-20T10:00:00-24:00', '2026-10-20T10:00:00-99:99', '2026-02-29T00:00:00Z', '2026-04-31T00:00:00Z',
    '2026-00-10T00:00:00Z', '2026-10-00T00:00:00Z', '2026-13-01T00:00:00Z', '2026-10-20T10:00:00', '2026-10-20t10:00:00Z', '2026-10-20T10:00:00z', '2026-10-20 10:00:00Z',
    ' 2026-10-20T10:00:00Z', '2026-10-20T10:00:00Z ', '2026-10-20T10:00Z', '2026-10-20T10:00:00.Z', '2026-10-20T10:00:00+0500', '20261-10-20T10:00:00Z', '2026-10-20',
    '2026-10-20T1:00:00Z', '२०२६-10-20T10:00:00Z', ''];
  for (const time of bad) {
    for (const id of [SECONDS, MILLIS]) assert.throws(() => run(id, {time}), refused('time_invalid'), `${id} ${time}`);
    assert.throws(() => run(WINDOW, {instant: time, now: NOW}), refused('time_invalid'), `window ${time}`);
  }
  for (const time of ['2026-10-20T23:59:59Z', '2026-10-20T00:00:00Z', '2026-10-20T10:59:59+23:59', '2026-10-20T10:00:00-23:59', '2028-02-29T12:00:00Z', '2000-02-29T12:00:00.5Z']) {
    assert.equal(typeof seconds(time), 'number', time);
  }
  // A local date-time and an offset follow the same ranges.
  for (const local of ['2026-10-20T24:00:00', '2026-10-20T23:60:00', '2026-10-20T23:59:60', '2026-10-20T25:00:00', '2026-02-30T10:00:00', '2026-10-20T10:00', '2026-10-20T10:00:00Z',
    '2026-10-20T10:00:00-04:00', '2026-10-20T10:00:00.5', '0000-01-01T10:00:00', '2026-10-20 10:00:00', '']) {
    assert.throws(() => zoned(local, 'America/Toronto'), refused('time_invalid'), local);
  }
  for (const offset of ['+24:00', '-24:00', '+05:60', '0500', '+5:00', 'Z', '-04:00 ', '']) assert.throws(() => zoned('2026-10-20T10:00:00', 'America/Toronto', offset), refused('time_invalid'), offset);
});

test('RFC 3339 to epoch seconds and milliseconds: offsets apply, fractions floor, -00:00 reads as UTC, and the range is years 0000 to 9999 at any offset', () => {
  assert.equal(seconds('2026-10-20T10:00:00-04:00'), 1_792_504_800);
  assert.equal(seconds('2026-10-20T19:30:00+05:30'), 1_792_504_800);
  assert.equal(seconds('2026-10-20T14:00:00-00:00'), 1_792_504_800);
  assert.equal(seconds('2026-10-20T14:00:00.999999999Z'), 1_792_504_800, 'a fraction floors');
  assert.equal(seconds('1969-12-31T23:59:59.5Z'), -1, 'before 1970 it floors too');
  assert.equal(run(MILLIS, {time: '1969-12-31T23:59:59.5Z'}).millis, '-500');
  assert.equal(run(MILLIS, {time: '2026-10-20T14:00:00.1239Z'}).millis, '1792504800123');
  assert.equal(run(MILLIS, {time: '1970-01-01T00:00:00Z'}).millis, '0');
  const schema = TRANSFORMS.get(SECONDS).output.properties.seconds;
  assert.deepEqual([schema.minimum, schema.maximum], [-62_167_305_540, 253_402_387_139]);
  assert.equal(seconds('0000-01-01T00:00:00+23:59'), schema.minimum);
  assert.equal(seconds('9999-12-31T23:59:59.999-23:59'), schema.maximum);
  assert.equal(seconds('0000-01-01T00:00:00Z'), Date.parse('0000-01-01T00:00:00Z') / 1000);
  assert.equal(run(MILLIS, {time: '9999-12-31T23:59:59.999-23:59'}).millis, '253402387139999');
  assert.equal(run(MILLIS, {time: '0000-01-01T00:00:00+23:59'}).millis, '-62167305540000');
});

test('epoch millisecond strings become RFC 3339 in UTC exactly, within safe integers and years 0000 to 9999', () => {
  const back = millis => run(FROM_MILLIS, {millis}).time;
  assert.equal(back('1792504800123'), '2026-10-20T14:00:00.123Z');
  assert.equal(back('0'), '1970-01-01T00:00:00.000Z');
  assert.equal(back('-1'), '1969-12-31T23:59:59.999Z');
  assert.equal(back('253402300799999'), '9999-12-31T23:59:59.999Z');
  assert.equal(back('-62167219200000'), '0000-01-01T00:00:00.000Z');
  for (const millis of ['-0', '01', '1.5', '1e3', '', ' 1', '1 ', '+1', '0x10', '253402300800000', '-62167219200001', '9007199254740993', '12345678901234567', '١٢٣']) {
    assert.throws(() => run(FROM_MILLIS, {millis}), refused('time_invalid'), millis);
  }
  for (const time of ['2026-10-20T14:00:00.123Z', '1969-12-31T23:59:59.999Z', '2028-02-29T00:00:00.000Z', '0000-01-01T00:00:00.000Z']) assert.equal(back(run(MILLIS, {time}).millis), time, 'a round trip');
});

test('all-day end dates are exclusive, by UTC date arithmetic, and refuse dates that do not exist', () => {
  const end = (date, days) => run(ALL_DAY, {date, days}).end;
  assert.equal(end('2026-10-20', 1), '2026-10-21');
  assert.equal(end('2027-02-28', 1), '2027-03-01');
  assert.equal(end('2028-02-28', 2), '2028-03-01');
  assert.equal(end('2026-03-07', 2), '2026-03-09', 'a daylight-saving change in between changes nothing');
  assert.equal(end('2026-01-01', 365), '2027-01-01');
  assert.equal(end('2026-01-01', 3660), new Date(Date.UTC(2026, 0, 1) + 3660 * DAY).toISOString().slice(0, 10));
  assert.equal(end('9999-12-30', 1), '9999-12-31');
  assert.equal(end('0000-02-28', 1), '0000-02-29', 'year 0000 is a leap year in the proleptic calendar');
  for (const date of ['9999-12-31', '2026-02-30', '2026-1-01', '2026-10-20T00:00:00Z', '20261020', ' 2026-10-20', '']) assert.throws(() => run(ALL_DAY, {date, days: 1}), refused('time_invalid'), date);
  for (const days of [0, -1, 3661, 1.5]) assert.throws(() => run(ALL_DAY, {date: '2026-10-20', days}), refused('input_invalid'), String(days));
});

test('zones: names Intl knows, in IANA form with each part starting in upper case, come back exactly as given; offsets and case variants refuse', () => {
  for (const zone of ['America/Toronto', 'US/Eastern', 'Europe/Kyiv', 'Europe/Kiev', 'UTC', 'GMT', 'Etc/GMT+5', 'America/Argentina/Buenos_Aires', 'Antarctica/DumontDUrville',
    'America/Port-au-Prince', 'EST5EDT', 'Asia/Kolkata']) {
    assert.deepEqual(run(ZONE, {zone}), {zone}, zone);
  }
  for (const zone of ['+05:30', '-05:00', '+0530', 'Z', 'GMT+5', 'GMT+05:30', 'Not/AZone', 'america/toronto', 'America/TORONTO', 'AMERICA/TORONTO', 'America/toronto', 'utc', 'Utc',
    'America/', '/America', 'America//Toronto', 'A/B/C/D', 'America/Toronto ', ' America/Toronto', 'America/Toronto\n', 'Europe/Kyiv/', '..', 'Factory', '']) {
    assert.throws(() => run(ZONE, {zone}), refused('zone_invalid'), JSON.stringify(zone));
    assert.throws(() => run(ZONED, {local: '2026-10-20T10:00:00', zone}), refused('zone_invalid'), JSON.stringify(zone));
  }
});

test('daylight-saving boundaries (tz 2026a): gaps refuse, folds refuse without a valid offset, and events across a change keep their UTC length', () => {
  const toronto = (local, offset) => zoned(local, 'America/Toronto', offset);
  // America/Toronto: on 2026-03-08 02:00 at -05:00 becomes 03:00 at -04:00; on 2026-11-01 02:00 at -04:00 becomes 01:00 at -05:00.
  assert.equal(toronto('2026-03-08T01:59:59'), '2026-03-08T01:59:59-05:00');
  for (const local of ['2026-03-08T02:00:00', '2026-03-08T02:30:00', '2026-03-08T02:59:59']) assert.throws(() => toronto(local), refused('time_nonexistent'), local);
  for (const offset of ['-05:00', '-04:00']) assert.throws(() => toronto('2026-03-08T02:30:00', offset), refused('time_nonexistent'), `an offset (${offset}) cannot make a gap time exist`);
  for (const local of ['2026-11-01T01:00:00', '2026-11-01T01:30:00', '2026-11-01T01:59:59']) assert.throws(() => toronto(local), refused('time_ambiguous'), local);
  assert.equal(toronto('2026-11-01T00:59:59'), '2026-11-01T00:59:59-04:00');
  assert.equal(toronto('2026-11-01T02:00:00'), '2026-11-01T02:00:00-05:00');
  assert.throws(() => toronto('2026-11-01T01:30:00', '-06:00'), refused('time_invalid'), 'an offset that is not valid there');
  assert.throws(() => toronto('2026-10-20T10:00:00', '-05:00'), refused('time_invalid'));
  assert.equal(toronto('2026-10-20T10:00:00', '-04:00'), '2026-10-20T10:00:00-04:00', 'a matching offset on an ordinary time passes');
  // A 30-minute event across each change keeps its UTC length.
  const length = (start, end) => seconds(end) - seconds(start);
  assert.equal(length(toronto('2026-03-08T01:45:00'), toronto('2026-03-08T03:15:00')), 1800);
  assert.equal(length(toronto('2026-11-01T00:45:00'), toronto('2026-11-01T01:15:00', '-04:00')), 1800);
  assert.equal(length(toronto('2026-11-01T01:45:00', '-04:00'), toronto('2026-11-01T01:15:00', '-05:00')), 1800);
  // Europe/London changes at 01:00 UTC.
  assert.throws(() => zoned('2026-03-29T01:30:00', 'Europe/London'), refused('time_nonexistent'));
  assert.throws(() => zoned('2026-10-25T01:30:00', 'Europe/London'), refused('time_ambiguous'));
  assert.equal(zoned('2026-10-25T01:30:00', 'Europe/London', '+00:00'), '2026-10-25T01:30:00+00:00');
  assert.equal(zoned('2026-10-25T01:30:00', 'Europe/London', '-00:00'), '2026-10-25T01:30:00+00:00');
  // Australia/Lord_Howe moves by 30 minutes.
  assert.throws(() => zoned('2026-10-04T02:15:00', 'Australia/Lord_Howe'), refused('time_nonexistent'));
  assert.equal(zoned('2026-10-04T02:30:00', 'Australia/Lord_Howe'), '2026-10-04T02:30:00+11:00');
  assert.throws(() => zoned('2026-04-05T01:45:00', 'Australia/Lord_Howe'), refused('time_ambiguous'));
  assert.equal(zoned('2026-04-05T01:45:00', 'Australia/Lord_Howe', '+10:30'), '2026-04-05T01:45:00+10:30');
  // Pacific/Apia skipped the whole of 2011-12-30.
  assert.throws(() => zoned('2011-12-30T12:00:00', 'Pacific/Apia'), refused('time_nonexistent'));
  assert.equal(zoned('2011-12-31T12:00:00', 'Pacific/Apia'), '2011-12-31T12:00:00+14:00');
  // Fixed zones, and history RFC 3339 cannot write.
  assert.equal(zoned('2026-10-20T10:00:00', 'UTC'), '2026-10-20T10:00:00+00:00');
  assert.equal(zoned('2026-10-20T10:00:00', 'Asia/Kolkata'), '2026-10-20T10:00:00+05:30');
  assert.equal(zoned('2026-10-20T10:00:00', 'Etc/GMT+5'), '2026-10-20T10:00:00-05:00');
  assert.throws(() => toronto('1800-01-01T12:00:00'), refused('time_invalid'), 'local mean time has seconds in its offset');
});

test('Slack ts: BigInt microseconds, compared as numbers, one microsecond on for an exclusive cursor, and RFC 3339 with microseconds', () => {
  const ts = (value, than) => run(TS, {ts: value, ...(than === undefined ? {} : {than})});
  assert.deepEqual(ts('1355517523.000005'), {ts: '1355517523.000005', next: '1355517523.000006', time: '2012-12-14T20:38:43.000005Z'});
  assert.equal(ts('1355517523.999999').next, '1355517524.000000', 'the microsecond carries');
  assert.equal(ts('9999999999.999998').next, '9999999999.999999');
  assert.equal(ts('0.000000').time, '1970-01-01T00:00:00.000000Z');
  assert.ok('999999999.999999' > '1000000000.000000', 'a string comparison says otherwise');
  assert.equal(ts('999999999.999999', '1000000000.000000').order, -1);
  assert.equal(ts('1000000000.000000', '999999999.999999').order, 1);
  assert.equal(ts('1355517523.000005', '1355517523.000005').order, 0);
  assert.equal(ts('0001.000000', '1.000000').order, 0);
  for (const value of [1355517523.000005, 1.5, '1.5', '1355517523.0000051', '1355517523', '1355517523.', '.000001', '12345678901.000000', ' 1.000000', '1.000000 ',
    '-1.000000', '+1.000000', '1,000000', '1e9.000000', null, true, {ts: '1.000000'}, ['1.000000'], '9999999999.999999', '١.٠٠٠٠٠٠']) {
    assert.throws(() => ts(value), refused('ts_invalid'), JSON.stringify(value));
  }
  for (const than of ['1.5', '', '1355517523.0000051']) assert.throws(() => ts('1.000000', than), refused('ts_invalid'), than);
  assert.throws(() => ts('1.000000', 1.5), refused('input_invalid'), 'than is a closed string');
  assert.throws(() => run(TS, {}), refused('input_invalid'), 'ts is required');
});

test('decimal strings compare as numbers of up to 20 digits, past safe integers, for Gmail historyId and internalDate', () => {
  const order = (a, b) => run(DECIMAL, {a, b}).order;
  assert.equal(order('9', '10'), -1);
  assert.ok('9' > '10', 'a string comparison says otherwise');
  assert.equal(order('10', '9'), 1);
  assert.equal(order('007', '7'), 0);
  assert.equal(order('18446744073709551615', '18446744073709551614'), 1);
  assert.equal(order('99999999999999999999', '99999999999999999999'), 0);
  for (const [a, b] of [['100000000000000000000', '1'], ['', '1'], ['-1', '1'], ['1.0', '1'], [' 1', '1'], ['1e3', '1'], ['0x1', '1'], ['١', '1']]) {
    assert.throws(() => run(DECIMAL, {a, b}), refused('time_invalid'), `${a} ${b}`);
    assert.throws(() => run(DECIMAL, {a: b, b: a}), refused('time_invalid'), `${b} ${a}`);
  }
});

test('window (a guard with the passed now): each check applies only to the fields given (open point Minor 4)', () => {
  const window = args => run(WINDOW, {...args, now: args.now ?? NOW});
  assert.deepEqual(window({}), {}, 'the cancel path of Schedule or cancel carries no instant');
  assert.deepEqual(window({instant: iso(NOW + DAY), maxDays: 120}), {});
  assert.deepEqual(window({instant: iso(NOW), maxDays: 120}), {}, 'now itself is not past');
  assert.deepEqual(window({instant: iso(NOW + 120 * DAY), maxDays: 120}), {}, 'exactly 120 days passes (spec line 1140)');
  assert.throws(() => window({instant: iso(NOW + 120 * DAY + 1), maxDays: 120}), refused('window_too_far'));
  assert.throws(() => window({instant: `${iso(NOW + 120 * DAY).slice(0, -1)}0001Z`, maxDays: 120}), refused('window_too_far'), 'a fraction below the millisecond counts');
  assert.throws(() => window({instant: iso(NOW - 1), maxDays: 120}), refused('window_past'));
  assert.deepEqual(window({instant: iso(NOW + 1000 * DAY)}), {}, 'without maxDays only the past is checked');
  assert.throws(() => window({instant: iso(NOW - 1)}), refused('window_past'));
  assert.deepEqual(window({maxDays: 120}), {}, 'maxDays without an instant checks nothing');
  // The passed now decides, never the machine clock.
  assert.throws(() => window({instant: iso(NOW + DAY), maxDays: 120, now: NOW + 2 * DAY}), refused('window_past'));
  assert.throws(() => window({instant: iso(NOW + DAY), maxDays: 120, now: NOW - 200 * DAY}), refused('window_too_far'));
  // Gmail vacation: the start before the end (spec line 1027), which is not refused for being in the past.
  assert.deepEqual(window({start: '2026-12-20T00:00:00-05:00', end: '2027-01-04T00:00:00-05:00'}), {});
  assert.deepEqual(window({start: '2020-01-01T00:00:00Z', end: '2020-01-02T00:00:00Z'}), {});
  for (const [start, end] of [['2027-01-04T00:00:00Z', '2026-12-20T00:00:00Z'], ['2026-12-20T00:00:00Z', '2026-12-20T00:00:00Z'], ['2026-12-20T05:00:00Z', '2026-12-20T00:00:00-05:00'],
    ['2026-12-20T00:00:00.0001Z', '2026-12-20T00:00:00.0002Z']]) {
    assert.throws(() => window({start, end}), refused('window_order'), `${start} ${end}`);
  }
  assert.throws(() => window({start: '2026-12-20T24:00:00Z'}), refused('time_invalid'), 'a start alone is still read');
  assert.throws(() => window({end: 'tomorrow'}), refused('time_invalid'));
  const control = '\u0001'.repeat(64);
  assert.throws(() => window({start: control, end: control, instant: control, maxDays: 120}), refused('time_invalid'), 'the byte cap holds three fields at their longest');
  assert.throws(() => window({start: '2026-12-20T00:00:00Z', end: '2026-12-21T00:00:00Z', instant: iso(NOW - 1)}), refused('window_past'));
  for (const maxDays of [0, 3661, 1.5]) assert.throws(() => window({maxDays}), refused('input_invalid'), String(maxDays));
  assert.throws(() => run(WINDOW, {}), refused('input_invalid'), 'now is required');
});

const answer = (calendars, extra = {}) => ({kind: 'calendar#freeBusy', timeMin: '2026-10-20T13:00:00.000Z', timeMax: '2026-10-20T21:00:00.000Z', calendars, ...extra});
const free = (freeBusy, start = '2026-10-20T13:00:00Z', end = '2026-10-20T21:00:00Z', minMinutes = 30) => run(FREE, {freeBusy, start, end, minMinutes});
const busy = (start, end) => ({start, end});

test('free slots: the busy blocks of every calendar merge, and the free time left of at least minMinutes comes back in UTC, sorted', () => {
  assert.deepEqual(free(answer({primary: {busy: [busy('2026-10-20T18:00:00Z', '2026-10-20T19:00:00Z'), busy('2026-10-20T12:00:00Z', '2026-10-20T13:30:00Z'),
    busy('2026-10-20T20:30:00Z', '2026-10-20T22:00:00Z')]}})).free, [{start: '2026-10-20T13:30:00Z', end: '2026-10-20T18:00:00Z'}, {start: '2026-10-20T19:00:00Z', end: '2026-10-20T20:30:00Z'}]);
  assert.deepEqual(free(answer({primary: {busy: []}})).free, [{start: '2026-10-20T13:00:00Z', end: '2026-10-20T21:00:00Z'}]);
  assert.deepEqual(free(answer({primary: {busy: [busy('2026-10-20T13:00:00Z', '2026-10-20T21:00:00Z')]}})).free, []);
  assert.deepEqual(free(answer({primary: {busy: [busy('2026-10-20T13:29:00Z', '2026-10-20T20:30:00Z')]}})).free, [{start: '2026-10-20T20:30:00Z', end: '2026-10-20T21:00:00Z'}],
    'a 29-minute gap is left out, a 30-minute one kept');
  assert.deepEqual(free(answer({primary: {busy: [busy('2026-10-20T10:00:00-04:00', '2026-10-20T11:00:00-04:00')]}, b: {busy: [busy('2026-10-20T14:30:00Z', '2026-10-20T14:40:00Z')]}})).free,
    [{start: '2026-10-20T13:00:00Z', end: '2026-10-20T14:00:00Z'}, {start: '2026-10-20T15:00:00Z', end: '2026-10-20T21:00:00Z'}], 'offsets apply, and a block inside another changes nothing');
  // Below the millisecond, busy time grows outward and the window shrinks inward, so nothing busy shows as free.
  assert.deepEqual(free(answer({primary: {busy: [busy('2026-10-20T14:00:00.0005Z', '2026-10-20T15:00:00.0005Z')]}}), '2026-10-20T13:00:00.0005Z', '2026-10-20T21:00:00Z', 1).free,
    [{start: '2026-10-20T13:00:00.001Z', end: '2026-10-20T14:00:00Z'}, {start: '2026-10-20T15:00:00.001Z', end: '2026-10-20T21:00:00Z'}]);
});

test('free slots never count a calendar Fabric could not read as free, and hold at most 2,000 busy blocks', () => {
  const ok = {primary: {busy: []}};
  const {timeMin, ...noMin} = answer(ok);
  assert.equal(timeMin, '2026-10-20T13:00:00.000Z');
  for (const [what, freeBusy] of [
    ['a calendar with errors', answer({...ok, 'x@example.com': {errors: [{domain: 'global', reason: 'notFound'}], busy: []}})],
    ['a calendar with an empty errors list', answer({...ok, other: {errors: [], busy: []}})],
    ['a calendar with no busy list', answer({...ok, other: {}})],
    ['a calendar that is not an object', answer({...ok, other: 'busy'})],
    ['no calendars', answer({})],
    ['no calendars object', answer(null)],
    ['a group that could not be expanded', answer(ok, {groups: {'team@example.com': {errors: [{domain: 'global', reason: 'groupTooBig'}]}}})],
    ['a busy block that does not parse', answer({primary: {busy: [busy('2026-10-20T14:00:00', '2026-10-20T15:00:00Z')]}})],
    ['a busy block that ends before it starts', answer({primary: {busy: [busy('2026-10-20T15:00:00Z', '2026-10-20T14:00:00Z')]}})],
    ['a busy block that is not an object', answer({primary: {busy: ['2026-10-20T14:00:00Z']}})],
    ['a window that starts before the answer\'s timeMin', answer(ok, {timeMin: '2026-10-20T14:00:00Z'})],
    ['a window that ends after the answer\'s timeMax', answer(ok, {timeMax: '2026-10-20T20:00:00Z'})],
    ['an answer without timeMin', noMin],
    ['an answer whose timeMax does not parse', answer(ok, {timeMax: 'soon'})],
    ['a list', []],
    ['null', null],
  ]) assert.throws(() => free(freeBusy), refused('busy_unknown'), what);
  for (const [start, end] of [['2026-10-20T21:00:00Z', '2026-10-20T13:00:00Z'], ['2026-10-20T13:00:00Z', '2026-10-20T13:00:00Z']]) assert.throws(() => free(answer(ok), start, end), refused('window_order'), start);
  assert.throws(() => free(answer(ok), '2026-10-20T13:00:00'), refused('time_invalid'));
  assert.throws(() => free(answer(ok), undefined, '2026-10-20T24:00:00Z'), refused('time_invalid'));
  for (const minMinutes of [0, 1441, 1.5]) assert.throws(() => free(answer(ok), undefined, undefined, minMinutes), refused('input_invalid'), String(minMinutes));
  // At most 2,000 busy blocks across every calendar; two calendars of 1,000 pass.
  const start = Date.UTC(2026, 9, 20, 13), blocks = count => Array.from({length: count}, (_, index) => busy(iso(start + index * 10_000), iso(start + index * 10_000 + 5000)));
  assert.deepEqual(free(answer({a: {busy: blocks(1000)}, b: {busy: blocks(1000)}}), undefined, undefined, 1).free, [{start: '2026-10-20T15:46:35Z', end: '2026-10-20T21:00:00Z'}]);
  assert.throws(() => free(answer({a: {busy: blocks(1000)}, b: {busy: blocks(1001)}})), refused('input_too_large'));
});

test('recurrence lines follow RFC 5545 section 3.3.10 and refuse DTSTART and DTEND lines, COUNT with UNTIL, and more than 10 lines', () => {
  const rrule = recurrence => run(RRULE, {recurrence});
  const pass = lines => assert.deepEqual(rrule(lines), {recurrence: lines}, lines.join(' | '));
  const fail = lines => assert.throws(() => rrule(lines), refused('time_invalid'), JSON.stringify(lines));
  pass(['RRULE:FREQ=WEEKLY;COUNT=3']);
  pass([]);
  pass(['RRULE:FREQ=WEEKLY;BYDAY=MO,WE,FR;UNTIL=20261231T235959Z', 'EXDATE;TZID=America/Toronto:20261027T090000,20261103T090000', 'RDATE;VALUE=DATE:20261225',
    'EXRULE:FREQ=MONTHLY;BYMONTHDAY=1', 'EXDATE:20261027T090000', 'RDATE;VALUE=DATE-TIME:20261224T170000Z']);
  pass(['RRULE:FREQ=MONTHLY;BYDAY=-1FR;INTERVAL=2;WKST=SU']);
  pass(['RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=2SU;BYHOUR=23;BYMINUTE=59;BYSECOND=59']);
  pass(['RRULE:FREQ=YEARLY;BYHOUR=00,09;BYMINUTE=0;BYSECOND=00']);
  pass(['RRULE:FREQ=YEARLY;BYWEEKNO=20,-1;BYDAY=MO']);
  pass(['RRULE:FREQ=YEARLY;BYYEARDAY=1,-366,100']);
  pass(['RRULE:FREQ=MONTHLY;BYDAY=MO,TU,WE,TH,FR;BYSETPOS=-1']);
  pass(['RRULE:FREQ=DAILY;UNTIL=20261231']);
  pass(['RRULE:FREQ=DAILY;UNTIL=20280229T120000']);
  pass(Array.from({length: 10}, (_, index) => `EXDATE:202610${10 + index}T130000Z`));
  fail(Array.from({length: 11}, (_, index) => `EXDATE:202610${10 + index}T130000Z`));
  fail(['RRULE:FREQ=DAILY', 'RRULE:FREQ=WEEKLY']);
  for (const line of ['DTSTART:20261020T090000Z', 'DTSTART;TZID=America/Toronto:20261020T090000', 'DTEND:20261020T100000Z', 'RRULE:FREQ=DAILY;COUNT=3;UNTIL=20261231',
    'RRULE:UNTIL=20261231;FREQ=DAILY;COUNT=3', 'RRULE:COUNT=3', 'RRULE:FREQ=FORTNIGHTLY', 'RRULE:FREQ=DAILY;FREQ=WEEKLY', 'RRULE:FREQ=DAILY;COUNT=1;COUNT=2', 'RRULE:FREQ=DAILY;FOO=1',
    'rrule:FREQ=DAILY', 'RRULE:freq=daily', 'RRULE:FREQ=DAILY;', 'RRULE:FREQ=DAILY;;COUNT=1', 'RRULE:FREQ', 'RRULE:', 'RRULE', 'RRULE;X-NAME=1:FREQ=DAILY',
    'RRULE:FREQ=DAILY;BYHOUR=24', 'RRULE:FREQ=DAILY;BYMINUTE=60', 'RRULE:FREQ=DAILY;BYSECOND=60', 'RRULE:FREQ=DAILY;BYHOUR=', 'RRULE:FREQ=DAILY;BYHOUR=1,,2', 'RRULE:FREQ=DAILY;BYHOUR=123',
    'RRULE:FREQ=DAILY;BYHOUR=-1', 'RRULE:FREQ=DAILY;UNTIL=20261020T240000Z', 'RRULE:FREQ=DAILY;UNTIL=20261020T106000Z', 'RRULE:FREQ=DAILY;UNTIL=20261020T100060Z',
    'RRULE:FREQ=DAILY;UNTIL=20260230', 'RRULE:FREQ=DAILY;UNTIL=2026-10-20', 'RRULE:FREQ=DAILY;UNTIL=20261020T1000Z', 'RRULE:FREQ=WEEKLY;BYDAY=1MO', 'RRULE:FREQ=MONTHLY;BYDAY=0MO',
    'RRULE:FREQ=MONTHLY;BYDAY=54MO', 'RRULE:FREQ=MONTHLY;BYDAY=XX', 'RRULE:FREQ=MONTHLY;BYDAY=mo', 'RRULE:FREQ=YEARLY;BYWEEKNO=1;BYDAY=1MO', 'RRULE:FREQ=WEEKLY;BYMONTHDAY=1',
    'RRULE:FREQ=MONTHLY;BYMONTHDAY=32', 'RRULE:FREQ=MONTHLY;BYMONTHDAY=0', 'RRULE:FREQ=MONTHLY;BYYEARDAY=1', 'RRULE:FREQ=YEARLY;BYYEARDAY=367', 'RRULE:FREQ=MONTHLY;BYWEEKNO=1',
    'RRULE:FREQ=YEARLY;BYWEEKNO=54', 'RRULE:FREQ=YEARLY;BYMONTH=13', 'RRULE:FREQ=YEARLY;BYMONTH=0', 'RRULE:FREQ=DAILY;BYSETPOS=1', 'RRULE:FREQ=MONTHLY;BYDAY=MO;BYSETPOS=367',
    'RRULE:FREQ=DAILY;INTERVAL=0', 'RRULE:FREQ=DAILY;COUNT=0', 'RRULE:FREQ=DAILY;COUNT=-1', 'RRULE:FREQ=DAILY;WKST=XX', 'RRULE:FREQ=DAILY\r\nDTSTART:20261020T090000Z',
    'RRULE:FREQ=DAILY\n', 'RRULE:FREQ=DAILY;COUNT=3 ', ' RRULE:FREQ=DAILY', 'RRULE:FREQ=DAILY;BYDAY=MO​', 'EXDATE;TZID=America/Toronto:20261027T090000Z',
    'EXDATE;VALUE=DATE:20261027T090000', 'EXDATE;VALUE=DATE;TZID=America/Toronto:20261027', 'RDATE;VALUE=PERIOD:20261027T090000Z/PT1H', 'EXDATE;VALUE=PERIOD:20261027T090000Z/PT1H',
    'EXDATE;TZID=+05:30:20261027T090000', 'EXDATE;TZID="America/Toronto":20261027T090000', 'EXDATE;TZID=america/toronto:20261027T090000', 'EXDATE;VALUE=DATE;VALUE=DATE:20261027',
    'EXDATE;TZID=America/Toronto;TZID=UTC:20261027T090000', 'EXDATE:', 'EXDATE:20261027T090000Z,', 'EXDATE:20261027T250000Z', 'EXDATE:20261027T096000Z', 'EXDATE;FOO=BAR:20261027T090000Z',
    'EXDATE:2026102T090000Z', 'EXDATE;VALUE=TEXT:20261027', 'EXDATE;TZIDx:20261027T090000', 'EXDATE;VALUEDATE:20261027', 'EXDATE;=DATE:20261027', 'EXDATE;:20261027T090000Z']) {
    fail([line]);
  }
  assert.throws(() => rrule(['RRULE:FREQ=DAILY'.padEnd(1001, ';')]), refused('input_invalid'), 'a line is at most 1,000 characters');
});
