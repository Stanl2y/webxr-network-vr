// MessagePack frame decoding: {tick_ms, base_ts_ns, count, dropped_ticks, records}.
import { decode, encode } from '@msgpack/msgpack';
import { decodeRecords, RECORD_SIZE } from './record.js';

export function decodeFrame(buf) {
  const m = decode(buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf, { useBigInt64: true });
  const records = m.records instanceof Uint8Array ? m.records : new Uint8Array(0);
  const count = Number(m.count ?? 0);
  if (records.byteLength !== count * RECORD_SIZE) {
    throw new Error(`frame count ${count} does not match ${records.byteLength} record bytes`);
  }
  return {
    tickMs: Number(m.tick_ms ?? 50),
    baseTsNs: BigInt(m.base_ts_ns ?? 0),
    count,
    droppedTicks: Number(m.dropped_ticks ?? 0),
    records: decodeRecords(records),
  };
}

/** Encode a frame the same way the Go agent does (used by the demo source and tests). */
export function encodeFrame({ tickMs = 50, baseTsNs = 0n, droppedTicks = 0, records }) {
  return encode(
    {
      tick_ms: tickMs,
      base_ts_ns: BigInt(baseTsNs),
      count: records.byteLength / RECORD_SIZE,
      dropped_ticks: droppedTicks,
      records,
    },
    { useBigInt64: true },
  );
}
