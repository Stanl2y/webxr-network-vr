// 32-byte packet record codec. Must match internal/record/record.go.
//
//  off size field          off size field
//    0    8 ts_ns           24    2 pkt_len
//    8    4 flow_hash       26    1 proto
//   12    4 src_ip          27    1 dev
//   16    4 dst_ip          28    1 queue
//   20    2 src_port        29    1 verdict (bit7 aggregate, bits0-6 reason)
//   22    2 dst_port        30    2 sample_weight
// All multi-byte integers little-endian; IPs are raw network-order bytes.

export const RECORD_SIZE = 32;
export const VERDICT_AGGREGATE = 0x80;
export const REASON_MASK = 0x7f;
export const REASONS = ['forwarded', 'queue_full', 'policy', 'no_route'];

function ip(view, off) {
  return `${view.getUint8(off)}.${view.getUint8(off + 1)}.${view.getUint8(off + 2)}.${view.getUint8(off + 3)}`;
}

/** Decode the record starting at byte `off` of a DataView. */
export function decodeRecord(view, off = 0) {
  const verdict = view.getUint8(off + 29);
  return {
    tsNs: view.getBigUint64(off, true),
    flowHash: view.getUint32(off + 8, true),
    srcIp: ip(view, off + 12),
    dstIp: ip(view, off + 16),
    dstNet: view.getUint8(off + 18), // third octet of dst, used for L3 grouping
    srcPort: view.getUint16(off + 20, true),
    dstPort: view.getUint16(off + 22, true),
    pktLen: view.getUint16(off + 24, true),
    proto: view.getUint8(off + 26),
    dev: view.getUint8(off + 27),
    queue: view.getUint8(off + 28),
    verdict,
    reason: verdict & REASON_MASK,
    dropped: (verdict & REASON_MASK) !== 0,
    aggregated: (verdict & VERDICT_AGGREGATE) !== 0,
    weight: view.getUint16(off + 30, true),
  };
}

/** Decode a concatenation of records (Uint8Array). */
export function decodeRecords(bytes) {
  if (bytes.byteLength % RECORD_SIZE !== 0) {
    throw new Error(`records length ${bytes.byteLength} is not a multiple of 32`);
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const out = new Array(bytes.byteLength / RECORD_SIZE);
  for (let i = 0; i < out.length; i++) out[i] = decodeRecord(view, i * RECORD_SIZE);
  return out;
}

/** Encode a record object into `view` at `off` (used by the in-browser demo source). */
export function encodeRecord(view, off, r) {
  view.setBigUint64(off, BigInt(r.tsNs ?? 0), true);
  view.setUint32(off + 8, r.flowHash >>> 0, true);
  const put = (o, s) => s.split('.').forEach((x, i) => view.setUint8(o + i, Number(x)));
  put(off + 12, r.srcIp ?? '0.0.0.0');
  put(off + 16, r.dstIp ?? '0.0.0.0');
  view.setUint16(off + 20, r.srcPort ?? 0, true);
  view.setUint16(off + 22, r.dstPort ?? 0, true);
  view.setUint16(off + 24, r.pktLen ?? 0, true);
  view.setUint8(off + 26, r.proto ?? 0);
  view.setUint8(off + 27, r.dev ?? 0);
  view.setUint8(off + 28, r.queue ?? 0);
  view.setUint8(off + 29, r.verdict ?? 0);
  view.setUint16(off + 30, r.weight ?? 1, true);
}
