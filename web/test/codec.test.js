import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { decodeRecords, encodeRecord, RECORD_SIZE } from '../src/record.js';
import { decodeFrame, encodeFrame } from '../src/frame.js';
import { DemoSource, flowHash } from '../src/demo.js';

const golden = JSON.parse(readFileSync(new URL('../../testdata/record_golden.json', import.meta.url)));
const hexBytes = (h) => Uint8Array.from(h.match(/../g).map((b) => parseInt(b, 16)));

for (const g of golden) {
  test(`golden decode: ${g.name}`, () => {
    const [r] = decodeRecords(hexBytes(g.hex));
    const w = g.record;
    assert.equal(r.tsNs, BigInt(w.ts_ns));
    assert.equal(r.flowHash, w.flow_hash);
    assert.equal(r.srcIp, w.src_ip);
    assert.equal(r.dstIp, w.dst_ip);
    assert.equal(r.srcPort, w.src_port);
    assert.equal(r.dstPort, w.dst_port);
    assert.equal(r.pktLen, w.pkt_len);
    assert.equal(r.proto, w.proto);
    assert.equal(r.dev, w.dev);
    assert.equal(r.queue, w.queue);
    assert.equal(r.verdict, w.verdict);
    assert.equal(r.weight, w.sample_weight);
  });

  test(`golden encode: ${g.name}`, () => {
    const w = g.record;
    const buf = new Uint8Array(RECORD_SIZE);
    encodeRecord(new DataView(buf.buffer), 0, {
      tsNs: w.ts_ns, flowHash: w.flow_hash, srcIp: w.src_ip, dstIp: w.dst_ip,
      srcPort: w.src_port, dstPort: w.dst_port, pktLen: w.pkt_len, proto: w.proto,
      dev: w.dev, queue: w.queue, verdict: w.verdict, weight: w.sample_weight,
    });
    assert.equal(Buffer.from(buf).toString('hex'), g.hex);
  });
}

test('flowHash matches Go record.FlowHash', () => {
  // Same pinned value as internal/record TestFlowHashKnownValue.
  assert.equal(flowHash([0, 0, 0, 0], [0, 0, 0, 0], 0, 0, 0), 0xda0f62ef);
});

test('frame round trip', () => {
  const recs = hexBytes(golden.map((g) => g.hex).join(''));
  const f = decodeFrame(encodeFrame({ baseTsNs: 1000n, droppedTicks: 2, records: recs }));
  assert.equal(f.count, golden.length);
  assert.equal(f.droppedTicks, 2);
  assert.equal(f.baseTsNs, 1000n);
  assert.ok(f.records[1].aggregated);
});

test('demo source emits valid frames with k-weighted records', () => {
  const src = new DemoSource({ pps: 120_000, seed: 3 });
  let drops = 0;
  let weight = 0;
  for (let i = 0; i < 60; i++) {
    const f = decodeFrame(src.nextFrame());
    for (const r of f.records) {
      if (r.dropped) drops += r.weight;
      else weight += r.weight;
    }
  }
  // Drops are never sampled, so their weight is exact.
  assert.equal(drops, src.dropped);
  assert.ok(drops > 0, 'expected some drops');
  // Forwarded weight is an estimate of the forwarded packet count.
  const forwarded = src.offered - src.dropped;
  assert.ok(Math.abs(weight - forwarded) / forwarded < 0.35, `weight ${weight} vs forwarded ${forwarded}`);
});
