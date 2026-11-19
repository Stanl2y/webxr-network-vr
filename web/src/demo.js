// In-browser demo source: a small port of internal/capture/synth plus the
// sampling rules of internal/sampler, so the viewer works with no agent.
// Produces the exact MessagePack frame bytes the Go agent would send.
import { encodeFrame } from './frame.js';
import { encodeRecord, RECORD_SIZE, VERDICT_AGGREGATE } from './record.js';

const TICK_MS = 50;
const TARGET_PPS = 50_000;
const MAX_K = 32;
const HH_PPS = 200;
const HH_BURST = 10;
const DROP_AGG = 1000;

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function flowHash(src, dst, sport, dport, proto) {
  const key = [...src, ...dst, sport & 0xff, sport >> 8, dport & 0xff, dport >> 8, proto];
  let h = 2166136261;
  for (const c of key) h = Math.imul(h ^ c, 16777619) >>> 0;
  return h >>> 0;
}

function mix(h) {
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b) >>> 0;
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35) >>> 0;
  h ^= h >>> 16;
  return h >>> 0;
}

export class DemoSource {
  constructor({ pps = 60_000, flows = 1024, devs = 4, queues = 4, seed = 1 } = {}) {
    this.pps = pps;
    this.devs = devs;
    this.queues = queues;
    this.rng = mulberry32(seed);
    this.nowNs = 0;
    this.k = 1;
    this.offered = 0; // packets generated (forwarded + dropped)
    this.dropped = 0;
    this.depth = new Float64Array(devs * queues);
    this.cap = 256;
    this.service = (pps / (devs * queues)) * 2.0;
    this.flows = [];
    this.cdf = new Float64Array(flows);
    let acc = 0;
    for (let i = 0; i < flows; i++) {
      const r = this.rng;
      const src = [10, (r() * 4) | 0, (r() * 256) | 0, 1 + ((r() * 254) | 0)];
      const dst = [172, 16, (r() * 8) | 0, 1 + ((r() * 254) | 0)];
      const p = r();
      const proto = p < 0.7 ? 6 : p < 0.97 ? 17 : 1;
      const dport = proto === 6 ? [443, 80, 22, 5432][(r() * 4) | 0] : proto === 17 ? [53, 443, 4789][(r() * 3) | 0] : 0;
      const sport = proto === 1 ? 0 : 32768 + ((r() * 28000) | 0);
      const hash = flowHash(src, dst, sport, dport, proto);
      this.flows.push({
        srcIp: src.join('.'), dstIp: dst.join('.'), srcPort: sport, dstPort: dport, proto, flowHash: hash,
        dev: hash % devs, queue: (hash >>> 8) % queues, big: r() < 0.4, tokens: HH_BURST, lastNs: 0, pending: 0,
      });
      acc += 1 / Math.pow(i + 4, 1.15);
      this.cdf[i] = acc;
    }
    for (let i = 0; i < flows; i++) this.cdf[i] /= acc;
  }

  pickFlow() {
    const u = this.rng();
    let lo = 0;
    let hi = this.cdf.length - 1;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (this.cdf[mid] < u) lo = mid + 1;
      else hi = mid;
    }
    return this.flows[lo];
  }

  /** Advance 50 ms of virtual time and return one encoded frame. */
  nextFrame() {
    const dtNs = TICK_MS * 1e6;
    const burst = this.nowNs % 2e9 < 2.5e8;
    const n = Math.round(this.pps * (TICK_MS / 1000) * (burst ? 3 : 1));
    const drain = this.service * (TICK_MS / 1000);
    const k = this.k;
    const out = [];
    const drops = [];
    this.offered += n;
    for (let i = 0; i < n; i++) {
      const f = this.pickFlow();
      const ts = this.nowNs + Math.floor(((i + 1) * dtNs) / n);
      const qi = f.dev * this.queues + f.queue;
      this.depth[qi] = Math.max(0, this.depth[qi] - drain / n);
      const pktLen = f.big ? 1514 : 64 + ((this.rng() * 512) | 0);
      let verdict = 0;
      if (this.depth[qi] >= this.cap) verdict = 1;
      else if (this.rng() < 1e-4) verdict = 2;
      else this.depth[qi]++;
      const rec = { ...f, tsNs: ts, pktLen, verdict, weight: 1 };
      if (verdict) {
        this.dropped++;
        drops.push(rec);
        continue;
      }
      if (k > 1 && mix(f.flowHash) % k !== 0) continue;
      f.tokens = Math.min(HH_BURST, f.tokens + ((ts - f.lastNs) / 1e9) * HH_PPS);
      f.lastNs = ts;
      const owed = f.pending + k;
      if (f.tokens < 1) {
        f.pending = owed;
        continue;
      }
      f.tokens--;
      f.pending = Math.max(0, owed - 65535);
      rec.weight = Math.min(owed, 65535);
      out.push(rec);
    }
    if (drops.length > DROP_AGG) {
      const agg = new Map();
      for (const d of drops) {
        const key = `${d.dev}/${d.queue}/${d.verdict}`;
        const a = agg.get(key) ?? { tsNs: d.tsNs, dev: d.dev, queue: d.queue, verdict: VERDICT_AGGREGATE | d.verdict, weight: 0, pktLen: d.pktLen };
        a.weight++;
        agg.set(key, a);
      }
      out.push(...agg.values());
    } else {
      out.push(...drops);
    }
    this.k = Math.min(MAX_K, Math.max(1, Math.ceil((n / (TICK_MS / 1000)) / TARGET_PPS)));
    const bytes = new Uint8Array(out.length * RECORD_SIZE);
    const view = new DataView(bytes.buffer);
    out.forEach((r, i) => encodeRecord(view, i * RECORD_SIZE, r));
    const frame = encodeFrame({ tickMs: TICK_MS, baseTsNs: BigInt(this.nowNs), records: bytes });
    this.nowNs += dtNs;
    return frame;
  }

  queueDepths() {
    return Array.from(this.depth, (d) => d / this.cap);
  }
}
