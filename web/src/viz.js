// Three.js scene: three stacked layers (L1 ports, L2 queues, L3 routes).
// Each record becomes one instanced "packet" that rises from its device port
// (L1) into its output queue (L2) and on to a destination prefix (L3).
// Dropped packets stop at the queue and burst into red particles.
import * as THREE from 'three';

const MAX_PACKETS = 12000;
const MAX_SPARKS = 6000;
const PACKET_LIFE = 1.4; // seconds
const SPARK_LIFE = 0.7;
const L3_NODES = 8;

const Y = { L1: 0.5, L2: 1.3, L3: 2.1 };
const Z = { L1: -1.6, L2: -2.6, L3: -3.6 };

const PROTO_COLOR = { 6: new THREE.Color(0x35d0ff), 17: new THREE.Color(0xffa733), 1: new THREE.Color(0xc58cff) };
const OTHER_COLOR = new THREE.Color(0x9aa4b2);
const DROP_COLOR = new THREE.Color(0xff3344);

function label(text, { size = 64, color = '#e8f1ff', bg = 'rgba(8,16,32,0.65)' } = {}) {
  const c = document.createElement('canvas');
  const ctx = c.getContext('2d');
  ctx.font = `600 ${size}px system-ui, sans-serif`;
  const w = Math.ceil(ctx.measureText(text).width) + size;
  c.width = w;
  c.height = size * 1.6;
  ctx.font = `600 ${size}px system-ui, sans-serif`;
  ctx.fillStyle = bg;
  ctx.fillRect(0, 0, c.width, c.height);
  ctx.fillStyle = color;
  ctx.textBaseline = 'middle';
  ctx.fillText(text, size / 2, c.height / 2);
  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, depthWrite: false }));
  const h = 0.09 * (size / 64);
  s.scale.set((h * c.width) / c.height, h, 1);
  return s;
}

export class NetworkScene {
  constructor(scene, { devs = 4, queues = 4 } = {}) {
    this.devs = devs;
    this.queues = queues;
    this.root = new THREE.Group();
    scene.add(this.root);
    this.time = 0;
    this.buildLayers();
    this.buildQueues();
    this.buildL3();
    this.buildPackets();
    this.buildSparks();
    this.pressure = new Float32Array(devs * queues);
    this.flash = new Float32Array(devs * queues);
    this.l3Labels = new Map();
  }

  devX(d) {
    return (d - (this.devs - 1) / 2) * 0.9;
  }

  queueX(d, q) {
    return this.devX(d) + (q - (this.queues - 1) / 2) * 0.16;
  }

  l3Pos(i) {
    const a = ((i + 0.5) / L3_NODES - 0.5) * Math.PI * 0.8;
    return new THREE.Vector3(Math.sin(a) * 2.2, Y.L3, Z.L3 + (1 - Math.cos(a)) * 1.2);
  }

  buildLayers() {
    const mk = (y, z, color, w, d) => {
      const m = new THREE.Mesh(
        new THREE.PlaneGeometry(w, d),
        new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.08, side: THREE.DoubleSide, depthWrite: false }),
      );
      m.rotation.x = -Math.PI / 2;
      m.position.set(0, y, z);
      this.root.add(m);
      const edges = new THREE.LineSegments(new THREE.EdgesGeometry(m.geometry), new THREE.LineBasicMaterial({ color, transparent: true, opacity: 0.5 }));
      edges.rotation.copy(m.rotation);
      edges.position.copy(m.position);
      this.root.add(edges);
    };
    mk(Y.L1, Z.L1, 0x35d0ff, 4.2, 0.8);
    mk(Y.L2, Z.L2, 0x66ff99, 4.2, 0.8);
    mk(Y.L3, Z.L3 + 0.5, 0xffd166, 5.0, 1.8);
    const add = (s, x, y, z) => {
      s.position.set(x, y, z);
      this.root.add(s);
    };
    add(label('L1  PHY / ports', { color: '#7fe3ff' }), -2.6, Y.L1 + 0.12, Z.L1);
    add(label('L2  Ethernet / egress queues', { color: '#8dffb4' }), -2.9, Y.L2 + 0.12, Z.L2);
    add(label('L3  IPv4 / destination prefixes', { color: '#ffe08a' }), -3.1, Y.L3 + 0.12, Z.L3);

    const portGeo = new THREE.BoxGeometry(0.5, 0.06, 0.25);
    for (let d = 0; d < this.devs; d++) {
      const p = new THREE.Mesh(portGeo, new THREE.MeshStandardMaterial({ color: 0x1c4a66, emissive: 0x0a2233 }));
      p.position.set(this.devX(d), Y.L1, Z.L1);
      this.root.add(p);
      add(label(`eth${d}`, { size: 44 }), this.devX(d), Y.L1 - 0.1, Z.L1 + 0.2);
    }
  }

  buildQueues() {
    this.queueBars = [];
    const geo = new THREE.BoxGeometry(0.1, 1, 0.1);
    geo.translate(0, 0.5, 0); // grow upward from the L2 plane
    for (let d = 0; d < this.devs; d++) {
      for (let q = 0; q < this.queues; q++) {
        const mat = new THREE.MeshStandardMaterial({ color: 0x2bd47a, emissive: 0x000000, transparent: true, opacity: 0.85 });
        const bar = new THREE.Mesh(geo, mat);
        bar.position.set(this.queueX(d, q), Y.L2, Z.L2);
        bar.scale.y = 0.02;
        this.root.add(bar);
        const frame = new THREE.LineSegments(
          new THREE.EdgesGeometry(new THREE.BoxGeometry(0.11, 0.55, 0.11)),
          new THREE.LineBasicMaterial({ color: 0x3a6b52, transparent: true, opacity: 0.6 }),
        );
        frame.position.set(this.queueX(d, q), Y.L2 + 0.275, Z.L2);
        this.root.add(frame);
        this.queueBars.push(bar);
      }
    }
  }

  buildL3() {
    this.l3 = [];
    const geo = new THREE.IcosahedronGeometry(0.09, 1);
    for (let i = 0; i < L3_NODES; i++) {
      const m = new THREE.Mesh(geo, new THREE.MeshStandardMaterial({ color: 0xffd166, emissive: 0x332200, flatShading: true }));
      m.position.copy(this.l3Pos(i));
      this.root.add(m);
      const s = label(`172.16.${i}.0/24`, { size: 40, color: '#ffe08a' });
      s.position.copy(m.position).add(new THREE.Vector3(0, 0.17, 0));
      this.root.add(s);
      this.l3.push(m);
    }
  }

  buildPackets() {
    const geo = new THREE.SphereGeometry(1, 8, 6);
    const mat = new THREE.MeshBasicMaterial({ toneMapped: false });
    this.packets = new THREE.InstancedMesh(geo, mat, MAX_PACKETS);
    this.packets.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    this.packets.frustumCulled = false;
    this.pk = {
      born: new Float32Array(MAX_PACKETS).fill(-1e9),
      a: new Float32Array(MAX_PACKETS * 3),
      b: new Float32Array(MAX_PACKETS * 3),
      c: new Float32Array(MAX_PACKETS * 3),
      size: new Float32Array(MAX_PACKETS),
      drop: new Uint8Array(MAX_PACKETS),
      qi: new Uint16Array(MAX_PACKETS),
      next: 0,
    };
    const col = new THREE.Color();
    for (let i = 0; i < MAX_PACKETS; i++) this.packets.setColorAt(i, col.set(0));
    this.root.add(this.packets);
  }

  buildSparks() {
    const geo = new THREE.TetrahedronGeometry(1);
    const mat = new THREE.MeshBasicMaterial({ color: DROP_COLOR, toneMapped: false });
    this.sparks = new THREE.InstancedMesh(geo, mat, MAX_SPARKS);
    this.sparks.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    this.sparks.frustumCulled = false;
    this.sp = {
      born: new Float32Array(MAX_SPARKS).fill(-1e9),
      p: new Float32Array(MAX_SPARKS * 3),
      v: new Float32Array(MAX_SPARKS * 3),
      next: 0,
    };
    this.root.add(this.sparks);
  }

  burst(x, y, z, n) {
    const sp = this.sp;
    for (let j = 0; j < n; j++) {
      const i = sp.next;
      sp.next = (sp.next + 1) % MAX_SPARKS;
      sp.born[i] = this.time;
      sp.p.set([x, y, z], i * 3);
      const th = Math.random() * Math.PI * 2;
      const up = Math.random() * 0.9 + 0.2;
      const r = Math.random() * 0.8 + 0.4;
      sp.v.set([Math.cos(th) * r, up, Math.sin(th) * r], i * 3);
    }
  }

  /** Feed one decoded frame (see frame.js). */
  ingest(frame) {
    const pk = this.pk;
    const col = new THREE.Color();
    const tickS = frame.tickMs / 1000;
    // A packet lives PACKET_LIFE seconds; never spawn more per tick than the
    // instance pool can hold for that long. Extra records still drive the
    // queue bars; drawn packets are scaled up by the stride to compensate.
    const budget = Math.floor(MAX_PACKETS / (PACKET_LIFE / tickS));
    let nDrop = 0;
    for (const r of frame.records) if (r.dropped) nDrop++;
    const fwdStride = Math.max(1, Math.ceil((frame.records.length - nDrop) / (budget * 0.6)));
    const dropStride = Math.max(1, Math.ceil(nDrop / (budget * 0.4)));
    let seenFwd = 0;
    let seenDrop = 0;
    for (let ri = 0; ri < frame.records.length; ri++) {
      const r = frame.records[ri];
      const d = r.dev % this.devs;
      const q = r.queue % this.queues;
      const qi = d * this.queues + q;
      const w = r.weight || 1;
      if (r.dropped) {
        this.flash[qi] = 1;
        this.pressure[qi] = Math.min(1.2, this.pressure[qi] + 0.002 * w + 0.02);
      } else {
        this.pressure[qi] += 0.00025 * w;
      }
      const stride = r.dropped ? dropStride : fwdStride;
      if ((r.dropped ? seenDrop++ : seenFwd++) % stride !== 0) continue;
      const i = pk.next;
      pk.next = (pk.next + 1) % MAX_PACKETS;
      // Stagger spawns across the tick so motion is continuous at 20 Hz.
      pk.born[i] = this.time + Math.random() * tickS;
      const node = this.l3Pos(r.dstNet % L3_NODES);
      pk.a.set([this.devX(d) + (Math.random() - 0.5) * 0.4, Y.L1 + 0.04, Z.L1 + (Math.random() - 0.5) * 0.15], i * 3);
      pk.b.set([this.queueX(d, q), Y.L2 + 0.02, Z.L2], i * 3);
      pk.c.set([node.x, node.y, node.z], i * 3);
      pk.drop[i] = r.dropped ? 1 : 0;
      pk.qi[i] = qi;
      const drawnW = w * stride;
      pk.size[i] = 0.012 * (1 + Math.log2(drawnW) * 0.3) * (r.aggregated ? 2.5 : 1);
      this.packets.setColorAt(i, r.dropped ? DROP_COLOR : col.copy(PROTO_COLOR[r.proto] ?? OTHER_COLOR));
      if (r.dropped) pk.drop[i] = r.aggregated ? 2 : 1;
    }
    if (this.packets.instanceColor) this.packets.instanceColor.needsUpdate = true;
  }

  update(dt) {
    this.time += dt;
    const t = this.time;
    const m = new THREE.Matrix4();
    const p = new THREE.Vector3();
    const s = new THREE.Vector3();
    const q = new THREE.Quaternion();
    const pk = this.pk;
    for (let i = 0; i < MAX_PACKETS; i++) {
      const age = (t - pk.born[i]) / PACKET_LIFE;
      let k = 0;
      if (age >= 0 && age < 1) {
        const o = i * 3;
        if (age < 0.5) {
          const u = age / 0.5;
          p.set(pk.a[o] + (pk.b[o] - pk.a[o]) * u, pk.a[o + 1] + (pk.b[o + 1] - pk.a[o + 1]) * u, pk.a[o + 2] + (pk.b[o + 2] - pk.a[o + 2]) * u);
          k = pk.size[i];
        } else if (!pk.drop[i]) {
          const u = (age - 0.5) / 0.5;
          const arc = Math.sin(u * Math.PI) * 0.25;
          p.set(pk.b[o] + (pk.c[o] - pk.b[o]) * u, pk.b[o + 1] + (pk.c[o + 1] - pk.b[o + 1]) * u + arc, pk.b[o + 2] + (pk.c[o + 2] - pk.b[o + 2]) * u);
          k = pk.size[i];
        } else if (pk.drop[i] !== 3) {
          // reached the queue and was dropped: explode once
          this.burst(pk.b[o], pk.b[o + 1] + 0.05, pk.b[o + 2], pk.drop[i] === 2 ? 16 : 3);
          pk.drop[i] = 3;
        }
      }
      m.compose(p, q, s.setScalar(k));
      this.packets.setMatrixAt(i, m);
    }
    this.packets.instanceMatrix.needsUpdate = true;

    const sp = this.sp;
    for (let i = 0; i < MAX_SPARKS; i++) {
      const age = t - sp.born[i];
      let k = 0;
      if (age >= 0 && age < SPARK_LIFE) {
        const o = i * 3;
        p.set(sp.p[o] + sp.v[o] * age * 0.5, sp.p[o + 1] + sp.v[o + 1] * age * 0.5 - 0.6 * age * age, sp.p[o + 2] + sp.v[o + 2] * age * 0.5);
        k = 0.012 * (1 - age / SPARK_LIFE);
      }
      m.compose(p, q, s.setScalar(k));
      this.sparks.setMatrixAt(i, m);
    }
    this.sparks.instanceMatrix.needsUpdate = true;

    const decay = Math.exp(-dt * 1.5);
    for (let i = 0; i < this.queueBars.length; i++) {
      this.pressure[i] *= decay;
      this.flash[i] *= Math.exp(-dt * 4);
      const bar = this.queueBars[i];
      const level = Math.min(1, this.pressure[i]);
      bar.scale.y = 0.02 + level * 0.53;
      bar.material.color.setHSL(0.36 * (1 - level), 0.85, 0.5);
      bar.material.emissive.setRGB(this.flash[i], 0, 0);
    }
    for (let i = 0; i < this.l3.length; i++) this.l3[i].rotation.y += dt * 0.6;
  }
}
