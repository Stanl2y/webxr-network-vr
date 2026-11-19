import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import { VRButton } from 'three/examples/jsm/webxr/VRButton.js';
import { decodeFrame } from './frame.js';
import { DemoSource } from './demo.js';
import { NetworkScene } from './viz.js';

const params = new URLSearchParams(location.search);
const hud = document.getElementById('hud');

// ---- renderer / scene -------------------------------------------------------
const renderer = new THREE.WebGLRenderer({ antialias: true, preserveDrawingBuffer: params.has('capture') });
renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
renderer.setSize(innerWidth, innerHeight);
renderer.xr.enabled = true;
document.body.appendChild(renderer.domElement);
document.body.appendChild(VRButton.createButton(renderer));

const scene = new THREE.Scene();
scene.background = new THREE.Color(0x050a14);
scene.fog = new THREE.Fog(0x050a14, 6, 14);
scene.add(new THREE.HemisphereLight(0x8fb8ff, 0x0b0f1a, 1.2));
const sun = new THREE.DirectionalLight(0xffffff, 1.4);
sun.position.set(2, 5, 2);
scene.add(sun);
const grid = new THREE.GridHelper(12, 24, 0x1d3557, 0x0f1d33);
scene.add(grid);

// Desktop camera; in VR the headset pose replaces it (user stands at origin).
const camera = new THREE.PerspectiveCamera(60, innerWidth / innerHeight, 0.05, 50);
camera.position.set(0, 1.9, 1.4);
const controls = new OrbitControls(camera, renderer.domElement);
controls.target.set(0, 1.25, -2.6);
controls.update();

const net = new NetworkScene(scene);

addEventListener('resize', () => {
  camera.aspect = innerWidth / innerHeight;
  camera.updateProjectionMatrix();
  renderer.setSize(innerWidth, innerHeight);
});

// ---- data sources -----------------------------------------------------------
const stats = { frames: 0, records: 0, weight: 0, drops: 0, droppedTicks: 0, maxW: 1, since: performance.now() };
let sourceLabel = 'connecting...';
let shown = { fps: 0, rps: 0, pps: 0, dps: 0, k: 1, late: 0 };

function onFrame(buf) {
  const f = decodeFrame(buf);
  stats.frames++;
  stats.records += f.count;
  stats.droppedTicks += f.droppedTicks;
  let maxW = 1;
  for (const r of f.records) {
    if (r.dropped) stats.drops += r.weight;
    else {
      stats.weight += r.weight;
      if (r.weight > maxW) maxW = r.weight;
    }
  }
  stats.maxW = Math.max(stats.maxW, maxW);
  net.ingest(f);
}

let demoTimer = null;
function startDemo(reason) {
  if (demoTimer) return;
  const pps = Number(params.get('pps') ?? 60000);
  const demo = new DemoSource({ pps, seed: Number(params.get('seed') ?? 1) });
  sourceLabel = `demo (in-browser synthetic, ${pps.toLocaleString()} pps)${reason ? ' - ' + reason : ''}`;
  demoTimer = setInterval(() => onFrame(demo.nextFrame()), 50);
}

function wsURL() {
  if (params.get('ws')) return params.get('ws');
  return `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`;
}

if (params.has('demo')) {
  startDemo('');
} else {
  const url = wsURL();
  let opened = false;
  const ws = new WebSocket(url);
  ws.binaryType = 'arraybuffer';
  ws.onopen = () => {
    opened = true;
    sourceLabel = `agent ${url}`;
  };
  ws.onmessage = (e) => onFrame(e.data);
  ws.onclose = () => startDemo(opened ? 'agent disconnected' : 'no agent at ' + url);
  setTimeout(() => !opened && ws.close(), 1500);
}

function updateHud(now) {
  const dt = (now - stats.since) / 1000;
  if (dt >= 1) {
    shown = {
      fps: stats.frames / dt,
      rps: stats.records / dt,
      pps: stats.weight / dt,
      dps: stats.drops / dt,
      k: stats.maxW,
      late: stats.droppedTicks,
    };
    Object.assign(stats, { frames: 0, records: 0, weight: 0, drops: 0, droppedTicks: 0, maxW: 1, since: now });
  }
  const n = (x) => Math.round(x).toLocaleString();
  hud.innerHTML =
    `<b>webxr-network-vr</b><br>source: ${sourceLabel}<br>` +
    `frames/s ${shown.fps.toFixed(1)} &middot; records/s ${n(shown.rps)}<br>` +
    `est. packets/s (&Sigma;weight) ${n(shown.pps)} &middot; max weight ${shown.k}<br>` +
    `<span class="drop">drops/s ${n(shown.dps)}</span> &middot; late ticks ${shown.late}<br>` +
    `<span class="tcp">&#9679; TCP</span> <span class="udp">&#9679; UDP</span> <span class="icmp">&#9679; ICMP</span> <span class="drop">&#9679; drop</span>`;
}

// ---- loop ---------------------------------------------------------------------
const clock = new THREE.Clock();
renderer.setAnimationLoop((now) => {
  const dt = Math.min(clock.getDelta(), 0.1);
  net.update(dt);
  if (!renderer.xr.isPresenting) controls.update();
  updateHud(now);
  renderer.render(scene, camera);
});
