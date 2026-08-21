// ---------- hero3d: particles converging into the Kavach shield ----------
// A signature landing moment — scattered "telemetry dust" assembles into the
// shield crest, flanked by two slow sentinel rings. Runs independently of
// the boot sequence in script.js so a WebGL/CDN failure can never block the
// dashboard from loading.
(function () {
  const canvas = document.getElementById('hero-canvas');
  const section = document.getElementById('hero3d');
  const captionEl = document.getElementById('hero-caption');
  if (!canvas || !section || typeof THREE === 'undefined') return;

  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const isCoarse = window.matchMedia('(pointer: coarse)').matches;
  const isSmall = window.innerWidth < 700;

  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: !isCoarse });
  } catch (e) {
    return; // no WebGL — the hero still reads fine as plain text over the panel gradient
  }
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, isCoarse ? 1.5 : 2));

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(42, 1, 0.1, 100);
  camera.position.set(0, 0, 30);

  const GOLD = new THREE.Color('#e8c96a');
  const GOLD_DIM = new THREE.Color('#c9a227');
  const TEAL = new THREE.Color('#3fa796');

  // ---------- soft disc sprite for glowing particles ----------
  function makeDiscTexture() {
    const s = 64;
    const c = document.createElement('canvas');
    c.width = c.height = s;
    const ctx = c.getContext('2d');
    const g = ctx.createRadialGradient(s / 2, s / 2, 0, s / 2, s / 2, s / 2);
    g.addColorStop(0, 'rgba(255,255,255,1)');
    g.addColorStop(0.45, 'rgba(255,255,255,0.85)');
    g.addColorStop(1, 'rgba(255,255,255,0)');
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, s, s);
    return new THREE.CanvasTexture(c);
  }
  const discTex = makeDiscTexture();

  // ---------- shield silhouette (the Kavach crest, in local units) ----------
  const shieldShape = new THREE.Shape();
  shieldShape.moveTo(-9.5, 8.5);
  shieldShape.lineTo(9.5, 8.5);
  shieldShape.lineTo(9.5, -0.5);
  shieldShape.bezierCurveTo(9.5, -7.5, 5.6, -11.4, 0, -14.5);
  shieldShape.bezierCurveTo(-5.6, -11.4, -9.5, -7.5, -9.5, -0.5);
  shieldShape.lineTo(-9.5, 8.5);

  const shieldGeom = new THREE.ShapeGeometry(shieldShape, 4);
  const posAttr = shieldGeom.attributes.position;
  const idxAttr = shieldGeom.index;

  function triArea(ax, ay, bx, by, cx, cy) {
    return Math.abs((bx - ax) * (cy - ay) - (cx - ax) * (by - ay)) / 2;
  }

  const tris = [];
  let totalArea = 0;
  for (let i = 0; i < idxAttr.count; i += 3) {
    const ia = idxAttr.getX(i), ib = idxAttr.getX(i + 1), ic = idxAttr.getX(i + 2);
    const ax = posAttr.getX(ia), ay = posAttr.getY(ia);
    const bx = posAttr.getX(ib), by = posAttr.getY(ib);
    const cx = posAttr.getX(ic), cy = posAttr.getY(ic);
    const area = triArea(ax, ay, bx, by, cx, cy);
    totalArea += area;
    tris.push({ ax, ay, bx, by, cx, cy, area });
  }

  function samplePointInShield() {
    let r = Math.random() * totalArea;
    let tri = tris[tris.length - 1];
    for (let i = 0; i < tris.length; i++) {
      if (r < tris[i].area) { tri = tris[i]; break; }
      r -= tris[i].area;
    }
    let u = Math.random(), v = Math.random();
    if (u + v > 1) { u = 1 - u; v = 1 - v; }
    return [
      tri.ax + u * (tri.bx - tri.ax) + v * (tri.cx - tri.ax),
      tri.ay + u * (tri.by - tri.ay) + v * (tri.cy - tri.ay),
    ];
  }

  const outlinePts = shieldShape.getPoints(140);

  // ---------- particle buffers ----------
  const FILL_COUNT = isSmall || isCoarse ? 900 : 2200;
  const OUTLINE_COUNT = isSmall || isCoarse ? 220 : 420;
  const TOTAL = FILL_COUNT + OUTLINE_COUNT;

  const startPos = new Float32Array(TOTAL * 3);
  const targetPos = new Float32Array(TOTAL * 3);
  const colors = new Float32Array(TOTAL * 3);
  const sizes = new Float32Array(TOTAL);
  const delays = new Float32Array(TOTAL);
  const durations = new Float32Array(TOTAL);

  function randomScatter() {
    const r = 22 + Math.random() * 20;
    const theta = Math.random() * Math.PI * 2;
    const phi = Math.acos(2 * Math.random() - 1);
    return [
      r * Math.sin(phi) * Math.cos(theta),
      r * Math.sin(phi) * Math.sin(theta),
      r * Math.cos(phi),
    ];
  }

  for (let i = 0; i < TOTAL; i++) {
    const isOutline = i < OUTLINE_COUNT;
    let tx, ty, tz;
    if (isOutline) {
      const p = outlinePts[Math.floor((i / OUTLINE_COUNT) * outlinePts.length) % outlinePts.length];
      tx = p.x + (Math.random() - 0.5) * 0.25;
      ty = p.y + (Math.random() - 0.5) * 0.25;
      tz = (Math.random() - 0.5) * 0.8;
    } else {
      const [sx, sy] = samplePointInShield();
      tx = sx; ty = sy;
      tz = (Math.random() - 0.5) * 1.4;
    }
    targetPos[i * 3] = tx;
    targetPos[i * 3 + 1] = ty;
    targetPos[i * 3 + 2] = tz;

    const [rx, ry, rz] = randomScatter();
    startPos[i * 3] = rx;
    startPos[i * 3 + 1] = ry;
    startPos[i * 3 + 2] = rz;

    let col;
    if (isOutline) {
      col = Math.random() < 0.7 ? GOLD : GOLD_DIM;
    } else {
      const w = Math.random();
      col = w < 0.55 ? TEAL.clone().lerp(GOLD_DIM, 0.15) : GOLD_DIM.clone().lerp(TEAL, 0.2);
    }
    colors[i * 3] = col.r; colors[i * 3 + 1] = col.g; colors[i * 3 + 2] = col.b;

    sizes[i] = isOutline ? (0.34 + Math.random() * 0.16) : (0.16 + Math.random() * 0.16);
    delays[i] = Math.random() * 0.85;
    durations[i] = 1.5 + Math.random() * 0.9;
  }

  const geometry = new THREE.BufferGeometry();
  geometry.setAttribute('position', new THREE.BufferAttribute(startPos.slice(), 3));
  geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

  const material = new THREE.PointsMaterial({
    size: 0.5,
    map: discTex,
    vertexColors: true,
    transparent: true,
    depthWrite: false,
    blending: THREE.AdditiveBlending,
    sizeAttenuation: true,
    opacity: 0.95,
  });

  const points = new THREE.Points(geometry, material);
  const group = new THREE.Group();
  group.add(points);
  scene.add(group);

  // ---------- sentinel rings (the "watching eye" sweep, in 3D) ----------
  function makeRing(radius, color, opacity, tiltX) {
    const geo = new THREE.TorusGeometry(radius, 0.045, 8, 128);
    const mat = new THREE.MeshBasicMaterial({
      color, transparent: true, opacity, blending: THREE.AdditiveBlending, depthWrite: false,
    });
    const mesh = new THREE.Mesh(geo, mat);
    mesh.rotation.x = tiltX;
    return mesh;
  }
  const ringOuter = makeRing(14.5, GOLD_DIM, 0.28, Math.PI / 2.35);
  const ringInner = makeRing(12, TEAL, 0.22, Math.PI / 2.7);
  group.add(ringOuter, ringInner);

  // ---------- faint geo shell for depth ----------
  const icoWire = new THREE.WireframeGeometry(new THREE.IcosahedronGeometry(17, 1));
  const icoLines = new THREE.LineSegments(
    icoWire,
    new THREE.LineBasicMaterial({ color: GOLD_DIM, transparent: true, opacity: 0.07 })
  );
  group.add(icoLines);

  // ---------- resize ----------
  function resize() {
    const w = section.clientWidth, h = section.clientHeight;
    if (!w || !h) return;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  resize();
  window.addEventListener('resize', resize);

  // ---------- pointer parallax (camera drift, like a handheld showcase) ----------
  let mouseX = 0, mouseY = 0, curX = 0, curY = 0;
  if (!isCoarse) {
    window.addEventListener('mousemove', (e) => {
      mouseX = (e.clientX / window.innerWidth) * 2 - 1;
      mouseY = (e.clientY / window.innerHeight) * 2 - 1;
    });
  }

  // ---------- assembly captions, boot-log style ----------
  const CAPTIONS = [
    'SCANNING SECTOR TELEMETRY',
    'CROSS-REFERENCING ANOMALIES',
    'CONVERGING DEFENSE VECTORS',
    'SHIELD FORMED — SENTINEL ONLINE',
  ];
  function setCaption(i) {
    if (!captionEl) return;
    captionEl.innerHTML = `${CAPTIONS[i]}<span class="caret"></span>`;
  }
  let captionStage = -1;

  const clock = new THREE.Clock();
  let assembled = prefersReducedMotion;

  if (prefersReducedMotion) {
    const live = geometry.attributes.position;
    for (let i = 0; i < TOTAL; i++) {
      live.setXYZ(i, targetPos[i * 3], targetPos[i * 3 + 1], targetPos[i * 3 + 2]);
    }
    live.needsUpdate = true;
    setCaption(3);
  } else {
    setCaption(0);
  }

  function easeOutBack(t) {
    const c1 = 1.70158, c3 = c1 + 1;
    return 1 + c3 * Math.pow(t - 1, 3) + c1 * Math.pow(t - 1, 2);
  }

  let spinY = 0.12;
  let sectionVisible = true;
  let pageVisible = !document.hidden;
  let animationFrame = null;

  const visibilityObserver = new IntersectionObserver(([entry]) => {
    sectionVisible = entry.isIntersecting;
    if (sectionVisible && pageVisible && animationFrame === null) animate();
  }, { threshold: 0.01 });
  visibilityObserver.observe(section);
  document.addEventListener('visibilitychange', () => {
    pageVisible = !document.hidden;
    if (pageVisible && sectionVisible && animationFrame === null) animate();
  });

  function animate() {
    animationFrame = null;
    if (!pageVisible || !sectionVisible) return;
    animationFrame = requestAnimationFrame(animate);
    const t = clock.getElapsedTime();

    if (!assembled) {
      const live = geometry.attributes.position;
      let allDone = true;
      for (let i = 0; i < TOTAL; i++) {
        const local = (t - delays[i]) / durations[i];
        if (local < 1) allDone = false;
        const p = Math.max(0, Math.min(1, local));
        const e = easeOutBack(p);
        const sx = startPos[i * 3], sy = startPos[i * 3 + 1], sz = startPos[i * 3 + 2];
        const tx = targetPos[i * 3], ty = targetPos[i * 3 + 1], tz = targetPos[i * 3 + 2];
        live.setXYZ(i, sx + (tx - sx) * e, sy + (ty - sy) * e, sz + (tz - sz) * e);
      }
      live.needsUpdate = true;

      if (t > 0.15 && captionStage < 1) { captionStage = 1; setCaption(1); }
      if (t > 1.4 && captionStage < 2) { captionStage = 2; setCaption(2); }
      if (allDone) { assembled = true; captionStage = 3; setCaption(3); }
    } else {
      group.position.y = Math.sin(t * 0.6) * 0.35;
    }

    ringOuter.rotation.z += 0.0022;
    ringInner.rotation.z -= 0.0032;
    icoLines.rotation.y += 0.0009;
    icoLines.rotation.x += 0.0004;

    curX += (mouseX - curX) * 0.04;
    curY += (mouseY - curY) * 0.04;
    spinY += assembled ? 0.0018 : 0.0003;
    group.rotation.y = spinY + curX * 0.14;
    group.rotation.x = -0.12 - curY * 0.16;

    camera.position.x = curX * 2.2;
    camera.position.y = -curY * 1.4;
    camera.lookAt(0, 0, 0);

    renderer.render(scene, camera);
  }
  animate();
})();
