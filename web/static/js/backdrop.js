"use strict";
// =============================================================================
// Domain Hunter — Live Architectural Threat-Mesh Background Canvas (Landing)
// Automatically pauses in workspace mode, hidden tabs, and reduced-motion.
// =============================================================================
(function () {
  let pulseBoost = false;
  window.setScanPulse = function (on) {
    pulseBoost = !!on;
  };

  const canvas = document.getElementById("hero-bg-canvas");
  if (!canvas || typeof canvas.getContext !== "function") return;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  const prefersReduced = () =>
    window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const isLanding = () => document.body.classList.contains("is-landing") || document.body.classList.contains("landing-home");
  const isHeroHome = () => document.body.classList.contains("landing-home");
  const isDark = () => document.documentElement.dataset.theme === "dark";

  let width = 0;
  let height = 0;
  let dpr = 1;
  let nodes = [];
  let pulses = [];
  let pointer = { x: -9999, y: -9999, active: false };
  let rafId = null;
  let lastPulseAt = 0;

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = window.innerWidth || 1280;
    height = window.innerHeight || 800;
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    const targetCount = Math.max(22, Math.min(52, Math.round((width * height) / 28000)));
    if (nodes.length !== targetCount) {
      nodes = Array.from({ length: targetCount }, (_, i) => ({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.34,
        vy: (Math.random() - 0.5) * 0.34,
        r: i % 5 === 0 ? 2.8 : 1.9,
        alert: i % 11 === 0,
        phase: Math.random() * Math.PI * 2,
      }));
    }
  }

  function spawnPulse() {
    if (!nodes.length) return;
    const n = nodes[Math.floor(Math.random() * nodes.length)];
    pulses.push({ x: n.x, y: n.y, r: 4, maxR: pulseBoost ? 150 : 105, alpha: 0.55, alert: n.alert });
    if (pulses.length > 6) pulses.shift();
  }

  function drawStatic() {
    ctx.clearRect(0, 0, width, height);
    const home = isHeroHome();
    const dark = isDark();
    const lineRgb = dark ? "96, 165, 250" : "29, 78, 216";
    const nodeRgb = dark ? "147, 197, 253" : "37, 99, 235";
    const lineAlphaScale = home ? (dark ? 0.11 : 0.065) : (dark ? 0.17 : 0.095);
    const maxDist = 155;

    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < nodes.length; j++) {
        const b = nodes[j];
        const dx = a.x - b.x;
        const dy = a.y - b.y;
        const d2 = dx * dx + dy * dy;
        if (d2 < maxDist * maxDist) {
          const dist = Math.sqrt(d2);
          const alpha = (1 - dist / maxDist) * lineAlphaScale;
          ctx.strokeStyle = `rgba(${lineRgb}, ${alpha.toFixed(3)})`;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }
      if (pointer.active) {
        const pd = Math.hypot(a.x - pointer.x, a.y - pointer.y);
        if (pd < 190) {
          const pa = (1 - pd / 190) * (home ? (dark ? 0.18 : 0.10) : (dark ? 0.28 : 0.16));
          ctx.strokeStyle = `rgba(${lineRgb}, ${pa.toFixed(3)})`;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(pointer.x, pointer.y);
          ctx.stroke();
        }
      }
    }

    for (const n of nodes) {
      n.phase += 0.025;
      const glow = 0.45 + 0.35 * Math.sin(n.phase);
      const fill = n.alert && !home ? (dark ? `rgba(248,113,113,${(0.45 * glow).toFixed(2)})` : `rgba(220,38,38,${(0.32 * glow).toFixed(2)})`)
        : `rgba(${nodeRgb}, ${(home ? 0.22 + 0.16 * glow : 0.35 + 0.25 * glow).toFixed(2)})`;
      ctx.fillStyle = fill;
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fill();
    }

    for (let i = pulses.length - 1; i >= 0; i--) {
      const p = pulses[i];
      p.r += pulseBoost ? 1.5 : 0.85;
      p.alpha *= 0.975;
      const pRgb = p.alert ? "220, 38, 38" : lineRgb;
      ctx.strokeStyle = `rgba(${pRgb}, ${(p.alpha * (dark ? 0.35 : 0.22)).toFixed(3)})`;
      ctx.lineWidth = 1.25;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.stroke();
      if (p.r >= p.maxR || p.alpha < 0.03) pulses.splice(i, 1);
    }
  }

  function frame(ts) {
    if (!document.hidden && isLanding()) {
      if (!prefersReduced()) {
        const speed = pulseBoost ? 2.1 : 1;
        for (const n of nodes) {
          n.x += n.vx * speed;
          n.y += n.vy * speed;
          if (n.x < -10) n.x = width + 10;
          if (n.x > width + 10) n.x = -10;
          if (n.y < -10) n.y = height + 10;
          if (n.y > height + 10) n.y = -10;
        }
        const interval = pulseBoost ? 900 : 2100;
        if (ts - lastPulseAt > interval) {
          spawnPulse();
          lastPulseAt = ts;
        }
      }
      drawStatic();
    } else {
      ctx.clearRect(0, 0, width, height);
    }
    rafId = window.requestAnimationFrame(frame);
  }

  window.addEventListener("resize", resize);
  window.addEventListener("mousemove", e => {
    pointer.x = e.clientX;
    pointer.y = e.clientY;
    pointer.active = true;
  }, { passive: true });
  window.addEventListener("mouseleave", () => { pointer.active = false; });

  resize();
  if (!prefersReduced()) {
    rafId = window.requestAnimationFrame(frame);
  } else {
    drawStatic();
  }
  void rafId;
})();
