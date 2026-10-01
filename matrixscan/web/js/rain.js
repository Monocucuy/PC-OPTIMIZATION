/* Lluvia digital estilo Matrix en un canvas de fondo. */
(function () {
  'use strict';
  const canvas = document.getElementById('rain');
  const ctx = canvas.getContext('2d');
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const GLYPHS = 'ｦｱｳｴｵｶｷｹｺｻｼｽｾｿﾀﾂﾃﾅﾆﾇﾈﾊﾋﾎﾏﾐﾑﾒﾓﾔﾕﾗﾘﾜ0123456789ABCDEFZ:.=*+-<>¦|';
  const SIZE = 16;
  let cols = 0, drops = [], speeds = [], w = 0, h = 0, dpr = 1;
  let intensity = 0; // 0 normal, 1 escaneando
  let last = 0;

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    w = window.innerWidth; h = window.innerHeight;
    canvas.width = w * dpr; canvas.height = h * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    cols = Math.ceil(w / SIZE);
    drops = Array.from({ length: cols }, () => Math.random() * -h / SIZE);
    speeds = Array.from({ length: cols }, () => 0.35 + Math.random() * 0.75);
    ctx.fillStyle = '#000'; ctx.fillRect(0, 0, w, h);
  }

  function frame(t) {
    requestAnimationFrame(frame);
    const interval = intensity ? 33 : 50;
    if (t - last < interval || document.hidden) return;
    last = t;
    ctx.fillStyle = 'rgba(0, 3, 0, 0.09)';
    ctx.fillRect(0, 0, w, h);
    ctx.font = `${SIZE}px Consolas, monospace`;
    for (let i = 0; i < cols; i++) {
      const y = drops[i] * SIZE;
      const ch = GLYPHS[(Math.random() * GLYPHS.length) | 0];
      // cabeza brillante y estela verde
      ctx.fillStyle = Math.random() < 0.08 ? '#e6ffee' : '#00ff41';
      ctx.shadowColor = '#00ff41';
      ctx.shadowBlur = intensity ? 8 : 0;
      ctx.fillText(ch, i * SIZE, y);
      drops[i] += speeds[i] * (1 + intensity * 0.9);
      if (y > h && Math.random() > 0.975) drops[i] = Math.random() * -20;
    }
    ctx.shadowBlur = 0;
  }

  window.MatrixRain = {
    setIntensity(v) { intensity = v ? 1 : 0; document.body.classList.toggle('scanning', !!v); },
  };

  if (reduce) return;
  window.addEventListener('resize', resize);
  resize();
  requestAnimationFrame(frame);
})();
