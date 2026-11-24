"use strict";
/* A02 · Lucide-style SVG icon helper. The sprite is embedded in index.html. */
function ncIcon(name){
  const glyph=String(name||'').replace(/[^a-z0-9-]/g,'');
  return `<svg class="nc-ui-icon" aria-hidden="true" focusable="false"><use href="#i-${glyph}"></use></svg>`;
}
