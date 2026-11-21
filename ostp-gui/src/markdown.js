// ── A small, safe Markdown subset for text written by a server operator ──
// Headings (#, ##, ###), paragraphs, **bold**, *italic*, `code`, fenced code
// blocks, - / * / 1. lists and [links](url). Nothing else is interpreted:
// HTML and every other construct stay visible as plain text. The result is
// built with createElement/textContent only, never innerHTML.

export const MAX_MARKDOWN_CHARS = 8000;
const MAX_URL = 2048;

// Links that may be opened, and only after the user clicks them.
export function safeUrl(url) {
  const u = String(url || '').trim();
  if (!u || u.length > MAX_URL || /[\s\u0000-\u001f\u007f<>"']/.test(u)) return null;
  return /^(https?:\/\/[^/]|mailto:[^/]|tg:)/i.test(u) ? u : null;
}

// Inline text → [{ t: 'text', text, b, i } | { t: 'code', text } | { t: 'link', text, url, b, i }]
export function parseInline(src) {
  const s = String(src);
  const out = [];
  let buf = '';
  let b = false, it = false;
  const flush = () => { if (buf) { out.push({ t: 'text', text: buf, b, i: it }); buf = ''; } };
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === '\\' && i + 1 < s.length && /[\\`*_[\]()#\-.!>]/.test(s[i + 1])) {
      buf += s[i + 1]; i += 2; continue;
    }
    if (c === '`') {
      const end = s.indexOf('`', i + 1);
      if (end > i + 1) { flush(); out.push({ t: 'code', text: s.slice(i + 1, end) }); i = end + 1; continue; }
    }
    if (c === '*' && s[i + 1] === '*') {
      // A marker opens only when it is closed later on the same text.
      if (b || s.indexOf('**', i + 2) > i + 2) { flush(); b = !b; i += 2; continue; }
      buf += '**'; i += 2; continue;
    }
    if (c === '*') {
      if (it || (s.indexOf('*', i + 1) > i + 1 && s[i + 1] !== ' ')) { flush(); it = !it; i += 1; continue; }
    }
    if (c === '[') {
      const close = s.indexOf('](', i + 1);
      const end = close > i ? s.indexOf(')', close + 2) : -1;
      if (close > i + 1 && end > close + 2 && !s.slice(i + 1, close).includes('[')) {
        const url = safeUrl(s.slice(close + 2, end));
        if (url) {
          flush();
          out.push({ t: 'link', text: s.slice(i + 1, close), url, b, i: it });
          i = end + 1;
          continue;
        }
      }
    }
    buf += c;
    i += 1;
  }
  flush();
  return out;
}

// Text → blocks: { t: 'h', level, inl } | { t: 'p', inl } | { t: 'code', text } | { t: 'ul'|'ol', items: [inl] }
export function parseMarkdown(src) {
  const lines = String(src || '').slice(0, MAX_MARKDOWN_CHARS).replace(/\r\n?/g, '\n').split('\n');
  const blocks = [];
  let para = [];
  let list = null; // { t, items: [string] }
  const endPara = () => { if (para.length) { blocks.push({ t: 'p', inl: parseInline(para.join(' ')) }); para = []; } };
  const endList = () => { if (list) { blocks.push({ t: list.t, items: list.items.map(parseInline) }); list = null; } };
  for (let n = 0; n < lines.length; n++) {
    const line = lines[n];
    if (/^\s*```/.test(line)) {
      endPara(); endList();
      const code = [];
      n += 1;
      while (n < lines.length && !/^\s*```/.test(lines[n])) code.push(lines[n++]);
      blocks.push({ t: 'code', text: code.join('\n') });
      continue;
    }
    if (!line.trim()) { endPara(); endList(); continue; }
    const h = /^(#{1,3})\s+(.*)$/.exec(line);
    if (h) { endPara(); endList(); blocks.push({ t: 'h', level: h[1].length, inl: parseInline(h[2].replace(/\s+#+\s*$/, '')) }); continue; }
    const ul = /^\s{0,3}[-*]\s+(.*)$/.exec(line);
    const ol = ul ? null : /^\s{0,3}\d{1,9}[.)]\s+(.*)$/.exec(line);
    if (ul || ol) {
      endPara();
      const t = ul ? 'ul' : 'ol';
      if (list && list.t !== t) endList();
      if (!list) list = { t, items: [] };
      list.items.push((ul || ol)[1]);
      continue;
    }
    // An indented line right after a list item continues that item.
    if (list && /^\s+\S/.test(line)) { list.items[list.items.length - 1] += ' ' + line.trim(); continue; }
    endList();
    para.push(line.trim());
  }
  endPara(); endList();
  return blocks;
}

// Builds the blocks into `parent`. onLink(url) is called when a link is clicked.
export function renderMarkdown(parent, src, onLink) {
  const doc = parent.ownerDocument;
  const inline = (el, nodes) => {
    for (const x of nodes) {
      let node;
      if (x.t === 'code') {
        node = doc.createElement('code');
        node.textContent = x.text;
      } else if (x.t === 'link') {
        node = doc.createElement('a');
        node.href = '#';
        node.className = 'md-link';
        node.textContent = x.text;
        node.title = x.url;
        node.addEventListener('click', e => { e.preventDefault(); onLink?.(x.url); });
      } else {
        node = doc.createTextNode(x.text);
      }
      if (x.t !== 'code' && (x.b || x.i)) {
        let wrap = node;
        if (x.i) { const em = doc.createElement('em'); em.appendChild(wrap); wrap = em; }
        if (x.b) { const st = doc.createElement('strong'); st.appendChild(wrap); wrap = st; }
        node = wrap;
      }
      el.appendChild(node);
    }
  };
  for (const blk of parseMarkdown(src)) {
    let el;
    if (blk.t === 'h') { el = doc.createElement('h' + (blk.level + 3)); inline(el, blk.inl); }
    else if (blk.t === 'p') { el = doc.createElement('p'); inline(el, blk.inl); }
    else if (blk.t === 'code') { el = doc.createElement('pre'); el.textContent = blk.text; }
    else {
      el = doc.createElement(blk.t);
      for (const item of blk.items) { const li = doc.createElement('li'); inline(li, item); el.appendChild(li); }
    }
    parent.appendChild(el);
  }
}
