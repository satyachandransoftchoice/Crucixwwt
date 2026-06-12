// Shared output-encoding helpers used by server-side code and tests.
// The equivalent escHtml function is also defined in dashboard/public/jarvis.html
// for client-side use — keep both in sync if changing the encoding rules.

/**
 * HTML-encode a value for safe insertion into an innerHTML context.
 * Decodes one layer of common HTML entities first so double-encoded
 * source text (e.g. &amp;lt; from OSINT feeds) renders correctly.
 */
export function escHtml(t) {
  const decoded = String(t)
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&#39;/g, "'")
    .replace(/&#33;/g, '!');
  return decoded
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Escape Markdown control characters for Telegram/Discord legacy Markdown.
 * Only escapes the characters that legacy parse mode treats as markup:
 * _ * ` [
 */
export function escapeMd(text) {
  if (!text) return '';
  return text.replace(/([_*`\[])/g, '\\$1');
}
