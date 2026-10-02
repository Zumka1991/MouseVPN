'use strict';
// The secret word is checked by Caddy against the mv_gate cookie; this page only stores what was typed.
const COOKIE = 'mv_gate';
const RU_TO_EN = { 'й':'q','ц':'w','у':'e','к':'r','е':'t','н':'y','г':'u','ш':'i','щ':'o','з':'p','ф':'a','ы':'s','в':'d','а':'f','п':'g','р':'h','о':'j','л':'k','д':'l','я':'z','ч':'x','с':'c','м':'v','и':'b','т':'n','ь':'m' };
const normalize = value => [...value.trim().toLowerCase()].map(c => RU_TO_EN[c] || c).join('');
const secure = location.protocol === 'https:' ? '; Secure' : '';
const setCookie = (value, maxAge) => { document.cookie = `${COOKIE}=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=/; SameSite=Lax${secure}`; };

const input = document.getElementById('gateWord');
const error = document.getElementById('gateError');
// Still seeing this page while carrying the cookie means the server rejected the word.
if (document.cookie.split('; ').some(item => item.startsWith(`${COOKIE}=`))) {
  setCookie('', 0);
  error.hidden = false;
  input.classList.add('shake');
}
input.addEventListener('input', () => { error.hidden = true; input.classList.remove('shake'); });
document.getElementById('gateForm').addEventListener('submit', event => {
  event.preventDefault();
  const word = normalize(input.value);
  if (!word) return;
  setCookie(word, 60 * 60 * 24 * 365);
  location.reload();
});
