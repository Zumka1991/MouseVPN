'use strict';
fetch('releases.json', { cache: 'no-store' }).then(response => {
  if (!response.ok) throw new Error('Manifest unavailable');
  return response.json();
}).then(data => {
  for (const platform of ['android', 'windows', 'linux', 'linuxAppimage']) {
    const release = data[platform];
    if (!release || !/^downloads\/[A-Za-z0-9._-]+$/.test(release.file) || !/^[a-f0-9]{64}$/.test(release.sha256)) continue;
    const link = document.getElementById(`${platform}Download`);
    if (!link) continue;
    link.hidden = false;
    link.href = release.file; link.setAttribute('download', ''); link.removeAttribute('aria-disabled');
    link.textContent = {android:'Скачать для Android ↓',windows:'Скачать для Windows ↓',linux:'Скачать .deb ↓',linuxAppimage:'Скачать AppImage ↓'}[platform];
    document.getElementById(`${platform}Version`).textContent = `Версия ${release.version} · ${release.size_mb} МБ`;
    const details = document.getElementById(`${platform}Hash`); details.hidden = false;
    details.querySelector('code').textContent = `SHA-256: ${release.sha256}`;
  }
  if (typeof data.contact_url === 'string' && /^https:\/\/t\.me\/[A-Za-z0-9_]+$/.test(data.contact_url)) {
    const link = document.getElementById('contactButton'); link.href = data.contact_url;
    link.textContent = 'Написать в Telegram ↗'; link.target = '_blank'; link.rel = 'noopener noreferrer';
    document.getElementById('contactNote').textContent = 'Напишите владельцу: поможем с подключением и расскажем, как оплатить.';
  }
}).catch(() => {});

const signupForm = document.getElementById('signupForm');
const signupResult = document.getElementById('signupResult');
function showSignupResult(success, text, trial = false) {
  document.getElementById('signupResultTitle').textContent = trial ? 'Подарок активирован!' : success ? 'Заявка принята!' : 'Не удалось отправить заявку';
  const next = document.getElementById('signupResultContact');
  if (trial) { next.textContent = 'Скачать приложение ↓'; next.href = '#download'; next.removeAttribute('target'); next.onclick = () => signupResult.close(); }
  else { next.textContent = 'Обсудить оплату в Telegram ↗'; next.href = 'https://t.me/napsy13'; next.target = '_blank'; next.onclick = null; }
  document.getElementById('signupResultText').textContent = text;
  document.getElementById('signupResultIcon').textContent = success ? '✓' : '!';
  document.getElementById('signupResultContact').hidden = !success;
  signupResult.classList.toggle('result-error', !success);
  signupResult.showModal();
}
for (const id of ['signupResultClose', 'signupResultDone']) document.getElementById(id).onclick = () => signupResult.close();
let signupSending = false;
signupForm.addEventListener('submit', async event => {
  event.preventDefault();
  if (signupSending) return;
  const status = document.getElementById('signupStatus');
  const password = document.getElementById('signupPassword');
  const confirmation = document.getElementById('signupConfirm');
  status.className = '';
  if (password.value !== confirmation.value) { status.textContent = 'Пароли не совпадают'; status.className = 'error'; showSignupResult(false, status.textContent); return; }
  const submit = document.getElementById('signupSubmit'); signupSending = true; submit.disabled = true; const originalLabel = submit.innerHTML; submit.textContent = 'Отправляем…'; signupForm.setAttribute('aria-busy', 'true'); status.textContent = 'Отправляем заявку…';
  try {
    const response = await fetch(signupForm.action, { method: 'POST', signal: AbortSignal.timeout(20000), headers: {'Content-Type':'application/json'},
      body: JSON.stringify({email:document.getElementById('signupEmail').value.trim(),password:password.value}) });
    const data = await response.json().catch(() => ({error:'Сервис временно недоступен. Попробуйте позже.'}));
    if (!response.ok) throw new Error(data.error || 'Не удалось отправить заявку');
    if (typeof data.login !== 'string' || !data.login) throw new Error('Не удалось получить подтверждение. Проверьте вход в приложение или напишите @napsy13.');
    password.value = ''; confirmation.value = '';
    if (Number.isInteger(data.trial_days) && data.trial_days > 0 && Number.isInteger(data.valid_until)) {
      status.textContent = `Готово! Ваш логин: ${data.login}. Бесплатный доступ действует до ${new Date(data.valid_until * 1000).toLocaleDateString('ru-RU', {day:'numeric',month:'long'})}. Скачайте приложение и войдите с этой почтой и паролем.`;
      status.className = 'success'; showSignupResult(true, status.textContent, true); hideTrial(); return;
    }
    status.textContent = 'Заявка принята! Ваш логин: ' + data.login + '. Напишите @napsy13 в Telegram для оплаты. Доступ появится после её подтверждения.';
    status.className = 'success'; showSignupResult(true, status.textContent);
  } catch (error) { status.textContent = error.name === 'TimeoutError' ? 'Ответ задержался. Заявка могла быть принята — попробуйте войти в приложение или напишите @napsy13.' : error instanceof TypeError ? 'Нет связи с сервером. Проверьте интернет и попробуйте снова.' : error.message; status.className = 'error'; showSignupResult(false, status.textContent); }
  finally { signupSending = false; submit.disabled = false; submit.innerHTML = trialClaimed ? submitLabel : originalLabel; signupForm.removeAttribute('aria-busy'); }
});

// Product preview: navigation only. It never initiates a VPN connection.
const previewTabs = [...document.querySelectorAll('[role="tab"]')];
function selectPreview(tab) {
  for (const item of previewTabs) {
    const selected = item === tab;
    item.setAttribute('aria-selected', String(selected));
    item.tabIndex = selected ? 0 : -1;
    document.getElementById(item.getAttribute('aria-controls')).hidden = !selected;
  }
}
previewTabs.forEach((tab, index) => {
  tab.addEventListener('click', () => selectPreview(tab));
  tab.addEventListener('keydown', event => {
    let next;
    if (event.key === 'ArrowRight') next = (index + 1) % previewTabs.length;
    if (event.key === 'ArrowLeft') next = (index + previewTabs.length - 1) % previewTabs.length;
    if (event.key === 'Home') next = 0;
    if (event.key === 'End') next = previewTabs.length - 1;
    if (next === undefined) return;
    event.preventDefault(); selectPreview(previewTabs[next]); previewTabs[next].focus();
  });
});

async function refreshPricing() {
  try {
    const response=await fetch('/vpn/v1/pricing',{cache:'no-store',signal:AbortSignal.timeout(15000)});
    if(!response.ok)throw new Error('Pricing unavailable');
    const price=await response.json();
    if(!Number.isInteger(price.min_months)||price.min_months<1||price.min_months>120||!Number.isInteger(price.month_price)||price.month_price<=0)throw new Error('Invalid pricing');
    document.querySelectorAll('[data-minimum-price]').forEach(node=>node.textContent=`От ${price.min_months} мес. за ${price.min_months * price.month_price} ₽`);
    document.querySelectorAll('[data-minimum]').forEach(node=>node.textContent=`от ${price.min_months} мес.`);
  } catch (_) { /* Keep the neutral fallback instead of advertising outdated terms. */ }
}
refreshPricing();
setInterval(()=>{if(!document.hidden)refreshPricing();},60000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden)refreshPricing();});

// Invite links: the code itself lives in an HttpOnly cookie, so keep it out of the address bar.
const arrivedByInvite = new URLSearchParams(location.search).has('invite');
if (arrivedByInvite) history.replaceState(null, '', location.pathname + location.hash);
const giftDialog = document.getElementById('giftDialog');
const submitLabel = document.getElementById('signupSubmit').innerHTML;
let trialClaimed = false;
const days = n => `${n} ${n % 10 === 1 && n % 100 !== 11 ? 'день' : n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 12 || n % 100 > 14) ? 'дня' : 'дней'}`;
function remember(key) { try { localStorage.setItem(key, '1'); } catch (_) { /* Only affects whether the gift is shown again. */ } }
function seen(key) { try { return localStorage.getItem(key) === '1'; } catch (_) { return false; } }
function hideTrial() {
  trialClaimed = true;
  document.getElementById('trialBanner').hidden = true;
  document.querySelectorAll('[data-trial-days]').forEach(node => { node.textContent = ''; });
}
async function loadTrial() {
  try {
    const response = await fetch('/vpn/v1/invite', { cache: 'no-store', signal: AbortSignal.timeout(15000) });
    if (!response.ok) return;
    const offer = await response.json();
    if (!Number.isInteger(offer.trial_days) || offer.trial_days < 1 || offer.trial_days > 365) return;
    const label = days(offer.trial_days);
    document.querySelectorAll('[data-trial-days]').forEach(node => { node.textContent = label; });
    document.getElementById('trialBanner').hidden = false;
    document.getElementById('signupLead').textContent = `Укажите почту и придумайте пароль для приложения. VPN заработает сразу: ${label} бесплатно, без оплаты и привязки карты. Продлить подписку можно потом, прямо в приложении.`;
    const submit = document.getElementById('signupSubmit');
    submit.innerHTML = ''; submit.append(`Забрать ${label} бесплатно `); const arrow = document.createElement('span'); arrow.setAttribute('aria-hidden', 'true'); arrow.textContent = '↗'; submit.append(arrow);
    const status = document.getElementById('signupStatus');
    if (!status.className) status.textContent = 'Пробный период начнётся сразу после регистрации. Платить — только если понравится.';
    const key = `mv.gift.${offer.trial_days}`;
    if ((arrivedByInvite || !seen(key)) && !giftDialog.open && !signupResult.open) { giftDialog.showModal(); remember(key); }
  } catch (_) { /* Without an offer the regular signup stays as is. */ }
}
document.getElementById('giftClose').onclick = () => giftDialog.close();
document.getElementById('giftLater').onclick = () => giftDialog.close();
document.getElementById('giftTake').onclick = () => { giftDialog.close(); setTimeout(() => document.getElementById('signupEmail').focus({ preventScroll: true }), 300); };
loadTrial();
