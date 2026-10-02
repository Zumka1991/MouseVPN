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
function showSignupResult(success, text) {
  document.getElementById('signupResultTitle').textContent = success ? 'Заявка принята!' : 'Не удалось отправить заявку';
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
    status.textContent = 'Заявка принята! Ваш логин: ' + data.login + '. Напишите @napsy13 в Telegram для оплаты. Доступ появится после её подтверждения.';
    status.className = 'success'; showSignupResult(true, status.textContent);
  } catch (error) { status.textContent = error.name === 'TimeoutError' ? 'Ответ задержался. Заявка могла быть принята — попробуйте войти в приложение или напишите @napsy13.' : error instanceof TypeError ? 'Нет связи с сервером. Проверьте интернет и попробуйте снова.' : error.message; status.className = 'error'; showSignupResult(false, status.textContent); }
  finally { signupSending = false; submit.disabled = false; submit.innerHTML = originalLabel; signupForm.removeAttribute('aria-busy'); }
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
