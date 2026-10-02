'use strict';
const $ = id => document.getElementById(id);
let token = sessionStorage.getItem('relay.owner') || '';
let servers = [];
let accounts = [];
let selectedUser = null;
let currentTicket = null;
let ticketRequest = 0;
let ticketPolling = false;
const date = value => value >= 253402300799 ? 'Бессрочно' : value ? new Date(value * 1000).toLocaleString('ru-RU') : 'Не оплачено';
function el(tag, text, className) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node; }
function message(text, error = false) { $('status').textContent = text; $('status').className = error ? 'error' : 'success'; }
async function api(path, method = 'GET', body) {
  const response = await fetch(`.${path}`, { method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  const data = await response.json().catch(() => ({ error: 'Некорректный ответ сервера' }));
  if (!response.ok) throw new Error(data.error || 'Запрос отклонён');
  return data;
}
async function action(button, work) { button.disabled = true; try { await work(); } catch (error) { message(error.message, true); } finally { button.disabled = false; } }
async function load() {
  const [users, nodes, tickets] = await Promise.all([api('/v1/admin/users'), api('/v1/admin/servers'), api('/v1/admin/tickets')]);
  servers = nodes; accounts = users; updateUsageUsers();
  $('workspace').hidden = false; $('loginPanel').hidden = true; $('refresh').hidden = false;
  $('userCount').textContent = users.length; $('activeCount').textContent = users.filter(user => user.active).length;
  $('onlineCount').textContent = nodes.filter(node => node.enabled && node.last_seen > Date.now() / 1000 - 90).length;
  $('pendingCount').textContent = users.filter(user => !user.valid_until).length; renderUsers(); $('servers').replaceChildren(...nodes.map(serverCard));
  renderNetwork(nodes);
  renderTickets(tickets);
  await loadPaymentRequests();
  if (paymentRevision === null) await loadPaymentDetails();
  if (!users.length) $('users').append(el('p', 'Создайте первый аккаунт. Старые ключи продолжают работать на своих серверах.', 'muted'));
  message('Данные обновлены');
}
function userCard(user) {
  const card = el('article', undefined, 'card');
  const head = el('div', undefined, 'user-header'); const title = el('div'); title.append(el('h2', user.login), el('div', `${user.lifetime ? 'Бессрочный доступ' : 'Доступ до: ' + date(user.valid_until)} · устройства ${user.devices.length}/2`, 'muted'));
  head.append(title, el('span', user.enabled ? (user.active ? 'Активна' : (!user.valid_until ? 'Новая заявка' : 'Ожидает оплаты')) : 'Заблокирован', `badge ${user.active ? 'active' : ''}`)); card.append(head);
  const lifetimeLabel=el('label','Бессрочный доступ (для друзей)','check section');
  const lifetimeInput=document.createElement('input');lifetimeInput.type='checkbox';lifetimeInput.checked=user.lifetime;
  lifetimeInput.onchange=()=>action(lifetimeInput,async()=>{try{await api(`/v1/admin/users/${user.id}/lifetime`,'PUT',{enabled:lifetimeInput.checked});await load();message(lifetimeInput.checked?'Бессрочный доступ включён':'Действует обычный оплаченный срок');}catch(error){lifetimeInput.checked=user.lifetime;throw error;}});
  lifetimeLabel.prepend(lifetimeInput);card.append(lifetimeLabel,el('p',`Срочный доступ до: ${user.paid_valid_until ? date(user.paid_valid_until) : 'не выдан'}. Лимит устройств и распределение серверов сохраняются.`,'muted'));
  card.append(dayGrantSection(user));
  const access = el('details', undefined, 'section'); access.append(el('summary', 'Распределение серверов'));
  const all = document.createElement('input'); all.type = 'checkbox'; all.checked = user.all_servers;
  const allLabel = el('label', 'Все серверы, включая новые', 'check'); allLabel.prepend(all); access.append(allLabel);
  const choices = el('div', undefined, 'server-choice'); const picks = servers.map(server => { const input = document.createElement('input'); input.type = 'checkbox'; input.checked = user.server_ids.includes(server.id); input.disabled = all.checked; const label = el('label', server.name, 'check'); label.prepend(input); choices.append(label); return [server.id, input]; });
  all.onchange = () => picks.forEach(([, input]) => { input.disabled = all.checked; }); access.append(choices);
  const save = el('button', 'Сохранить распределение'); save.onclick = () => action(save, async () => { await api(`/v1/admin/users/${user.id}/access`, 'PUT', { enabled: user.enabled, all_servers: all.checked, server_ids: all.checked ? [] : picks.filter(([, input]) => input.checked).map(([id]) => id) }); await load(); }); access.append(save); card.append(access);
  const pay = el('details', undefined, 'section'); pay.append(el('summary', 'Оплата и история продлений'));
  const form = document.createElement('form'); const months = document.createElement('input'); months.type = 'number'; months.min = '3'; months.max = '120'; months.step = '1'; months.value = '3'; months.required = true;
  const ref = document.createElement('input'); ref.required = true; ref.maxLength = 120; ref.placeholder = 'Номер перевода или ваша отметка';
  const monthLabel = el('label', 'Месяцы'); monthLabel.append(months); const refLabel = el('label', 'Уникальная отметка платежа'); refLabel.append(ref);
  const confirm = el('button', 'Подтвердить 900 ₽'); confirm.type = 'submit'; months.oninput = () => { confirm.textContent = `Подтвердить ${Number(months.value) * 300} ₽`; };
  form.append(monthLabel, refLabel, confirm); form.onsubmit = event => { event.preventDefault(); action(confirm, async () => { await api(`/v1/admin/users/${user.id}/payments`, 'POST', { reference: ref.value.trim(), months: Number(months.value), amount_rub: Number(months.value) * 300 }); await load(); }); }; pay.append(form);
  for (const payment of user.payments.slice(0, 5)) pay.append(el('p', `${date(payment.confirmed_at)} · ${payment.amount_rub} ₽ · ${payment.months} мес. · ${payment.reference}`, 'payment-history')); card.append(pay);
  const devices = el('section', undefined, 'section'); devices.append(el('h3', 'Устройства'));
  for (const device of user.devices) { const row = el('div', undefined, 'device'); const revoke = el('button', 'Отключить', 'danger'); revoke.onclick = () => action(revoke, async () => { if (!window.confirm(`Отключить устройство «${device.name}»?`)) return; await api(`/v1/admin/users/${user.id}/devices/${device.id}`, 'DELETE'); await load(); }); row.append(el('span', `${device.name} · ${device.platform}`), revoke); devices.append(row); }
  if (!user.devices.length) devices.append(el('p', 'Устройства появятся после входа в приложение.', 'muted')); card.append(devices);
  const usageButton = el('button', 'Трафик и подключения'); usageButton.onclick = () => { $('usageTab').click(); $('usageUser').value = user.id; usagePage = 0; refreshUsage(); }; card.append(usageButton);
  const actions = el('div', undefined, 'actions section'); const block = el('button', user.enabled ? 'Заблокировать аккаунт' : 'Разблокировать аккаунт', user.enabled ? 'danger' : ''); block.onclick = () => action(block, async () => { await api(`/v1/admin/users/${user.id}/access`, 'PUT', { enabled: !user.enabled, all_servers: user.all_servers, server_ids: user.server_ids }); await load(); });
  const reset = el('button', 'Сменить пароль'); reset.onclick = () => action(reset, async () => { const password = window.prompt('Новый пароль (минимум 10 символов). Потребуется повторный вход на устройствах.'); if (!password) return; await api(`/v1/admin/users/${user.id}/password`, 'PUT', { password }); message('Пароль изменён'); }); actions.append(block, reset); card.append(actions);
  const compose = el('details', undefined, 'section'); compose.append(el('summary', 'Написать пользователю в приложение'));
  const messageForm = document.createElement('form'); const subject = document.createElement('input'); subject.value = 'Сообщение администрации'; subject.required = true; subject.maxLength = 80;
  const text = document.createElement('textarea'); text.required = true; text.maxLength = 3000; text.rows = 4;
  const subjectLabel = el('label', 'Тема'); subjectLabel.append(subject); const textLabel = el('label', 'Сообщение'); textLabel.append(text);
  const send = el('button', 'Отправить в приложение'); send.type = 'submit'; messageForm.append(subjectLabel, textLabel, send);
  messageForm.onsubmit = event => { event.preventDefault(); action(send, async () => { await api(`/v1/admin/users/${user.id}/messages`, 'POST', { subject: subject.value, text: text.value }); text.value = ''; await load(); message('Сообщение отправлено пользователю'); }); }; compose.append(messageForm); card.append(compose);
  return card;
}
function serverCard(server) {
  const card = el('article', undefined, 'card'); const head = el('div', undefined, 'user-header'); head.append(el('h2', server.name), serverStatus(server)); card.append(head, addressRow(server), el('p', `Последняя связь: ${server.last_seen ? date(server.last_seen) : 'ожидается подключение'}`, 'muted'), el('p', 'Режим соединения выбирается в приложении.', 'muted'));
  const rename = document.createElement('form'); rename.className = 'rename-server';
  const name = document.createElement('input'); name.type = 'text'; name.value = server.name; name.maxLength = 80; name.required = true;
  const label = el('label', 'Название для клиентов'); label.append(name);
  const saveName = el('button', 'Сохранить название'); saveName.type = 'submit'; rename.append(label, saveName);
  rename.onsubmit = event => { event.preventDefault(); action(saveName, async () => { await api(`/v1/admin/servers/${server.id}`, 'PUT', { ...server, name: name.value.trim() }); await load(); message('Название сервера сохранено. Клиенты увидят его после обновления данных.'); }); };
  card.append(rename);
  const toggle = el('button', server.enabled ? 'Выключить доступ' : 'Включить доступ'); toggle.onclick = () => action(toggle, async () => { await api(`/v1/admin/servers/${server.id}`, 'PUT', { ...server, enabled: !server.enabled }); await load(); }); card.append(toggle); return card;
}
function serverStatus(server) {
  const online = server.enabled && server.last_seen > Date.now() / 1000 - 90;
  return el('span', server.enabled ? (online ? 'На связи' : 'Нет связи') : 'Отключён', 'badge ' + (online ? 'active' : ''));
}
function addressRow(server) {
  const row = el('div', undefined, 'server-address');
  const separator = server.endpoint.lastIndexOf(':');
  const ip = separator >= 0 ? server.endpoint.slice(0, separator).replace(/^\[|\]$/g, '') : server.endpoint;
  const port = separator >= 0 ? server.endpoint.slice(separator + 1) : '';
  const copy = el('button', 'Копировать IP', 'copy-ip'); copy.type = 'button';
  copy.onclick = () => action(copy, async () => { await navigator.clipboard.writeText(ip); message('IP сервера скопирован'); });
  row.append(el('code', ip, 'server-ip'), el('span', port ? 'UDP ' + port : '', 'port-label'), copy);
  return row;
}
function renderNetwork(nodes) {
  $('activeServers').replaceChildren(...nodes.filter(server => server.enabled).map(server => {
    const card = el('article', undefined, 'server-summary'); const head = el('div', undefined, 'user-header');
    head.append(el('h3', server.name), serverStatus(server)); card.append(head, addressRow(server)); return card;
  }));
  if (!nodes.some(server => server.enabled)) $('activeServers').append(el('p', 'Активных серверов пока нет. Добавьте первый в разделе «Серверы».', 'muted'));
}
$('loginForm').onsubmit = event => { event.preventDefault(); token = $('token').value.trim(); action(event.submitter, async () => { await load(); sessionStorage.setItem('relay.owner', token); $('token').value = ''; }); };
$('refresh').onclick = () => action($('refresh'), load);
$('logout').onclick = () => { paymentRevision = null; $('paymentDetailsForm').reset(); $('paymentRequests').replaceChildren(); token = ''; sessionStorage.removeItem('relay.owner'); $('workspace').hidden = true; selectedUser = null; $('userSearch').value = ''; $('userDetail').replaceChildren(); $('refresh').hidden = true; $('loginPanel').hidden = false; accounts = []; $('users').replaceChildren(); $('servers').replaceChildren(); $('tickets').replaceChildren(); $('conversationMessages').replaceChildren(); $('conversation').hidden = true; $('replyText').value = ''; currentTicket = null; servers = []; $('nodeToken').value = ''; $('nodeSecret').hidden = true; message('Вы вышли'); };
$('userForm').onsubmit = event => { event.preventDefault(); action(event.submitter, async () => { await api('/v1/admin/users', 'POST', { login: $('userLogin').value, password: $('userPassword').value }); $('userForm').reset(); await load(); }); };
$('serverForm').onsubmit = event => { event.preventDefault(); action(event.submitter, async () => { const result = await api('/v1/admin/servers', 'POST', { name: $('serverName').value, endpoint: $('serverEndpoint').value, public_key: $('serverKey').value, protocol: $('serverProtocol').value, enabled: true }); $('nodeToken').value = result.node_token; $('nodeSecret').hidden = false; $('serverForm').reset(); await load(); }); };
$('hideSecret').onclick = () => { $('nodeToken').value = ''; $('nodeSecret').hidden = true; };
for (const name of ['users', 'servers', 'tickets', 'payments', 'usage']) $(`${name}Tab`).onclick = () => { for (const panel of ['users', 'servers', 'tickets', 'payments', 'usage']) { $(`${panel}Panel`).hidden = name !== panel; $(`${panel}Tab`).classList.toggle('selected', name === panel); } };
function renderTickets(tickets) {
  const unread = tickets.reduce((sum, ticket) => sum + ticket.unread_count, 0);
  $('ticketsTab').textContent = `Тикеты и сообщения${unread ? ` · ${unread} новых` : ''}`;
  $('tickets').replaceChildren(...tickets.map(ticket => {
    const button = el('button', `${ticket.unread_count ? '● ' : ''}${ticket.login} · ${ticket.subject} · ${ticket.status === 'closed' ? 'закрыт' : 'открыт'}`, 'ticket-button');
    button.onclick = () => action(button, async () => { await openTicket(ticket.id); renderTickets(await api('/v1/admin/tickets')); }); return button;
  }));
  if (!tickets.length) $('tickets').append(el('p', 'Новых обращений пока нет.', 'muted'));
}
function messageNode(item) {
  const article = el('article', undefined, `message ${item.author}`); article.append(el('small', `${item.author === 'admin' ? 'Администрация' : 'Пользователь'} · ${date(item.created_at)}`), el('p', item.text)); return article;
}
async function openTicket(id, before = null) {
  const request = ++ticketRequest;
  const detail = await api(`/v1/admin/tickets/${id}${before ? `?before=${before}` : ''}`);
  if (request !== ticketRequest || !token) return;
  const changedTicket = currentTicket?.ticket.id !== id;
  if (changedTicket) $('replyText').value = '';
  renderConversation(detail, !changedTicket);
}
function renderConversation(detail, merge = true) {
  const previous = currentTicket;
  if (merge && previous?.ticket.id === detail.ticket.id) {
    const items = new Map([...previous.messages, ...detail.messages].map(item => [item.id, item]));
    const earlierLoaded = previous.messages.length && detail.messages.length && previous.messages[0].id < detail.messages[0].id;
    detail = { ...detail, messages: [...items.values()].sort((a, b) => a.id - b.id), has_more: earlierLoaded ? previous.has_more : detail.has_more };
  }
  currentTicket = detail;
  const list = $('conversationMessages');
  const position = list.scrollTop;
  const height = list.scrollHeight;
  const atBottom = height - list.clientHeight - position < 80;
  const sameTicket = previous?.ticket.id === detail.ticket.id;
  const changedMessages = !sameTicket || previous.messages.length !== detail.messages.length || previous.messages.some((item, index) => item.id !== detail.messages[index]?.id);
  $('conversation').hidden = false; $('conversationTitle').textContent = `${detail.ticket.login} · ${detail.ticket.subject}`;
  if (changedMessages) {
    list.replaceChildren(...detail.messages.map(messageNode));
    const prepended = sameTicket && previous.messages.length && detail.messages[0]?.id < previous.messages[0].id;
    list.scrollTop = prepended ? position + list.scrollHeight - height : (!sameTicket || atBottom ? list.scrollHeight : position);
  }
  $('olderMessages').hidden = !detail.has_more;
  $('closeTicket').textContent = detail.ticket.status === 'closed' ? 'Открыть тикет' : 'Закрыть тикет';
}
$('replyForm').onsubmit = event => {
  event.preventDefault(); if (!currentTicket) return;
  const id = currentTicket.ticket.id; const text = $('replyText').value;
  action($('sendReply'), async () => {
    await api(`/v1/admin/tickets/${id}/messages`, 'POST', { text });
    if (currentTicket?.ticket.id === id) {
      if ($('replyText').value === text) $('replyText').value = '';
      await openTicket(id);
    }
    renderTickets(await api('/v1/admin/tickets')); message('Ответ отправлен');
  });
};
$('closeTicket').onclick = () => {
  if (!currentTicket) return;
  const id = currentTicket.ticket.id; const status = currentTicket.ticket.status === 'closed' ? 'open' : 'closed';
  action($('closeTicket'), async () => {
    await api(`/v1/admin/tickets/${id}/status`, 'PUT', { status });
    if (currentTicket?.ticket.id === id) await openTicket(id);
    renderTickets(await api('/v1/admin/tickets'));
  });
};
$('olderMessages').onclick = () => { if (currentTicket?.messages.length) action($('olderMessages'), () => openTicket(currentTicket.ticket.id, currentTicket.messages[0].id)); };
setInterval(async () => {
  if (!token || $('workspace').hidden || document.hidden || ticketPolling) return;
  ticketPolling = true;
  const id = currentTicket?.ticket.id;
  const request = ticketRequest;
  try {
    if (id && !$('ticketsPanel').hidden) {
      const detail = await api(`/v1/admin/tickets/${id}`);
      if (token && currentTicket?.ticket.id === id && request === ticketRequest) renderConversation(detail);
    }
    const tickets = await api('/v1/admin/tickets');
    if (token) renderTickets(tickets);
  } catch (_) { /* Retry on the next foreground refresh. */ }
  finally { ticketPolling = false; }
}, 3_000);
setInterval(() => {
  if (!token || $('workspace').hidden || document.hidden) return;
  api('/v1/admin/servers').then(nodes => {
    servers = nodes; renderNetwork(nodes);
    $('onlineCount').textContent = nodes.filter(node => node.enabled && node.last_seen > Date.now() / 1000 - 90).length;
    if (!$('servers').contains(document.activeElement)) $('servers').replaceChildren(...nodes.map(serverCard));
  }).catch(() => {});
}, 30_000);
if (token) Promise.resolve().then(load).catch(error => { message(error.message, true); });

function renderUsers() {
  const search=$('userSearch').value.trim().toLowerCase();
  const users=accounts.filter(user=>(!$('pendingOnly').checked || !user.valid_until)&&user.login.toLowerCase().includes(search));
  if (!users.some(u=>u.id===selectedUser)) selectedUser=null;
  $('userSearchCount').textContent=`${users.length} из ${accounts.length}`;
  $('users').replaceChildren(...users.map(user=>{
    const row=el('button',undefined,'user-list-row'+(selectedUser===user.id?' chosen':''));row.type='button';row.setAttribute('aria-pressed',String(selectedUser===user.id));
    const text=el('span');text.append(el('strong',user.login),el('small',`${user.devices.length}/2 устройства · ${user.lifetime?'бессрочно':user.valid_until?'до '+new Date(user.valid_until*1000).toLocaleDateString('ru-RU'):'без оплаты'}`));
    row.append(text,el('span',!user.enabled?'Блок':user.active?'Активна':!user.valid_until?'Заявка':'Истекла','badge '+(user.active?'active':'')));
    row.onclick=()=>{selectedUser=user.id;renderUsers();if(matchMedia('(max-width:1000px)').matches)$('userDetail').scrollIntoView({behavior:'smooth',block:'start'});};return row;
  }));
  if(!users.length)$('users').append(el('p','Пользователи не найдены.','muted'));
  const current=accounts.find(u=>u.id===selectedUser);
  $('userDetail').replaceChildren(current?userCard(current):el('p','Выберите пользователя, чтобы управлять подпиской, устройствами и доступом.','card muted'));
}
$('pendingOnly').onchange = renderUsers;
$('userSearch').oninput = renderUsers;

let paymentRevision = null;
let paymentBusy = false;
async function loadPaymentDetails() {
  const d = await api('/v1/admin/payment-details');
  paymentRevision = d?.revision || 0;
  $('paymentEnabled').checked = d?.enabled || false;
  for (const [id, field] of [['paymentBank','bank'],['paymentRecipient','recipient'],['paymentCard','card_number'],['paymentInstructions','instructions']]) $(id).value = d?.[field] || '';
}
async function loadPaymentRequests() {
  const requests = await api('/v1/admin/payment-requests');
  const count = requests.filter(r => r.status === 'pending').length;
  $('paymentCount').textContent = count ? `· на проверке: ${count}` : '';
  $('paymentsTab').textContent = count ? `Оплата (${count})` : 'Оплата';
  $('paymentRequests').replaceChildren(...requests.map(paymentRequestCard));
  if (!requests.length) $('paymentRequests').append(el('p', 'Заявок пока нет.', 'muted'));
}
function paymentRequestCard(r) {
  const card = el('article', undefined, 'section');
  card.append(el('h3', `${r.login} · ${r.amount_rub} ₽ · ${r.months} мес.`),
    el('p', `${date(r.created_at)} · ${{pending:'На проверке',approved:'Подтверждено',rejected:'Отклонено'}[r.status]}`, 'muted'),
    el('p', `Перевод: ${r.details.bank} · ${r.details.recipient} · карта •••• ${r.details.card_number.slice(-4)}`));
  if (r.note) card.append(el('p', r.note, 'payment-note'));
  if (r.admin_note) card.append(el('p', `Ответ: ${r.admin_note}`, 'payment-note'));
  if (r.valid_until) card.append(el('p', `Подписка продлена до ${date(r.valid_until)}`, 'success'));
  if (r.status === 'pending') {
    const approve = el('button', `Деньги пришли — добавить ${r.months} мес.`);
    const reject = el('button', 'Отклонить', 'danger');
    const decide = (button, status, note) => action(button, async () => {
      if (paymentBusy) return;
      paymentBusy = true;
      try { await api(`/v1/admin/payment-requests/${r.id}/decision`, 'POST', {status, note}); await load(); message(status === 'approved' ? 'Оплата подтверждена, месяцы добавлены' : 'Причина отклонения отправлена в приложение'); }
      finally { paymentBusy = false; }
    });
    approve.onclick = () => { if (window.confirm(`Подтвердить поступление ${r.amount_rub} ₽ от ${r.login} и добавить ${r.months} мес.?`)) decide(approve, 'approved', ''); };
    reject.onclick = () => { const reason = window.prompt('Причина отклонения (будет видна пользователю):'); if (reason?.trim()) decide(reject, 'rejected', reason.trim()); };
    const actions = el('div', undefined, 'actions'); actions.append(approve, reject); card.append(actions);
  }
  return card;
}
$('paymentDetailsForm').onsubmit = event => { event.preventDefault(); action(event.submitter, async () => {
  const d = await api('/v1/admin/payment-details', 'PUT', {revision:paymentRevision || 0,enabled:$('paymentEnabled').checked,bank:$('paymentBank').value,recipient:$('paymentRecipient').value,card_number:$('paymentCard').value,instructions:$('paymentInstructions').value});
  paymentRevision = d.revision; message('Реквизиты сохранены. Они доступны в разделе оплаты приложений.');
}); };
$('reloadPaymentDetails').onclick = () => action($('reloadPaymentDetails'), loadPaymentDetails);
setInterval(async () => { if (!token || document.hidden || $('workspace').hidden || paymentBusy) return; paymentBusy = true; try { await loadPaymentRequests(); } catch (_) {} finally { paymentBusy = false; } }, 8000);

let usagePage = 0;
let usageRequest = 0;
let usageBusy = false;
function bytes(n) { if (!n) return '0 Б'; const units=['Б','КиБ','МиБ','ГиБ','ТиБ']; const i=Math.min(4,Math.floor(Math.log(n)/Math.log(1024))); return `${(n/1024**i).toLocaleString('ru-RU',{maximumFractionDigits:2})} ${units[i]}`; }
function updateUsageUsers() {
  const value=$('usageUser').value; $('usageUser').replaceChildren(new Option('Все пользователи',''),...accounts.map(u=>new Option(u.login,u.id))); $('usageUser').value=accounts.some(u=>u.id===value)?value:'';
}
function usageTable(id, headings, rows) {
  const table=el('table'); const head=el('thead'); const tr=el('tr'); headings.forEach(h=>tr.append(el('th',h))); head.append(tr); table.append(head);
  const body=el('tbody'); for(const row of rows){const tr=el('tr'); row.forEach(value=>tr.append(el('td',value)));body.append(tr);} table.append(body);
  $(id).replaceChildren(rows.length?table:el('p','За этот период данных пока нет.','muted'));
}
async function refreshUsage() {
  if(!token || $('usagePanel').hidden)return;
  const request=++usageRequest; usageBusy=true; $('usageStatus').textContent='Загружаем статистику…';
  const query=new URLSearchParams({user:$('usageUser').value,days:$('usageDays').value,group:$('usageGroup').value,offset:String(-new Date().getTimezoneOffset()),page:String(usagePage)});
  try {
    const data=await api('/v1/admin/usage?'+query);
    if(request!==usageRequest || !token)return;
    const stale=data.sync.filter(s=>!s.at || data.generated_at-s.at>90);
    $('usageStatus').textContent=stale.length?`Неполные данные: нет свежего отчёта от ${stale.map(s=>s.name).join(', ')}. Последние полученные значения сохранены.`:`Обновлено ${date(data.generated_at)} · все серверы передают статистику`;
    const total=field=>data.users.reduce((s,u)=>s+u[field],0);
    $('usageMetrics').replaceChildren(...[['Текущий час',total('hour')],['Сегодня',total('day')],['Эта неделя',total('week')],['За период',total('upload')+total('download')]].map(([label,value])=>{const card=el('article',undefined,'card');card.append(el('span',label),el('strong',bytes(value)));return card;}));
    usageTable('usageUsers',['Пользователь','За час','Сегодня','Эта неделя','Отправлено за период','Получено за период'],data.users.map(u=>[u.login,bytes(u.hour),bytes(u.day),bytes(u.week),bytes(u.upload),bytes(u.download)]));
    usageTable('usageServers',['VPN-сервер','Адрес','Отправлено','Получено','Всего'],data.servers.map(s=>[s.name,s.endpoint,bytes(s.upload),bytes(s.download),bytes(s.upload+s.download)]));
    usageTable('usagePeriods',['Начало периода','Отправлено','Получено','Всего'],[...data.series].reverse().map(p=>[date(p.at),bytes(p.upload),bytes(p.download),bytes(p.upload+p.download)]));
    usageTable('usageConnections',['Когда','Пользователь','Устройство','VPN-сервер','Режим'],data.connections.map(c=>[date(c.at),c.login,c.device,c.server,({legacy:'Обычный',speedy:'Speedy',morph_quiet:'Morph Quiet',morph_balanced:'Morph Balanced',morph_paranoid:'Morph Paranoid'}[c.protocol]||c.protocol)]));
    $('usagePrev').disabled=usagePage===0; $('usageNext').disabled=!data.has_more; $('usagePage').textContent=`Страница ${usagePage+1}`;
    const peak=Math.max(1,...data.series.map(p=>p.upload+p.download));
    $('usageChart').replaceChildren(...data.series.map(p=>{const bar=el('div',undefined,'usage-bar'); const title=`${date(p.at)} · ${bytes(p.upload+p.download)}`;bar.title=title;bar.setAttribute('aria-label',title);bar.tabIndex=0; const meter=document.createElement('meter');meter.min=0;meter.max=peak;meter.value=p.upload+p.download;meter.setAttribute('aria-label',title);bar.append(meter,el('small',new Date(p.at*1000).toLocaleDateString('ru-RU',{day:'numeric',month:'short'})));return bar;}));
    if(!data.series.length)$('usageChart').append(el('p','График появится после передачи трафика.','muted'));
  }catch(error){if(request===usageRequest)$('usageStatus').textContent=`Не удалось обновить статистику: ${error.message}`;}
  finally{if(request===usageRequest)usageBusy=false;}
}
for(const id of ['usageUser','usageDays','usageGroup'])$(id).onchange=()=>{usagePage=0;refreshUsage();};
$('usageRefresh').onclick=()=>refreshUsage();
$('usageTab').addEventListener('click',()=>{usagePage=0;refreshUsage();});
$('usagePrev').onclick=()=>{usagePage=Math.max(0,usagePage-1);refreshUsage();};
$('usageNext').onclick=()=>{usagePage++;refreshUsage();};
$('logout').addEventListener('click',()=>{usageRequest++;usageBusy=false;for(const id of ['usageMetrics','usageChart','usageUsers','usageServers','usagePeriods','usageConnections'])$(id).replaceChildren();});
setInterval(()=>{if(!document.hidden&&!usageBusy&&usagePage===0)refreshUsage();},15000);

function dayGrantSection(user) {
  const section=el('section',undefined,'section');section.append(el('h3','Выдать доступ в днях'));
  const form=el('form');const days=document.createElement('input');days.type='number';days.min='1';days.max='3650';days.step='1';days.value='1';days.required=true;
  const dayLabel=el('label','Количество дней');dayLabel.append(days);
  const note=document.createElement('input');note.maxLength=200;note.placeholder='Например, пробный доступ';
  const noteLabel=el('label','Комментарий (необязательно)');noteLabel.append(note);
  const submit=el('button','Добавить дни');submit.type='submit';
  let reference=crypto.randomUUID();
  for(const input of [days,note])input.addEventListener('input',()=>{reference=crypto.randomUUID();});
  form.append(dayLabel,noteLabel,submit);
  form.onsubmit=event=>{event.preventDefault();if(submit.disabled)return;action(submit,async()=>{
    days.disabled=true;note.disabled=true;
    try {
      const updated=await api(`/v1/admin/users/${user.id}/days`,'POST',{reference,days:Number(days.value),note:note.value.trim()});
      accounts=accounts.map(u=>u.id===updated.id?updated:u);renderUsers();
      $('activeCount').textContent=accounts.filter(u=>u.active).length;
      $('pendingCount').textContent=accounts.filter(u=>!u.valid_until).length;
      message(`Дни добавлены. Срочный доступ до ${date(updated.paid_valid_until)}${updated.lifetime ? '. Бессрочный доступ остаётся включён' : !updated.enabled ? '. Аккаунт остаётся заблокирован' : ''}`);
    } finally {days.disabled=false;note.disabled=false;}
  });};
  section.append(form,el('p','От 1 дня. Оставшийся срок сохраняется; если доступ закончился, дни считаются с текущего момента. Один день — 24 часа.','muted'));
  if(user.lifetime)section.append(el('p','Включён бессрочный доступ. Чтобы ограничить его днями, снимите галочку выше.','muted'));
  if(user.day_grants?.length){const history=el('details');history.append(el('summary','История выдачи дней'));for(const g of user.day_grants)history.append(el('p',`${date(g.granted_at)} · +${g.days} дн. · до ${date(g.valid_until)}${g.note?' · '+g.note:''}`,'payment-history'));section.append(history);}
  return section;
}
