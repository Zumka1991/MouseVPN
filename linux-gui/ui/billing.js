'use strict';
const bill = id => document.getElementById(id);
let billingBusy = false;
let billingDetails = null;
let billingOwner = null;
let billingDraft = null;
let billingRequests = [];
const paymentLabels = {pending:'На проверке',approved:'Подтверждено',rejected:'Отклонено'};
function billingAmount() {
  const months = Number(bill('billingMonths').value);
  bill('billingTotal').textContent = Number.isInteger(months) && months >= 3 && months <= 120 ? `${months * 300} ₽` : 'От 3 месяцев';
}
function paintBilling(view, details) {
  if (details) {
    billingDetails = view.details;
    const ready = !!billingDetails?.enabled;
    bill('billingDetails').classList.toggle('hidden', !ready);
    for (const [id, key] of [['billingBank','bank'],['billingRecipient','recipient'],['billingInstructions','instructions']]) bill(id).textContent = billingDetails?.[key] || '';
    bill('billingCard').value = billingDetails?.card_number || '';
    if (!ready) bill('billingStatus').textContent = 'Реквизиты пока не опубликованы. Напишите в поддержку.';
  }
  billingRequests = view.requests;
  const pending = view.requests.some(r => r.status === 'pending');
  bill('billingForm').classList.toggle('hidden', pending);
  bill('billingPending').classList.toggle('hidden', !pending);
  bill('billingHistory').replaceChildren();
  for (const r of view.requests) {
    const row = document.createElement('article'); row.className = 'billing-history-item';
    const title = document.createElement('strong'); title.className = `billing-${r.status}`; title.textContent = `${r.amount_rub} ₽ · ${r.months} мес. · ${paymentLabels[r.status] || r.status}`;
    const time = document.createElement('small'); time.textContent = new Date(r.created_at * 1000).toLocaleString('ru-RU'); row.append(title,time);
    for (const text of [r.admin_note, r.valid_until ? `Подписка продлена до ${new Date(r.valid_until * 1000).toLocaleDateString('ru-RU')}` : '']) if (text) { const line = document.createElement('span'); line.className = 'billing-history-note'; line.textContent = text; row.append(line); }
    bill('billingHistory').append(row);
  }
  if (!view.requests.length) bill('billingHistory').textContent = 'Заявок пока нет.';
}
async function billingWork(job, quiet = false) {
  if (billingBusy) return;
  billingBusy = true;
  const epoch = supportEpoch;
  bill('billingSubmit').disabled = true; bill('billingRefresh').disabled = true;
  if (!quiet) bill('billingStatus').textContent = 'Загружаем…';
  try { await job(); }
  catch (error) { if (epoch === supportEpoch) bill('billingStatus').textContent = String(error); }
  finally { billingBusy = false; bill('billingSubmit').disabled = false; bill('billingRefresh').disabled = false; }
}
async function loadBilling(details = false) {
  const view = await supportInvoke('billing_view');
  const changed = view.requests.some(r => r.status === 'approved' && billingRequests.find(old => old.id === r.id)?.status !== 'approved');
  bill('billingStatus').textContent = '';
  paintBilling(view, details);
  if (changed) await refreshAccount();
}
bill('openBilling').onclick = () => {
  if (!accountView?.signed_in) { document.querySelector('#openAccount').click(); return; }
  if (billingOwner !== accountView.account.id) { billingOwner = accountView.account.id; billingDraft = null; billingRequests = []; bill('billingForm').reset(); billingAmount(); bill('billingHistory').replaceChildren(); bill('billingDetails').classList.add('hidden'); }
  bill('billingModal').classList.remove('hidden'); billingWork(() => loadBilling(true));
};
bill('closeBilling').onclick = () => bill('billingModal').classList.add('hidden');
bill('billingRefresh').onclick = () => billingWork(() => loadBilling(true));
bill('billingMonths').oninput = billingAmount;
bill('billingCopy').onclick = async () => {
  try { await navigator.clipboard.writeText(bill('billingCard').value); bill('billingStatus').textContent = 'Номер карты скопирован'; }
  catch (_) { bill('billingCard').focus(); bill('billingCard').select(); bill('billingStatus').textContent = document.execCommand('copy') ? 'Номер карты скопирован' : 'Номер выделен. Нажмите Ctrl+C, чтобы скопировать.'; }
};
bill('billingForm').onsubmit = event => {
  event.preventDefault();
  if (!billingDetails?.enabled) return;
  const value = {months:Number(bill('billingMonths').value),note:bill('billingNote').value.trim(),details_revision:billingDetails.revision};
  if (!Number.isInteger(value.months) || value.months < 3 || value.months > 120) return;
  const signature = JSON.stringify(value);
  if (billingDraft?.signature !== signature) billingDraft = {signature, request:{id:crypto.randomUUID(), ...value}};
  billingWork(async () => { await supportInvoke('billing_submit', {request:billingDraft.request}); billingDraft = null; await loadBilling(); bill('billingStatus').textContent = 'Заявка отправлена. Ожидайте проверки поступления.'; });
};
setInterval(() => { if (!document.hidden && !bill('billingModal').classList.contains('hidden') && accountView?.signed_in) billingWork(() => loadBilling(), true); }, 8000);
