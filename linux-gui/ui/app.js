const invoke = window.__TAURI__.core.invoke;

const platformLabel = document.querySelector(".brand span");
if (platformLabel && navigator.userAgent.includes("Windows")) {
  platformLabel.textContent = "Windows Client";
  document.querySelector("#openSettings small").textContent = "Ключи, запуск и приложения";
}

const elements = {
  profiles: document.querySelector("#profiles"),
  addProfile: document.querySelector("#addProfile"),
  addProfileSmall: document.querySelector("#addProfileSmall"),
  activeName: document.querySelector("#activeProfileName"),
  activeEndpoint: document.querySelector("#activeEndpoint"),
  serverValue: document.querySelector("#serverValue"),
  power: document.querySelector("#powerButton"),
  statusTitle: document.querySelector("#statusTitle"),
  statusMessage: document.querySelector("#statusMessage"),
  connectedServer: document.querySelector("#connectedServer"),
  connectedServerName: document.querySelector("#connectedServerName"),
  connectedServerEndpoint: document.querySelector("#connectedServerEndpoint"),
  badge: document.querySelector("#connectionBadge"),
  time: document.querySelector("#timeValue"),
  protocolSelector: document.querySelector("#protocolSelector"),
  protocolMode: document.querySelector("#protocolMode"),
  protocolHint: document.querySelector("#protocolHint"),
  reliabilityDiagnostics: document.querySelector("#reliabilityDiagnostics"),
  reliabilityModal: document.querySelector("#reliabilityModal"),
  reliabilityRecommendation: document.querySelector("#reliabilityRecommendation"),
  reliabilityModes: document.querySelector("#reliabilityModes"),
  closeReliability: document.querySelector("#closeReliability"),
  clearReliability: document.querySelector("#clearReliability"),
  profileModal: document.querySelector("#profileModal"),
  profileForm: document.querySelector("#profileForm"),
  token: document.querySelector("#profileToken"),
  password: document.querySelector("#profilePassword"),
  togglePassword: document.querySelector("#togglePassword"),
  saveProfile: document.querySelector("#saveProfile"),
  formError: document.querySelector("#formError"),
  deleteModal: document.querySelector("#deleteModal"),
  deleteMessage: document.querySelector("#deleteMessage"),
  cancelDelete: document.querySelector("#cancelDelete"),
  confirmDelete: document.querySelector("#confirmDelete"),
  appExclusions: document.querySelector("#appExclusions"),
  appExclusionsCount: document.querySelector("#appExclusionsCount"),
  appExclusionsModal: document.querySelector("#appExclusionsModal"),
  appExclusionsList: document.querySelector("#appExclusionsList"),
  appExclusionsError: document.querySelector("#appExclusionsError"),
  addAppExclusion: document.querySelector("#addAppExclusion"),
  closeAppExclusions: document.querySelector("#closeAppExclusions"),
  routingExclude: document.querySelector("#routingExclude"),
  routingInclude: document.querySelector("#routingInclude"),
  appRoutingHint: document.querySelector("#appRoutingHint"),
  appRoutingSearch: document.querySelector("#appRoutingSearch"),
  clearRoutedApps: document.querySelector("#clearRoutedApps"),
  openInstalledApps: document.querySelector("#openInstalledApps"),
  installedAppsModal: document.querySelector("#installedAppsModal"),
  installedAppsList: document.querySelector("#installedAppsList"),
  installedAppsSearch: document.querySelector("#installedAppsSearch"),
  installedAppsSelectionCount: document.querySelector("#installedAppsSelectionCount"),
  installedAppsError: document.querySelector("#installedAppsError"),
  closeInstalledApps: document.querySelector("#closeInstalledApps"),
  cancelInstalledApps: document.querySelector("#cancelInstalledApps"),
  applyInstalledApps: document.querySelector("#applyInstalledApps"),
  autostartSetting: document.querySelector("#autostartSetting"),
  autostartEnabled: document.querySelector("#autostartEnabled"),
};

let profiles = [];
let appRouting = { mode: "exclude", apps: [] };
let installedApps = [];
let installedAppSelection = new Set();
let selectedId = localStorage.getItem("mousevpn.selectedProfile");
let pendingDeleteId = null;
let connection = { state: "disconnected", message: "VPN выключен", profileId: null };
let connectedAt = null;
const isWindows = navigator.userAgent.includes("Windows");
let accountView = null;
let accountUpdating = false;
let supportBusy = false;
let supportConversation = null;
let supportEpoch = 0;
const supportDrafts = new Map();
async function supportInvoke(command, args) {
  const epoch = supportEpoch;
  const result = await invoke(command, args);
  if (epoch !== supportEpoch) throw new Error("Аккаунт изменён");
  return result;
}

function activeAccount(view) { return view.account?.active && view.account.valid_until > Date.now() / 1000; }
function renderAccount(view) {
  accountView = view;
  const signedIn = view.signed_in;
  document.querySelector('#accountForm').classList.toggle('hidden', signedIn);
  document.querySelector('#accountDetails').classList.toggle('hidden', !signedIn);
  document.querySelector('#accountBase').value = view.base || '';
  document.querySelector('#accountBase').classList.toggle('hidden', !isWindows);
  document.querySelector('label[for=accountBase]').classList.toggle('hidden', !isWindows);
  document.querySelector('#accountSignup').classList.toggle('hidden', isWindows || signedIn);
  document.querySelector('#accountRegister').classList.toggle('hidden', isWindows || !signedIn || view.registered);
  document.querySelector('#deviceCount').textContent = `${view.account?.devices?.length || 0} из ${view.account?.device_limit || 2} устройств`;
  document.querySelector('#accountNotice').textContent = view.notice || (signedIn && !activeAccount(view) ? 'После подтверждения оплаты подписка появится здесь.' : '');
  document.querySelector('#accountLogin').value = view.account?.login || '';
  const active = view.account?.active && view.account.valid_until > Date.now() / 1000;
  document.querySelector('#accountBadge').textContent = signedIn ? (active ? `Подписка до ${new Date(view.account.valid_until * 1000).toLocaleDateString('ru-RU')}` : 'Подписка неактивна') : 'Войти и посмотреть подписку';
  document.querySelector('#supportBadge').textContent = view.account?.unread_messages ? `Непрочитанных: ${view.account.unread_messages}` : 'Написать администрации';
  document.querySelector('#subscriptionUntil').textContent = view.account ? `${view.account.login} · ${active ? 'Действует до' : 'Неактивна, срок'}: ${view.account.valid_until ? new Date(view.account.valid_until * 1000).toLocaleString('ru-RU') : 'не оплачено'}` : '';
  const list = document.querySelector('#accountDevices');
  list.replaceChildren();
  for (const device of view.account?.devices || []) {
    const row = document.createElement('div'); row.className = 'account-device';
    const label = document.createElement('span'); label.textContent = `${device.name} · ${device.platform}${device.public_key === view.public_key ? ' · это устройство' : ''}`;
    const button = document.createElement('button'); button.className = 'secondary-button compact-button'; button.textContent = 'Отключить';
    button.onclick = () => accountAction(button, async () => {
      if (!window.confirm(`Отключить устройство «${device.name}»?`)) return;
      renderAccount(await invoke('account_revoke_device', { id: device.id }));
      await refreshProfiles();
    });
    row.append(label, button); list.append(row);
  }
}

async function accountAction(button, job) {
  if (accountUpdating) return;
  accountUpdating = true; button.disabled = true;
  const status = document.querySelector('#accountStatus'); status.textContent = 'Подождите…';
  try { await job(); status.textContent = accountView?.notice || 'Данные обновлены'; }
  catch (error) { status.textContent = String(error); }
  finally { button.disabled = false; accountUpdating = false; }
}

async function refreshAccount() {
  renderAccount(await invoke('account_refresh'));
  await refreshProfiles();
}

{
  document.querySelector('#openSupport').classList.remove('hidden');
  document.querySelector('#openAccount').classList.remove('hidden');
  document.querySelector('#openAccount').onclick = async () => {
    document.querySelector('#accountModal').classList.remove('hidden');
    try { renderAccount(await invoke('account_view')); } catch (error) { document.querySelector('#accountStatus').textContent = String(error); }
  };
  if (!isWindows) {
    document.querySelector('#accountContact').classList.remove('hidden');
    document.querySelector('#accountSignup').onclick = () => accountAction(document.querySelector('#accountSignup'), () => invoke('open_account_page', { kind: 'signup' }));
    document.querySelector('#accountContact').onclick = () => accountAction(document.querySelector('#accountContact'), () => invoke('open_account_page', { kind: 'contact' }));
    document.querySelector('#accountRegister').onclick = () => accountAction(document.querySelector('#accountRegister'), async () => { renderAccount(await invoke('account_register_device')); await refreshProfiles(); });
  }
  document.querySelector('#closeAccount').onclick = () => document.querySelector('#accountModal').classList.add('hidden');
  document.querySelector('#accountForm').onsubmit = event => {
    event.preventDefault();
    const password = document.querySelector('#accountPassword').value;
    document.querySelector('#accountPassword').value = '';
    accountAction(document.querySelector('#accountSignIn'), async () => {
      renderAccount(await invoke('account_login', { base: document.querySelector('#accountBase').value, login: document.querySelector('#accountLogin').value, password }));
      await refreshProfiles();
    });
  };
  document.querySelector('#accountRefresh').onclick = () => accountAction(document.querySelector('#accountRefresh'), refreshAccount);
  document.querySelector('#accountLogout').onclick = () => accountAction(document.querySelector('#accountLogout'), async () => { supportEpoch++; document.querySelector('#billingModal').classList.add('hidden'); supportDrafts.clear(); renderAccount(await invoke('account_logout')); supportConversation = null; document.querySelector('#supportModal').classList.add('hidden'); document.querySelector('#supportMessages').replaceChildren(); document.querySelector('#supportList').replaceChildren(); document.querySelector('#supportCreate').reset(); document.querySelector('#supportReplyText').value = ''; await refreshProfiles(); });
  invoke('account_view').then(view => { renderAccount(view); if (view.signed_in) return refreshAccount(); }).catch(error => { document.querySelector('#accountStatus').textContent = String(error); });
  setInterval(() => { if (accountView?.signed_in && !accountUpdating) accountAction(document.querySelector('#accountRefresh'), refreshAccount); }, 30_000);
  document.querySelector('#openSupport').onclick = () => {
    if (!accountView?.signed_in) { document.querySelector('#openAccount').click(); return; }
    document.querySelector('#supportModal').classList.remove('hidden'); supportWork(loadSupportList);
  };
  document.querySelector('#closeSupport').onclick = () => document.querySelector('#supportModal').classList.add('hidden');
  document.querySelector('#supportBack').onclick = () => supportWork(loadSupportList);
  document.querySelector('#supportCreate').onsubmit = event => { event.preventDefault(); supportWork(async () => {
    showSupportConversation(await supportInvoke('support_create', { subject: document.querySelector('#supportSubject').value, text: document.querySelector('#supportText').value }));
    document.querySelector('#supportCreate').reset();
  }); };
  document.querySelector('#supportReplyText').oninput = event => { if (supportConversation) supportDrafts.set(supportConversation.ticket.id, event.target.value); };
  document.querySelector('#supportReplyForm').onsubmit = event => { event.preventDefault(); if (!supportConversation) return; supportWork(async () => {
    const id = supportConversation.ticket.id;
    const input = document.querySelector('#supportReplyText');
    const text = input.value;
    const updated = await supportInvoke('support_reply', { id, text });
    showSupportConversation(updated, true);
    if (input.value === text) { input.value = ''; supportDrafts.delete(id); }
  }); };
  document.querySelector('#supportOlder').onclick = () => { if (!supportConversation?.messages.length) return; supportWork(async () => {
    const page = await supportInvoke('support_ticket', { id: supportConversation.ticket.id, before: supportConversation.messages[0].id });
    showSupportConversation({ ...page, messages: [...page.messages, ...supportConversation.messages] });
  }); };
  setInterval(() => {
    if (!document.hidden && !document.querySelector('#supportModal').classList.contains('hidden') && !supportBusy) supportWork(async () => {
      if (supportConversation) showSupportConversation(await supportInvoke('support_ticket', { id: supportConversation.ticket.id, before: null }), true);
      else await loadSupportList();
    }, true);
  }, 3_000);
}

async function supportWork(job, quiet = false) {
  if (supportBusy) return;
  supportBusy = true;
  const status = document.querySelector('#supportStatus'); if (!quiet) status.textContent = 'Подождите…';
  if (!quiet) document.querySelectorAll('#supportModal button').forEach(button => { button.disabled = true; });
  try { await job(); status.textContent = ''; }
  catch (error) { status.textContent = String(error); }
  finally { supportBusy = false; document.querySelectorAll('#supportModal button').forEach(button => { button.disabled = false; }); }
}
async function loadSupportList() {
  const tickets = await supportInvoke('support_tickets'); supportConversation = null;
  document.querySelector('#supportConversation').classList.add('hidden');
  document.querySelector('#supportCreate').classList.remove('hidden');
  const list = document.querySelector('#supportList'); list.classList.remove('hidden'); list.replaceChildren();
  for (const ticket of tickets) {
    const button = document.createElement('button'); button.type = 'button'; button.className = 'secondary-button support-ticket';
    button.textContent = `${ticket.unread_count ? '● ' : ''}${ticket.subject} · ${ticket.status === 'closed' ? 'закрыто' : 'открыто'}`;
    button.onclick = () => supportWork(async () => { showSupportConversation(await supportInvoke('support_ticket', { id: ticket.id, before: null })); }); list.append(button);
  }
}
function showSupportConversation(detail, merge = false) {
  const previous = supportConversation;
  if (merge && previous?.ticket.id === detail.ticket.id) {
    const older = previous.messages.length && detail.messages.length && previous.messages[0].id < detail.messages[0].id;
    detail = { ...detail, messages: [...new Map([...previous.messages, ...detail.messages].map(item => [item.id,item])).values()].sort((a,b) => a.id-b.id), has_more: older ? previous.has_more : detail.has_more };
  }
  if (previous?.ticket.id !== detail.ticket.id) document.querySelector('#supportReplyText').value = supportDrafts.get(detail.ticket.id) || '';
  supportConversation = detail;
  document.querySelector('#supportList').classList.add('hidden'); document.querySelector('#supportCreate').classList.add('hidden'); document.querySelector('#supportConversation').classList.remove('hidden');
  document.querySelector('#supportConversationTitle').textContent = detail.ticket.subject;
  document.querySelector('#supportOlder').classList.toggle('hidden', !detail.has_more);
  const messages = document.querySelector('#supportMessages');
  if (previous?.ticket.id === detail.ticket.id && previous.messages.length === detail.messages.length && previous.messages.every((item,i) => item.id === detail.messages[i].id)) return;
  const position = messages.scrollTop; const height = messages.scrollHeight;
  const atBottom = height - messages.clientHeight - position < 80;
  messages.replaceChildren();
  for (const item of detail.messages) {
    const article = document.createElement('article'); article.className = `support-message ${item.author}`;
    const label = document.createElement('small'); label.textContent = `${item.author === 'admin' ? 'Администрация' : 'Вы'} · ${new Date(item.created_at * 1000).toLocaleString('ru-RU')}`;
    const text = document.createElement('p'); text.textContent = item.text; article.append(label, text); messages.append(article);
  }
  const prepended = previous?.ticket.id === detail.ticket.id && previous.messages.length && detail.messages[0]?.id < previous.messages[0].id;
  messages.scrollTop = previous?.ticket.id !== detail.ticket.id ? messages.scrollHeight : prepended ? position + messages.scrollHeight - height : atBottom ? messages.scrollHeight : position;
}

elements.protocolSelector.classList.remove("hidden");
if (isWindows) {
  elements.autostartSetting.classList.remove("hidden");
  invoke("split_tunneling_available")
    .then((available) => elements.appExclusions.classList.toggle("hidden", !available))
    .catch(() => elements.appExclusions.classList.add("hidden"));
} else {
  elements.protocolMode.add(new Option("Speedy — минимальная маскировка", "speedy"), 1);
  elements.reliabilityDiagnostics.classList.remove("hidden");
}

async function refreshAutostart() {
  if (!isWindows) return;
  elements.autostartEnabled.checked = await invoke("autostart_enabled");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function windowsPathKey(path) {
  return String(path).replaceAll("/", "\\").toLocaleLowerCase("en-US");
}

function selectedProfile() {
  return profiles.find((profile) => profile.id === selectedId) ?? null;
}

function connectionProfile() {
  return profiles.find((profile) => profile.id === connection.profileId) ?? null;
}

function renderProfiles() {
  if (!profiles.length) {
    elements.profiles.innerHTML = '<div class="profiles-empty">Здесь появятся доступные серверы.<br>Войдите в аккаунт или добавьте старый ключ.</div>';
  } else {
    const groups = [
      { title: "По подписке", items: profiles.filter(profile => profile.managedUser) },
      { title: "Личные ключи", items: profiles.filter(profile => !profile.managedUser) },
    ];
    elements.profiles.innerHTML = groups.filter(group => group.items.length).map(group => `
      <div class="profile-group-label">${group.title}</div>
      ${group.items.map(profile => `
        <div class="profile-row">
          <button class="profile-card ${profile.id === selectedId ? "selected" : ""}" data-profile-id="${escapeHtml(profile.id)}" aria-pressed="${profile.id === selectedId}" title="${escapeHtml(profile.name)}">
            <span class="profile-indicator"></span><span class="profile-copy"><strong>${escapeHtml(profile.name)}</strong><small>${escapeHtml(serverLoad(profile))}</small></span>
            <span class="profile-check" aria-hidden="true">${profile.id === selectedId ? "✓" : ""}</span>
          </button>
          ${profile.managedUser ? "" : `<button class="delete-profile" data-delete-id="${escapeHtml(profile.id)}" aria-label="Удалить профиль ${escapeHtml(profile.name)}" title="Удалить профиль">×</button>`}
        </div>`).join("")}
    `).join("");
  }
  renderActiveProfile();
}

function renderActiveProfile() {
  for (const button of document.querySelectorAll('[data-profile-id]')) {
    const label = button.querySelector('.profile-copy small');
    if (label) label.textContent = serverLoad(profiles.find(p => p.id === button.dataset.profileId));
  }
  const profile = selectedProfile();
  const active = connectionProfile();
  elements.activeName.textContent = profile?.name ?? "Нет конфигураций";
  elements.activeEndpoint.textContent = profile?.managedUser ? serverLoad(profile) : (profile ? "Личный ключ" : "Войдите в аккаунт или добавьте ключ");
  elements.serverValue.textContent = active
    ? active.endpoint
    : (profile?.endpoint ?? "—");
  elements.power.disabled = connection.state === "disconnecting" || (!profile && !["connecting", "connected"].includes(connection.state));
  elements.power.setAttribute("aria-label", connection.state === "connecting" ? "Отменить подключение" : connection.state === "connected" ? "Отключить VPN" : "Включить VPN");
  elements.reliabilityDiagnostics.disabled = !profile;

  const showConnection = active && active.id !== selectedId && ["connecting", "connected", "disconnecting"].includes(connection.state);
  elements.connectedServer.classList.toggle("hidden", !showConnection);
  elements.connectedServerName.textContent = active?.name ?? "—";
  elements.connectedServerEndpoint.textContent = "Отключите VPN, чтобы подключиться к выбранному серверу";
  renderProtocol();
}

function renderProtocol() {
  const profile = selectedProfile();
  const protocol = profile?.protocol ?? "legacy";
  const descriptions = {
    legacy: "Совместимость с серверами старого формата",
    speedy: "Минимальная маскировка без дополнений и задержек. Нужен сервер с поддержкой Speedy.",
    morph_quiet: "Лёгкая маскировка и меньше дополнительного трафика",
    morph_balanced: "Баланс маскировки и расхода трафика",
    morph_paranoid: "Больше маскировки и дополнительного трафика",
  };
  elements.protocolMode.value = protocol;
  elements.protocolMode.disabled = !profile
    || ["connecting", "connected", "disconnecting"].includes(connection.state);
  elements.protocolHint.textContent = ["connecting", "connected", "disconnecting"].includes(connection.state)
    ? "Чтобы сменить режим, сначала отключите VPN"
    : (descriptions[protocol] ?? descriptions.legacy);
}

function formatObservedTime(seconds) {
  if (!seconds) return "нет данных";
  if (seconds < 60) return `${seconds} сек`;
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (hours) return `${hours} ч ${minutes} мин`;
  return `${Math.max(1, minutes)} мин`;
}

function renderReliability(summary) {
  const best = summary.modes.find((mode) => mode.protocol === summary.bestProtocol);
  if (best) {
    elements.reliabilityRecommendation.className = "reliability-recommendation ready";
    elements.reliabilityRecommendation.innerHTML = `<strong>Лучший по стабильности: ${escapeHtml(best.label)}</strong><span>Оценка ${best.stabilityScore.toFixed(1)} из 100 · сравниваются потери и восстановления</span>`;
  } else {
    elements.reliabilityRecommendation.className = "reliability-recommendation";
    elements.reliabilityRecommendation.innerHTML = summary.eligibleModes === 1
      ? "Один режим уже набрал достаточно данных. Используйте ещё один не менее 5 минут для честного сравнения."
      : "Пока недостаточно данных для рекомендации. Статистика накапливается во время обычной работы VPN.";
  }
  const selectedProtocol = selectedProfile()?.protocol;
  elements.reliabilityModes.innerHTML = summary.modes.map((mode) => `
    <article class="reliability-mode ${mode.protocol === summary.bestProtocol ? "best" : ""} ${mode.enoughData ? "" : "insufficient"}">
      <header>
        <div><strong>${escapeHtml(mode.label)}</strong>${mode.protocol === selectedProtocol ? '<span class="current-mode">выбран</span>' : ""}</div>
        <span class="reliability-score">${mode.enoughData ? mode.stabilityScore.toFixed(1) : "—"}</span>
      </header>
      <div class="reliability-metrics">
        <span>Наблюдение<strong>${formatObservedTime(mode.observedSeconds)}</strong></span>
        <span>Keepalive<strong>${mode.keepaliveResponses}/${mode.keepalivesSent}</strong></span>
        <span>Потери<strong>${mode.lossPercent.toFixed(2)}% (${mode.keepaliveTimeouts})</strong></span>
        <span>Средний / макс. RTT<strong>${mode.averageRttMs || "—"} / ${mode.maxRttMs || "—"} мс</strong></span>
        <span>Переподключения<strong>${mode.reconnects} · ${mode.reconnectsPerHour.toFixed(2)}/ч</strong></span>
        <span>Ошибки восстановления<strong>${mode.reconnectFailures}</strong></span>
        <span>Drops отправки<strong>${mode.outgoingDrops}</strong></span>
        <span>Пакеты ↑ / ↓<strong>${mode.outgoingPackets} / ${mode.incomingPackets}</strong></span>
        <span>Сигналы недоступности<strong>${mode.peerUnreachable}</strong></span>
        <span>Быстрые миграции<strong>${mode.migrations}</strong></span>
      </div>
      <footer>${mode.enoughData ? `${mode.sessions} сесс.` : "Нужно 5 минут и 20 keepalive"}</footer>
    </article>
  `).join("");
}

async function refreshReliability() {
  const profile = selectedProfile();
  if (!profile || isWindows) return;
  renderReliability(await invoke("reliability_diagnostics", { profileId: profile.id }));
}

function renderConnection(next) {
  const previousState = connection.state;
  connection = next;
  const labels = {
    disconnected: "Отключено",
    connecting: "Подключение",
    connected: "Подключено",
    disconnecting: "Отключение",
    error: "Ошибка",
  };
  elements.badge.className = `connection-badge ${next.state}`;
  elements.badge.innerHTML = `<span></span>${labels[next.state] ?? "Неизвестно"}`;
  elements.power.classList.toggle("connected", next.state === "connected");
  elements.power.classList.toggle("busy", ["connecting", "disconnecting"].includes(next.state));
  elements.power.setAttribute("aria-label", next.state === "connected" ? "Выключить VPN" : "Включить VPN");
  elements.statusTitle.textContent = {
    disconnected: "VPN выключен",
    connecting: "Подключение…",
    connected: "VPN включён",
    disconnecting: "Отключение…",
    error: "Не удалось подключиться",
  }[next.state] ?? "MouseVPN";
  elements.statusMessage.textContent = next.state === "disconnected"
    ? (selectedProfile() ? "Нажмите, чтобы подключиться" : "Добавьте профиль, чтобы начать работу")
    : next.state === "connected"
      ? "Соединение защищено. Нажмите, чтобы отключить"
      : next.state === "connecting" ? "Нажмите ещё раз, чтобы отменить подключение" : next.message;
  document.querySelector("#connectionDetail").textContent = next.message || labels[next.state] || "—";
  document.querySelector("#sessionTime").classList.toggle("hidden", next.state !== "connected");
  if (next.state === "connected" && previousState !== "connected") connectedAt = Date.now();
  if (next.state !== "connected") {
    connectedAt = null;
    elements.time.textContent = "—";
  }
  renderActiveProfile();
}

function renderAppExclusions() {
  const count = appRouting.apps.length;
  const includeMode = appRouting.mode === "include";
  const query = elements.appRoutingSearch.value.trim().toLocaleLowerCase("ru");
  const visibleApps = appRouting.apps.filter((app) =>
    !query || `${app.name}\n${app.path}`.toLocaleLowerCase("ru").includes(query));
  elements.routingExclude.checked = !includeMode;
  elements.routingInclude.checked = includeMode;
  elements.appRoutingHint.textContent = includeMode
    ? "Только выбранные приложения используют VPN. Остальные подключаются напрямую. Изменения применятся при следующем подключении."
    : "Выбранные приложения обходят VPN. Все остальные остаются в защищённом туннеле. Изменения применятся при следующем подключении.";
  elements.appExclusionsCount.textContent = count
    ? `${includeMode ? "Через VPN" : "В обход"}: ${count}`
    : (includeMode ? "Никто не использует VPN" : "Все приложения через VPN");
  elements.clearRoutedApps.disabled = count === 0;
  elements.appExclusionsList.innerHTML = visibleApps.length
    ? visibleApps.map((app) => `
      <div class="exclusion-row ${app.available ? "" : "unavailable"}">
        <span class="exclusion-icon">◇</span>
        <span class="exclusion-copy">
          <strong>${escapeHtml(app.name)}${app.available ? "" : " — файл не найден"}</strong>
          <small title="${escapeHtml(app.path)}">${escapeHtml(app.path)}</small>
        </span>
        <button class="remove-exclusion" type="button" data-exclusion-path="${escapeHtml(app.path)}" aria-label="Удалить исключение">×</button>
      </div>`).join("")
    : `<div class="exclusions-empty">${query ? "По вашему запросу ничего не найдено" : includeMode ? "Ни одно приложение не выбрано для VPN" : "Нет приложений в обход VPN"}</div>`;
}

function renderInstalledApps() {
  const query = elements.installedAppsSearch.value.trim().toLocaleLowerCase("ru");
  const visibleApps = installedApps.filter((app) =>
    !query || `${app.name}\n${app.path}`.toLocaleLowerCase("ru").includes(query));
  elements.installedAppsSelectionCount.textContent = `Выбрано: ${installedAppSelection.size}`;
  elements.applyInstalledApps.disabled = installedApps.length === 0;
  elements.installedAppsList.innerHTML = visibleApps.length
    ? visibleApps.map((app) => `
      <label class="installed-app-row">
        <input type="checkbox" data-installed-app-id="${escapeHtml(app.id)}" ${installedAppSelection.has(app.id) ? "checked" : ""} />
        <span class="exclusion-icon">${app.source === "store" ? "▦" : "◇"}</span>
        <span class="exclusion-copy">
          <strong>${escapeHtml(app.name)}<span class="installed-app-source">${app.source === "store" ? "Microsoft Store" : "Desktop"}</span></strong>
          <small title="${escapeHtml(app.path)}">${escapeHtml(app.path)}</small>
        </span>
      </label>`).join("")
    : `<div class="exclusions-empty">${query ? "По вашему запросу ничего не найдено" : "Установленные приложения не найдены"}</div>`;
}

async function openInstalledApps() {
  elements.installedAppsModal.classList.remove("hidden");
  elements.installedAppsError.classList.add("hidden");
  elements.installedAppsSearch.value = "";
  elements.installedAppsList.innerHTML = '<div class="exclusions-empty">Собираем список приложений…</div>';
  elements.applyInstalledApps.disabled = true;
  try {
    installedApps = await invoke("list_installed_apps");
    const routed = new Set(appRouting.apps.map((app) => windowsPathKey(app.path)));
    installedAppSelection = new Set(installedApps
      .filter((app) => app.paths.some((path) => routed.has(windowsPathKey(path))))
      .map((app) => app.id));
    renderInstalledApps();
    setTimeout(() => elements.installedAppsSearch.focus(), 50);
  } catch (error) {
    installedApps = [];
    installedAppSelection = new Set();
    elements.installedAppsList.innerHTML = '<div class="exclusions-empty">Не удалось получить список приложений</div>';
    elements.installedAppsError.textContent = String(error);
    elements.installedAppsError.classList.remove("hidden");
  }
}

function closeInstalledApps() {
  elements.installedAppsModal.classList.add("hidden");
}

async function refreshAppExclusions() {
  if (!isWindows) return;
  appRouting = await invoke("get_app_routing");
  renderAppExclusions();
}

async function refreshProfiles(preferId = null) {
  profiles = await invoke("list_profiles");
  if (preferId && profiles.some((profile) => profile.id === preferId)) selectedId = preferId;
  if (!profiles.some((profile) => profile.id === selectedId)) selectedId = profiles[0]?.id ?? null;
  if (selectedId) localStorage.setItem("mousevpn.selectedProfile", selectedId);
  else localStorage.removeItem("mousevpn.selectedProfile");
  renderProfiles();
}

function openProfileModal() {
  elements.profileModal.classList.remove("hidden");
  setTimeout(() => elements.token.focus(), 50);
}

function closeProfileModal() {
  elements.profileModal.classList.add("hidden");
  elements.profileForm.reset();
  elements.formError.classList.add("hidden");
  elements.password.type = "password";
  elements.togglePassword.textContent = "Показать";
  validateForm();
}

function validateForm() {
  elements.saveProfile.disabled = !elements.token.value.trim().startsWith("MV1.") || elements.password.value.length < 8;
}

elements.addProfile.addEventListener("click", openProfileModal);
elements.addProfileSmall.addEventListener("click", openProfileModal);
document.querySelectorAll("[data-close-modal]").forEach((button) => button.addEventListener("click", closeProfileModal));
elements.token.addEventListener("input", validateForm);
elements.password.addEventListener("input", validateForm);
elements.togglePassword.addEventListener("click", () => {
  const visible = elements.password.type === "text";
  elements.password.type = visible ? "password" : "text";
  elements.togglePassword.textContent = visible ? "Показать" : "Скрыть";
});

elements.profileForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  elements.saveProfile.disabled = true;
  elements.saveProfile.textContent = "Расшифровываем…";
  elements.formError.classList.add("hidden");
  try {
    const profile = await invoke("import_profile", { token: elements.token.value.trim(), password: elements.password.value });
    closeProfileModal();
    await refreshProfiles(profile.id);
  } catch (error) {
    elements.formError.textContent = String(error);
    elements.formError.classList.remove("hidden");
  } finally {
    elements.saveProfile.textContent = "Добавить профиль";
    validateForm();
  }
});

elements.profiles.addEventListener("click", (event) => {
  const deleteControl = event.target.closest("[data-delete-id]");
  if (deleteControl) {
    event.stopPropagation();
    const profile = profiles.find((item) => item.id === deleteControl.dataset.deleteId);
    if (!profile) return;
    pendingDeleteId = profile.id;
    elements.deleteMessage.textContent = `Профиль «${profile.name}» и его ключи будут удалены с этого компьютера.`;
    elements.deleteModal.classList.remove("hidden");
    return;
  }
  const card = event.target.closest("[data-profile-id]");
  if (!card) return;
  selectedId = card.dataset.profileId;
  localStorage.setItem("mousevpn.selectedProfile", selectedId);
  renderProfiles();
});

elements.protocolMode.addEventListener("change", async () => {
  const profile = selectedProfile();
  if (!profile) return;
  elements.protocolMode.disabled = true;
  try {
    const updated = await invoke("set_profile_protocol", {
      id: profile.id,
      protocol: elements.protocolMode.value,
    });
    await refreshProfiles(updated.id);
  } catch (error) {
    renderProtocol();
    elements.protocolHint.textContent = `Не удалось сохранить режим: ${String(error)}`;
  }
});

elements.reliabilityDiagnostics.addEventListener("click", async () => {
  if (!selectedProfile() || isWindows) return;
  elements.reliabilityModal.classList.remove("hidden");
  elements.reliabilityRecommendation.textContent = "Собираем данные…";
  elements.reliabilityModes.innerHTML = "";
  try {
    await refreshReliability();
  } catch (error) {
    elements.reliabilityRecommendation.textContent = `Не удалось открыть диагностику: ${String(error)}`;
  }
});
elements.closeReliability.addEventListener("click", () => elements.reliabilityModal.classList.add("hidden"));
elements.clearReliability.addEventListener("click", async () => {
  const profile = selectedProfile();
  if (!profile || !window.confirm(`Сбросить статистику режимов для «${profile.name}»?`)) return;
  elements.clearReliability.disabled = true;
  try {
    renderReliability(await invoke("clear_reliability_diagnostics", { profileId: profile.id }));
  } catch (error) {
    elements.reliabilityRecommendation.textContent = `Не удалось очистить статистику: ${String(error)}`;
  } finally {
    elements.clearReliability.disabled = false;
  }
});

elements.cancelDelete.addEventListener("click", () => {
  pendingDeleteId = null;
  elements.deleteModal.classList.add("hidden");
});
elements.confirmDelete.addEventListener("click", async () => {
  if (!pendingDeleteId) return;
  elements.confirmDelete.disabled = true;
  try {
    await invoke("delete_profile", { id: pendingDeleteId });
    pendingDeleteId = null;
    elements.deleteModal.classList.add("hidden");
    await refreshProfiles();
  } catch (error) {
    elements.deleteMessage.textContent = String(error);
  } finally {
    elements.confirmDelete.disabled = false;
  }
});

elements.appExclusions.addEventListener("click", async () => {
  elements.appExclusionsError.classList.add("hidden");
  elements.appExclusionsModal.classList.remove("hidden");
  try {
    await refreshAppExclusions();
  } catch (error) {
    elements.appExclusionsError.textContent = String(error);
    elements.appExclusionsError.classList.remove("hidden");
  }
});
elements.closeAppExclusions.addEventListener("click", () => {
  closeInstalledApps();
  elements.appExclusionsModal.classList.add("hidden");
});
elements.openInstalledApps.addEventListener("click", openInstalledApps);
elements.closeInstalledApps.addEventListener("click", closeInstalledApps);
elements.cancelInstalledApps.addEventListener("click", closeInstalledApps);
elements.installedAppsSearch.addEventListener("input", renderInstalledApps);
elements.installedAppsList.addEventListener("change", (event) => {
  const checkbox = event.target.closest("[data-installed-app-id]");
  if (!checkbox) return;
  if (checkbox.checked) installedAppSelection.add(checkbox.dataset.installedAppId);
  else installedAppSelection.delete(checkbox.dataset.installedAppId);
  elements.installedAppsSelectionCount.textContent = `Выбрано: ${installedAppSelection.size}`;
});
elements.applyInstalledApps.addEventListener("click", async () => {
  elements.applyInstalledApps.disabled = true;
  elements.installedAppsError.classList.add("hidden");
  try {
    const selectedPaths = installedApps
      .filter((app) => installedAppSelection.has(app.id))
      .flatMap((app) => app.paths);
    const discoveredPaths = installedApps.flatMap((app) => app.paths);
    appRouting = await invoke("set_installed_app_selection", { selectedPaths, discoveredPaths });
    renderAppExclusions();
    closeInstalledApps();
  } catch (error) {
    elements.installedAppsError.textContent = String(error);
    elements.installedAppsError.classList.remove("hidden");
    elements.applyInstalledApps.disabled = false;
  }
});
elements.addAppExclusion.addEventListener("click", async () => {
  elements.addAppExclusion.disabled = true;
  elements.appExclusionsError.classList.add("hidden");
  try {
    const path = await invoke("choose_executable");
    if (path) {
      appRouting = await invoke("add_routed_app", { path });
      renderAppExclusions();
    }
  } catch (error) {
    elements.appExclusionsError.textContent = String(error);
    elements.appExclusionsError.classList.remove("hidden");
  } finally {
    elements.addAppExclusion.disabled = false;
  }
});
elements.appExclusionsList.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-exclusion-path]");
  if (!button) return;
  button.disabled = true;
  try {
    appRouting = await invoke("remove_routed_app", { path: button.dataset.exclusionPath });
    renderAppExclusions();
  } catch (error) {
    elements.appExclusionsError.textContent = String(error);
    elements.appExclusionsError.classList.remove("hidden");
    button.disabled = false;
  }
});

elements.appRoutingSearch.addEventListener("input", renderAppExclusions);
document.querySelectorAll('input[name="routingMode"]').forEach((radio) => {
  radio.addEventListener("change", async () => {
    if (!radio.checked) return;
    elements.appExclusionsError.classList.add("hidden");
    try {
      appRouting = await invoke("set_app_routing_mode", { mode: radio.value });
      renderAppExclusions();
    } catch (error) {
      elements.appExclusionsError.textContent = String(error);
      elements.appExclusionsError.classList.remove("hidden");
      renderAppExclusions();
    }
  });
});
elements.clearRoutedApps.addEventListener("click", async () => {
  elements.clearRoutedApps.disabled = true;
  elements.appExclusionsError.classList.add("hidden");
  try {
    appRouting = await invoke("clear_routed_apps");
    renderAppExclusions();
  } catch (error) {
    elements.appExclusionsError.textContent = String(error);
    elements.appExclusionsError.classList.remove("hidden");
    elements.clearRoutedApps.disabled = false;
  }
});

elements.autostartEnabled.addEventListener("change", async () => {
  const requested = elements.autostartEnabled.checked;
  elements.autostartEnabled.disabled = true;
  try {
    elements.autostartEnabled.checked = await invoke("set_autostart", { enabled: requested });
    elements.autostartSetting.title = "";
  } catch (error) {
    elements.autostartEnabled.checked = !requested;
    elements.autostartSetting.title = String(error);
  } finally {
    elements.autostartEnabled.disabled = false;
  }
});

elements.power.addEventListener("click", async () => {
  try {
    const next = ["connecting", "connected"].includes(connection.state)
      ? await invoke("disconnect")
      : await invoke("connect_profile", { id: selectedId });
    renderConnection(next);
  } catch (error) {
    renderConnection({ state: "error", message: String(error), profileId: selectedId });
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  if (!document.querySelector("#billingModal").classList.contains("hidden")) { document.querySelector("#billingModal").classList.add("hidden"); return; }
  if (!document.querySelector('#supportModal').classList.contains('hidden')) { document.querySelector('#supportModal').classList.add('hidden'); return; }
  if (!document.querySelector('#accountModal').classList.contains('hidden')) {
    document.querySelector('#accountModal').classList.add('hidden');
    return;
  }
  if (!elements.installedAppsModal.classList.contains("hidden")) {
    closeInstalledApps();
    return;
  }
  if (!elements.profileModal.classList.contains("hidden")) closeProfileModal();
  if (!elements.deleteModal.classList.contains("hidden")) elements.cancelDelete.click();
  if (!elements.reliabilityModal.classList.contains("hidden")) elements.closeReliability.click();
  if (!elements.appExclusionsModal.classList.contains("hidden")) elements.closeAppExclusions.click();
});

setInterval(async () => {
  try { renderConnection(await invoke("connection_status")); } catch (_) { /* retry on next tick */ }
}, 1000);

setInterval(async () => {
  if (isWindows || elements.reliabilityModal.classList.contains("hidden")) return;
  try { await refreshReliability(); } catch (_) { /* retry on next tick */ }
}, 5000);

setInterval(() => {
  if (!connectedAt) return;
  const elapsed = Math.floor((Date.now() - connectedAt) / 1000);
  const hours = Math.floor(elapsed / 3600);
  const minutes = Math.floor((elapsed % 3600) / 60);
  const seconds = elapsed % 60;
  elements.time.textContent = hours > 0
    ? `${hours}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`
    : `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}, 1000);

Promise.all([refreshProfiles(), refreshAppExclusions(), refreshAutostart(), invoke("connection_status").then(renderConnection)]).catch((error) => {
  renderConnection({ state: "error", message: String(error), profileId: null });
});

const settingsModal = document.querySelector('#settingsModal');
document.querySelector('#openSettings').onclick = () => settingsModal.classList.remove('hidden');
document.querySelector('#closeSettings').onclick = () => settingsModal.classList.add('hidden');
for (const id of ['addProfile', 'reliabilityDiagnostics', 'appExclusions']) {
  document.getElementById(id).addEventListener('click', () => settingsModal.classList.add('hidden'));
}
// Keep keyboard navigation inside the open dialog and restore focus on close.
const dialogOpeners = new WeakMap();
const dialogs = [...document.querySelectorAll('.modal-backdrop')];
const visibleDialogs = () => dialogs.filter(dialog => !dialog.classList.contains('hidden'));
const focusable = dialog => [...dialog.querySelectorAll('button, input, select, textarea, [tabindex="0"]')]
  .filter(control => !control.disabled && control.getClientRects().length);
for (const dialog of dialogs) {
  new MutationObserver(() => {
    document.querySelector('.app-shell').inert = visibleDialogs().length > 0;
    if (!dialog.classList.contains('hidden')) {
      if (!dialogOpeners.has(dialog)) {
        dialogOpeners.set(dialog, document.activeElement);
        (focusable(dialog)[0] || dialog).focus();
      }
    } else if (dialogOpeners.has(dialog)) {
      const opener = dialogOpeners.get(dialog); dialogOpeners.delete(dialog);
      if (!visibleDialogs().length) (opener?.getClientRects().length ? opener : document.querySelector('#openSettings')).focus();
    }
    document.querySelector('.app-shell').inert = visibleDialogs().length > 0;
  }).observe(dialog, { attributes: true, attributeFilter: ['class'] });
}
document.addEventListener('keydown', event => {
  if (event.key === 'Escape') settingsModal.classList.add('hidden');
  if (event.key !== 'Tab') return;
  const dialog = visibleDialogs().at(-1); if (!dialog) return;
  const controls = focusable(dialog); if (!controls.length) return;
  const first = controls[0], last = controls.at(-1);
  if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
  else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
});

function serverLoad(profile) {
  if (!profile?.managedUser) return 'Личный ключ';
  const server = accountView?.account?.servers?.find(s => s.id === profile.id);
  const fresh = server?.online_updated_at && Date.now()/1000 >= server.online_updated_at && Date.now()/1000 - server.online_updated_at <= 90;
  return fresh && Number.isInteger(server.online_devices) ? `${server.online_devices} устройств онлайн` : 'Онлайн: нет свежих данных';
}
