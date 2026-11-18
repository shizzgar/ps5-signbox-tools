(() => {
  "use strict";
  const element = (id) => document.getElementById(id);
  const login = element("login-view");
  const controls = element("controls");
  const input = element("pin");
  const filter = element("process-filter");
  const list = element("process-list");
  const log = element("log");
  const messages = element("panel-message");
  const start = element("start");
  const orbit = element("orbit");
  const stop = element("stop");
  const check = element("check");
  const egress = element("egress");
  const webview = element("webview");
  const diagnostics = element("diagnostics");
  const downloadDiagnostics = element("download-diagnostics");
  const download = element("download");
  const restart = element("restart");
  const refresh = element("refresh");
  const close = element("close-panel");
  let token = "";
  let processes = [];
  let selected = "";
  let processLoading = false;
  let state = "idle";
  let proxy = "starting";
  let webviewStatus = "idle";
  let webviewRoute = "off";
  let initial = true;
  let pending = false;
  let online = false;
  let localError = "";
  let snapshotError = "";
  let logContent = "";
  let statusRevision = 0;
  let statusTimer;
  let logTimer;

  const errors = {
    auth: "Введи код нового сеанса.",
    pin: "Код не подошёл. Проверь уведомление на PS5.",
    wait: "Подожди несколько секунд и повтори попытку.",
    proxy: "sing-box недоступен. Проверь журнал и перезапусти sing-box.",
    loader: "Локальный ELF-загрузчик недоступен. Проверь запуск ELF через Payload Manager и нажми «Перезапустить sing-box».",
    check: "Самотест не прошёл. Подробности в журнале.",
    diagnostics: "Перехват WebView не запустился. Скачай отчёт диагностики.",
    egress: "HTTPS-проверка не прошла. Подробности в журнале.",
    download: "Проверка загрузки не прошла. Подробности в журнале.",
    orbit_unreachable: "Orbit не отвечает на порту 34177. Запусти сервис Orbit и проверь, что приложение открывается.",
    orbit_unidentified: "Orbit отвечает, но его PID не удалось определить. Посмотри журнал запуска Orbit.",
    orbit_ambiguous: "Найдено несколько процессов с портом Orbit. Проверь, какая копия сервиса запущена.",
    orbit_stalled: "Orbit перестал отвечать. Панель отключила перенаправление.",
    orbit_image: "Файлы Orbit из кэша и приложения не подошли запущенному сервису. Подробности в диагностике.",
    orbit_live: "Не удалось подключить перехват к запущенному Orbit. Подробности в диагностике.",
    orbit_use_button: "Для сервиса Orbit используй «Orbit и WebView через VPN».",
    webview_not_ready: "Дождись перехвата WebView в режиме Orbit или диагностики.",
    trace: "Перехват завершился с ошибкой. Подробности в журнале.",
    target: "Процесс изменился или завершился. Обнови список и выбери его снова.",
    busy: "Уже выполняется операция. Дождись завершения или останови её.",
    processes: "Не удалось получить список процессов. Нажми «Обновить список процессов».",
    log: "Не удалось прочитать журнал.",
    offline: "Связь с панелью потеряна. Проверь, запущен ли ELF на PS5.",
  };

  function message(place, text = "", error = false) {
    if (place.textContent !== text) place.textContent = text;
    place.dataset.kind = error ? "error" : "";
  }

  function loginView(reason = "") {
    token = "";
    statusRevision++;
    online = false;
    try { sessionStorage.removeItem("relay-token"); } catch (_) {}
    clearTimeout(statusTimer);
    clearTimeout(logTimer);
    element("loading").hidden = true;
    controls.hidden = true;
    close.hidden = true;
    login.hidden = false;
    input.value = "";
    message(element("login-message"), reason, Boolean(reason));
    input.focus();
  }

  function updateButtons() {
    const running = state !== "idle";
    const available = !pending && !running && online && proxy === "ready";
    const tracing = state === "active" || state === "starting";
    list.disabled = running || processLoading || !online;
    filter.disabled = list.disabled;
    start.disabled = !available || !list.value;
    start.hidden = tracing || state === "stopping";
    orbit.disabled = !available;
    orbit.hidden = tracing || state === "stopping";
    [check, egress, download].forEach((button) => { button.disabled = !available; });
    diagnostics.disabled = !available;
    downloadDiagnostics.disabled = !online;
    webview.disabled = pending || !online || proxy !== "ready" || state !== "active" ||
      !["waiting", "armed", "error"].includes(webviewRoute) || webviewStatus === "opening";
    restart.disabled = pending || running || !online || proxy === "starting";
    stop.hidden = !running;
    stop.disabled = pending || !online || state === "stopping";
    close.disabled = pending || !online || state !== "idle";
    refresh.disabled = processLoading || running || !online;
  }

  async function api(path, body) {
    const request = new AbortController();
    const timeout = setTimeout(() => request.abort(), 5500);
    let result;
    try {
      result = await fetch(path, {
        method: body === undefined ? "GET" : "POST",
        headers: {"X-Relay-Panel": "1", "X-Relay-Token": token},
        body,
        cache: "no-store",
        signal: request.signal,
      });
    } catch (_) {
      throw new Error(errors.offline);
    } finally {
      clearTimeout(timeout);
    }
    if (!result.ok) {
      let name = "";
      try { name = (await result.json()).error; } catch (_) {}
      if (result.status === 401 && path !== "/api/login" && token) {
        initial = true;
        loginView(errors.auth);
      }
      throw new Error(errors[name] || "Панель отклонила запрос. Повтори попытку.");
    }
    const textReply = body === undefined && ["/api/log", "/api/diagnostics"].includes(path);
    return textReply ? result.text() : result.json();
  }

  function renderStatus(snapshot) {
    state = snapshot.state;
    proxy = snapshot.proxy;
    webviewStatus = snapshot.webview;
    webviewRoute = snapshot.webview_route;
    const status = element("status");
    status.dataset.state = state;
    const statusText = snapshot.diagnosing && state === "starting" ? "Диагностика…" : {
      idle: "Ожидание", starting: "Подключаюсь",
      active: snapshot.orbit_route === "unavailable" ? "Работает только WebView" : "Перехват активен",
      checking: "Проверка", restarting: "Запуск sing-box", stopping: "Остановка",
    }[state] || "Ожидание";
    if (element("status-text").textContent !== statusText) element("status-text").textContent = statusText;
    const proxyValue = element("proxy-value");
    proxyValue.dataset.result = {ready: "pass", error: "fail"}[proxy] || "";
    message(proxyValue, {ready: "Запущен", starting: "Запускается…", off: "Остановлен", error: "Ошибка запуска"}[proxy] || "—");
    for (const key of ["check", "egress", "download"]) {
      const value = element(key + "-value");
      value.dataset.result = snapshot[key];
      message(value, {ready: "—", running: "Выполняется…", pass: "Пройдено", fail: "Ошибка"}[snapshot[key]] || "—");
    }
    const webviewValue = element("webview-value");
    webviewValue.dataset.result = webviewStatus === "error" ? "fail" : "";
    message(webviewValue, {opening: "Открывается…", launched: "Проверь IP на PS5", error: "Сбой запуска"}[webviewStatus] || "—");
    const routeValue = element("webview-route");
    routeValue.dataset.result = ["unavailable", "error"].includes(webviewRoute) ? "fail" : "";
    message(routeValue, {
      checking: "Самотест…", waiting: "Ожидает сетевой процесс", armed: "Перехват установлен",
      unavailable: "Перехват недоступен", error: "Ошибка подключения к процессу",
    }[webviewRoute] || "—");
    const activeProcess = snapshot.name ? snapshot.name + " · PID " + snapshot.pid : "";
    const diagnosticMessage = state === "active" ? "Открой окно провайдера на PS5, затем скачай диагностику."
      : "Проверяю выделение памяти WebView и загрузчик ELF.";
    message(element("target-view"), snapshot.diagnosing ? diagnosticMessage : activeProcess ||
      "Режим подключает загрузчик Orbit и проверяет перехват WebView. Системный прокси PS5 оставь выключенным.");
    updateButtons();
  }

  async function updateStatus() {
    clearTimeout(statusTimer);
    if (!token) return;
    const revision = ++statusRevision;
    try {
      const snapshot = await api("/api/status");
      if (!token || revision !== statusRevision) return;
      online = true;
      element("loading").hidden = true;
      login.hidden = true;
      controls.hidden = false;
      close.hidden = false;
      const oldState = state;
      renderStatus(snapshot);
      snapshotError = errors[snapshot.error] || (proxy === "error" ? errors.proxy : "");
      message(messages, localError || snapshotError, Boolean(localError || snapshotError));
      if (initial) {
        initial = false;
        element("main-title").focus();
        refreshProcesses();
        updateLog();
      } else if (oldState !== "idle" && state === "idle") {
        refreshProcesses();
      }
    } catch (_) {
      if (!token || revision !== statusRevision) return;
      online = false;
      element("loading").hidden = true;
      if (initial) loginView(errors.offline);
      else {
        element("status").dataset.state = "offline";
        element("status-text").textContent = "Нет связи";
        message(messages, errors.offline, true);
        updateButtons();
      }
    } finally {
      if (token && revision === statusRevision) statusTimer = setTimeout(updateStatus, 1000);
    }
  }

  function renderProcesses() {
    const query = filter.value.trim().toLocaleLowerCase();
    const visible = processes.filter((process) => (process.name + " " + process.pid).toLocaleLowerCase().includes(query));
    list.replaceChildren();
    visible.forEach((process) => {
      list.add(new Option(process.name + " · PID " + process.pid, process.id));
    });
    list.value = selected;
    setProcessHint();
    updateButtons();
  }

  function setProcessHint() {
    const text = list.options.length ? "Выбери процесс приложения перед новой загрузкой." :
      (filter.value.trim() ? "Совпадений нет." : "Запусти приложение и обнови список.");
    if (element("process-help").textContent !== text) element("process-help").textContent = text;
  }

  async function refreshProcesses() {
    if (processLoading || !token) return;
    processLoading = true;
    element("process-help").textContent = "Загружаю список процессов…";
    updateButtons();
    try {
      processes = await api("/api/processes");
      if (!processes.some((process) => process.id === selected)) selected = "";
      renderProcesses();
    } catch (error) {
      if (token) element("process-help").textContent = error.message || errors.processes;
    } finally {
      processLoading = false;
      updateButtons();
    }
  }

  async function updateLog() {
    clearTimeout(logTimer);
    if (!token) return;
    try {
      const text = await api("/api/log");
      if (text !== logContent) {
        const atEnd = log.scrollHeight - log.scrollTop - log.clientHeight < 28;
        logContent = text;
        log.textContent = text || "Журнал пока пуст.";
        if (atEnd) log.scrollTop = log.scrollHeight;
      }
    } catch (_) {
      if (!logContent) log.textContent = errors.log;
    } finally {
      if (token) logTimer = setTimeout(updateLog, 1800);
    }
  }

  async function action(path, body = "") {
    pending = true;
    localError = "";
    snapshotError = "";
    updateButtons();
    message(messages);
    try {
      await api(path, body);
      if (path === "/api/close") {
        token = "";
        statusRevision++;
        try { sessionStorage.removeItem("relay-token"); } catch (_) {}
        clearTimeout(statusTimer);
        clearTimeout(logTimer);
        controls.hidden = true;
        close.hidden = true;
        element("closed-view").hidden = false;
        element("closed-view").querySelector("h1").focus();
      } else {
        await updateStatus();
      }
    } catch (error) {
      if (token) {
        localError = error.message || errors.offline;
        message(messages, localError, true);
      }
    } finally {
      pending = false;
      updateButtons();
    }
  }

  element("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = element("sign-in");
    button.disabled = true;
    message(element("login-message"), "Проверяю код…");
    try {
      token = (await api("/api/login", input.value.trim())).token;
      try { sessionStorage.setItem("relay-token", token); } catch (_) {}
      input.value = "";
      await updateStatus();
    } catch (error) {
      message(element("login-message"), error.message || errors.offline, true);
      input.select();
    } finally {
      button.disabled = false;
    }
  });
  element("show-code").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      await api("/api/show-code", "");
      message(element("login-message"), "Код снова показан на PS5.");
      input.focus();
    } catch (error) {
      message(element("login-message"), error.message, true);
    } finally {
      button.disabled = false;
    }
  });
  filter.addEventListener("input", renderProcesses);
  list.addEventListener("change", () => { selected = list.value; updateButtons(); });
  refresh.addEventListener("click", () => {
    localError = "";
    message(messages, snapshotError, Boolean(snapshotError));
    refreshProcesses();
  });
  start.addEventListener("click", () => { if (list.value) action("/api/start", list.value); });
  orbit.addEventListener("click", () => action("/api/orbit"));
  stop.addEventListener("click", () => action("/api/stop"));
  check.addEventListener("click", () => action("/api/check"));
  diagnostics.addEventListener("click", () => action("/api/diagnostics"));
  egress.addEventListener("click", () => action("/api/egress"));
  webview.addEventListener("click", () => action("/api/webview"));
  download.addEventListener("click", () => action("/api/download"));
  restart.addEventListener("click", () => action("/api/restart"));
  close.addEventListener("click", () => action("/api/close"));
  async function downloadText(path, filename) {
    try {
      const contents = await api(path);
      const url = URL.createObjectURL(new Blob([contents], {type: "text/plain;charset=utf-8"}));
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
      if (token) message(messages, error.message || errors.log, true);
    }
  }
  element("download-log").addEventListener("click", () => downloadText("/api/log", "tcp-relay.log"));
  downloadDiagnostics.addEventListener("click", () => downloadText("/api/diagnostics", "diagnostics.txt"));

  async function openSession() {
    // The server checks the socket peer; a LAN client cannot opt into local access.
    try {
      const session = await api("/api/local-session");
      token = session.token;
      try { sessionStorage.setItem("relay-token", token); } catch (_) {}
    } catch (_) {
      try { token = sessionStorage.getItem("relay-token") || ""; } catch (_) {}
    }
    if (token) updateStatus();
    else loginView();
  }
  openSession();
})();
