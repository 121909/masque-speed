"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const tokenKey = "masque-session-token";
  let token = "";
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  if (fragment.has("token")) {
    token = fragment.get("token") || "";
    try {
      if (token) sessionStorage.setItem(tokenKey, token);
      else sessionStorage.removeItem(tokenKey);
    } catch (_) { /* The in-memory token still works when browser storage is blocked. */ }
  } else {
    try { token = sessionStorage.getItem(tokenKey) || ""; } catch (_) { /* Use memory only. */ }
  }
  if (window.location.hash) history.replaceState(null, "", window.location.pathname + window.location.search);

  let endpoints = [];
  let regions = { country: {}, region: {}, city: {} };
  let selections = { country: new Set(), region: new Set(), city: new Set() };
  let state = { status: "idle", total: 0, tested: 0, qualified: 0, results: [], counts: {} };
  let initialized = false;
  let busy = false;
  let renderedResults = 0;
  let pollTimer = null;
  let stateEpoch = 0;
  let activeSettings = null;
  let pollError = false;
  const regionCheckboxes = [];
  const active = () => state.status === "running" || state.status === "stopping";
  const text = (tag, value, className) => {
    const element = document.createElement(tag);
    element.textContent = value;
    if (className) element.className = className;
    return element;
  };
  const number = (value) => Number.isFinite(Number(value)) ? Number(value) : 0;
  const displayNumber = (value, decimals = 0) => number(value).toLocaleString("zh-CN", { maximumFractionDigits: decimals });
  const address = (endpoint) => `${endpoint.ip.includes(":") ? `[${endpoint.ip}]` : endpoint.ip}:${endpoint.port}`;
  const selectedRegions = () => [...selections[$("region-level").value]];

  function showError(error) {
    $("global-error").textContent = error instanceof Error ? error.message : String(error);
    $("global-error").hidden = false;
  }
  function clearNotices() {
    $("global-error").hidden = true;
    $("global-message").hidden = true;
  }
  function showMessage(message) {
    $("global-message").textContent = message;
    $("global-message").hidden = false;
  }
  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set("X-Session-Token", token);
    const response = await fetch(path, { ...options, headers, credentials: "same-origin", cache: "no-store" });
    if (!response.ok) {
      let detail = "";
      const body = await response.text();
      try {
        const parsed = JSON.parse(body);
        detail = typeof parsed.error === "string" ? parsed.error : typeof parsed.message === "string" ? parsed.message : "";
      } catch (_) { detail = body; }
      const fallback = response.status === 401 || response.status === 403
        ? "会话令牌无效或已过期，请从本地程序重新打开控制台。"
        : response.status === 404 && path === "/api/credentials" ? "本机尚未保存凭据。" : `请求失败（HTTP ${response.status}）`;
      throw new Error(detail ? `${fallback}：${detail.slice(0, 2000)}` : fallback);
    }
    return response;
  }
  async function jsonAPI(path, options) {
    const response = await api(path, options);
    return response.json();
  }
  function jsonBody(value) {
    return { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(value) };
  }
  function readCredentials() {
    return {
      private_key: $("private-key").value.trim(),
      endpoint_pub_key: $("endpoint-pub-key").value.trim(),
      ipv4: $("ipv4").value.trim(),
      ipv6: $("ipv6").value.trim()
    };
  }
  function validateCredentials(credentials) {
    if (!credentials.private_key || !credentials.endpoint_pub_key) throw new Error("请填写 private_key 和 endpoint_pub_key，或从已注册 WARP 的 usque config.json 填入。");
  }
  function fillCredentials(credentials) {
    for (const key of ["private_key", "endpoint_pub_key", "ipv4", "ipv6"]) {
      if (credentials[key] !== undefined && typeof credentials[key] !== "string") throw new Error(`凭据中的 ${key} 必须是字符串。`);
    }
    $("private-key").value = credentials.private_key || "";
    $("endpoint-pub-key").value = credentials.endpoint_pub_key || "";
    $("ipv4").value = credentials.ipv4 || "172.16.0.2";
    $("ipv6").value = credentials.ipv6 || "";
    updateControls();
  }
  function updateControls() {
    const locked = !initialized || busy || active();
    for (const id of ["import-controls", "credential-controls", "settings-controls"]) $(id).disabled = locked;
    $("select-all-regions").disabled = locked || regionCheckboxes.length === 0;
    const credentials = readCredentials();
    $("start-run").disabled = locked || endpoints.length === 0 || selectedRegions().length === 0 || !credentials.private_key || !credentials.endpoint_pub_key;
    $("stop-run").disabled = busy || state.status !== "running";
    $("export-results").disabled = !initialized || busy || number(state.qualified) === 0;
    $("start-hint").textContent = active() ? "运行中已锁定导入、凭据和参数；可随时停止。" : !initialized ? "正在读取本地服务状态。" : endpoints.length === 0 ? "请先导入候选节点。" : selectedRegions().length === 0 ? "请至少选择一个地区后再开始。" : !credentials.private_key || !credentials.endpoint_pub_key ? "请填写 WARP private_key 和 endpoint_pub_key。" : "准备就绪，默认逐个测试候选节点。";
  }
  async function action(work) {
    if (busy) return;
    clearNotices();
    busy = true;
    updateControls();
    try { await work(); } catch (error) { showError(error); }
    finally { busy = false; updateControls(); }
  }
  function updateRegionSelection() {
    const selected = selectedRegions().length;
    $("select-all-regions").checked = regionCheckboxes.length > 0 && selected === regionCheckboxes.length;
    $("select-all-regions").indeterminate = selected > 0 && selected < regionCheckboxes.length;
    $("region-selection-summary").textContent = regionCheckboxes.length ? `已选 ${selected} / ${regionCheckboxes.length} 个地区` : "请先导入节点";
    $("region-error").hidden = endpoints.length === 0 || selected > 0;
    updateControls();
  }
  function renderRegions() {
    const level = $("region-level").value;
    const container = document.createDocumentFragment();
    regionCheckboxes.length = 0;
    const entries = Object.entries(regions[level] || {}).sort((a, b) => a[0].localeCompare(b[0], "zh-CN"));
    entries.forEach(([key, count]) => {
      const label = document.createElement("label");
      label.className = "region-option";
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.checked = selections[level].has(key);
      checkbox.addEventListener("change", () => {
        if (checkbox.checked) selections[level].add(key);
        else selections[level].delete(key);
        updateRegionSelection();
      });
      label.append(checkbox, text("span", key), text("span", displayNumber(count), "region-count"));
      regionCheckboxes.push(checkbox);
      container.append(label);
    });
    if (!entries.length) container.append(text("p", "导入后将在这里显示地区及节点数量。", "empty-hint"));
    $("region-options").replaceChildren(container);
    updateRegionSelection();
  }
  function updateQuotaDescription() {
    const target = $("target-count").value || "—";
    $("quota-description").textContent = $("quota-mode").value === "per_region"
      ? `每个所选地区各找到 ${target} 个达标节点后停止；某地区候选不足时将显示候选耗尽。`
      : `所选地区合计找到 ${target} 个达标节点后停止。`;
  }
  async function importEndpoints(body, filename) {
    if (active()) throw new Error("测试运行中不能导入，请先停止当前测试。");
    const imported = await jsonAPI(`/api/import?filename=${encodeURIComponent(filename)}`, {
      method: "POST", headers: { "Content-Type": "application/octet-stream" }, body
    });
    endpoints = imported.endpoints || [];
    regions = imported.regions || { country: {}, region: {}, city: {} };
    selections = Object.fromEntries(["country", "region", "city"].map((level) => [level, new Set(Object.keys(regions[level] || {}))]));
    $("import-count").textContent = `${displayNumber(endpoints.length)} 个节点`;
    $("import-status").textContent = `已导入 ${displayNumber(endpoints.length)} 个去重候选节点`;
    const warnings = Array.isArray(imported.warnings) ? imported.warnings : [];
    $("warning-list").replaceChildren(...warnings.map((warning) => text("li", String(warning))));
    $("import-warnings").hidden = warnings.length === 0;
    renderRegions();
    showMessage(endpoints.length ? "节点已导入，请确认地区选择和测试参数。" : "没有导入有效节点，请检查文件格式与导入提示。");
  }
  const numericFields = [
    ["max-latency", "max_latency_ms"], ["min-speed", "min_speed_mbps"], ["download-bytes", "download_bytes"],
    ["timeout", "timeout_seconds"], ["samples", "samples"], ["target-count", "target_count"]
  ];
  function readSettings() {
    const credentials = readCredentials();
    validateCredentials(credentials);
    const selected = selectedRegions();
    if (!selected.length) throw new Error("请至少选择一个地区；空选择不能开始测试。");
    const settings = {
      credentials, sni: $("sni").value.trim(), transport: $("transport").value,
      region_level: $("region-level").value, regions: selected, quota_mode: $("quota-mode").value
    };
    if (!settings.sni) { $("sni").focus(); throw new Error("请填写 SNI。"); }
    for (const [id, key] of numericFields) {
      const input = $(id);
      if (!input.reportValidity() || !Number.isFinite(input.valueAsNumber) || (key === "min_speed_mbps" ? input.valueAsNumber < 0 : input.valueAsNumber <= 0) || (input.step === "1" && !Number.isSafeInteger(input.valueAsNumber))) {
        input.focus();
        throw new Error(`请为“${input.labels[0].textContent.trim()}”填写有效的${key === "min_speed_mbps" ? "非负数" : input.step === "1" ? "正整数" : "正数"}。`);
      }
      settings[key] = input.valueAsNumber;
    }
    return settings;
  }
  const attemptStatuses = { success: "速度未达标", error: "测试错误", rejected: "延迟未达标" };
  function appendResults(results) {
    if (results.length < renderedResults) {
      $("result-rows").replaceChildren();
      renderedResults = 0;
    }
    if (results.length === renderedResults) return;
    const fragment = document.createDocumentFragment();
    for (let index = renderedResults; index < results.length; index++) {
      const result = results[index];
      const endpointCell = document.createElement("td");
      endpointCell.className = "endpoint-cell";
      endpointCell.append(text("code", address(result.endpoint), "endpoint-address"));
      endpointCell.append(text("span", [result.endpoint.country, result.endpoint.region, result.endpoint.city].filter(Boolean).join(" / ") || result.region_key || "未知地区", "endpoint-region"));
      endpointCell.append(text("span", result.qualified ? "达标节点" : "未达标", result.qualified ? "result-badge pass" : "result-badge fail"));
      const attempts = Array.isArray(result.attempts) && result.attempts.length ? result.attempts : [null];
      endpointCell.rowSpan = attempts.length;
      attempts.forEach((attempt, attemptIndex) => {
        const row = document.createElement("tr");
        if (attemptIndex === 0) row.append(endpointCell);
        const cells = Array.from({ length: 4 }, () => document.createElement("td"));
        if (attempt) {
          const transport = attempt.transport === "tcp" ? "TCP / HTTP/2" : attempt.transport === "udp" ? "UDP / QUIC" : attempt.transport;
          cells[0].append(text("div", transport || "—", "attempt-value"));
          cells[1].append(text("div", number(attempt.latency_ms) > 0 ? `${displayNumber(attempt.latency_ms, 2)} ms` : "—", "attempt-value tabular"));
          cells[2].append(text("div", number(attempt.download_bytes) > 0 || number(attempt.speed_mbps) > 0 ? `${displayNumber(attempt.speed_mbps, 2)} Mbps` : "—", "attempt-value tabular"));
          const status = text("div", "", "attempt-value attempt-status");
          status.append(text("span", attempt.qualified ? "达标" : attemptStatuses[attempt.status] || attempt.status || "未达标", attempt.qualified ? "status-pass" : "status-fail"));
          if (attempt.error) status.append(text("span", attempt.error, "attempt-error"));
          if (attempt.egress_ip) status.append(text("span", `出口 ${attempt.egress_ip}`, "attempt-egress"));
          cells[3].append(status);
        } else {
          cells[0].append(text("span", "—"));
          cells[1].append(text("span", "—"));
          cells[2].append(text("span", "—"));
          cells[3].append(text("span", "未产生传输测量记录", "muted"));
        }
        row.append(...cells);
        fragment.append(row);
      });
    }
    $("result-rows").append(fragment);
    renderedResults = results.length;
    $("results-empty").hidden = results.length > 0;
  }
  function renderQuotaProgress() {
    const counts = state.counts || {};
    const keys = activeSettings ? activeSettings.regions : Object.keys(counts);
    $("quota-progress-wrap").hidden = keys.length === 0;
    const fragment = document.createDocumentFragment();
    for (const key of keys) {
      const row = text("div", "", "quota-row");
      const target = activeSettings && activeSettings.quota_mode === "per_region" ? activeSettings.target_count : null;
      row.append(text("span", key), text("strong", `${displayNumber(counts[key])}${target ? ` / ${displayNumber(target)}` : " 个"}`));
      if (target && number(counts[key]) >= target) row.classList.add("quota-met");
      fragment.append(row);
    }
    $("quota-progress").replaceChildren(fragment);
  }
  function renderState(next, reset = false) {
    state = next;
    if (reset) {
      $("result-rows").replaceChildren();
      renderedResults = 0;
      $("results-empty").hidden = false;
    }
    const labels = { idle: "待开始", running: "测试中", stopping: "正在停止", completed: "已完成", stopped: "已停止", error: "运行错误" };
    $("run-status").textContent = labels[state.status] || state.status || "未知状态";
    $("run-status").className = `status-badge ${active() ? "is-active" : state.status === "error" ? "is-error" : ""}`;
    $("tested-count").textContent = displayNumber(state.tested);
    $("total-count").textContent = displayNumber(state.total);
    $("qualified-count").textContent = displayNumber(state.qualified);
    $("run-progress").max = Math.max(1, number(state.total));
    $("run-progress").value = number(state.tested);
    $("current-endpoint").textContent = state.current || "—";
    const reasons = {
      target_reached: "已达到达标配额，测试自动结束。",
      exhausted: "候选节点已耗尽；请对照达标数量确认目标是否完成。",
      user: "用户已停止测试；已完成的结果仍可导出。"
    };
    const descriptions = {
      idle: "尚未开始测试。", running: "正在串行测试候选节点…", stopping: "正在取消当前测量，请稍候…",
      completed: "测试已完成。", stopped: "测试已停止。", error: "测试发生错误。"
    };
    $("run-description").textContent = state.error ? `运行错误：${state.error}` : reasons[state.stop_reason] || (state.stop_reason ? `测试结束：${state.stop_reason}` : descriptions[state.status] || "");
    appendResults(state.results || []);
    renderQuotaProgress();
    updateControls();
  }
  function schedulePoll() {
    window.clearTimeout(pollTimer);
    if (!active()) return;
    pollTimer = window.setTimeout(pollState, 1000);
  }
  async function pollState() {
    const epoch = stateEpoch;
    try {
      const next = await jsonAPI("/api/state");
      if (epoch !== stateEpoch) return;
      if (pollError) { $("global-error").hidden = true; pollError = false; }
      renderState(next);
    } catch (error) {
      if (epoch !== stateEpoch) return;
      pollError = true;
      showError(new Error(`状态更新失败，将继续重试。${error.message}`));
    }
    if (epoch === stateEpoch) schedulePoll();
  }

  $("endpoint-file").addEventListener("change", () => {
    const file = $("endpoint-file").files[0];
    if (!file) return;
    action(async () => {
      try { await importEndpoints(file, file.name); }
      finally { $("endpoint-file").value = ""; }
    });
  });
  $("import-text").addEventListener("click", () => action(async () => {
    const body = $("endpoint-text").value.trim();
    if (!body) throw new Error("请先粘贴节点内容。");
    await importEndpoints(body, "pasted.txt");
  }));
  $("config-file").addEventListener("change", () => {
    const file = $("config-file").files[0];
    if (!file) return;
    action(async () => {
      try {
        let config;
        try { config = JSON.parse((await file.text()).replace(/^\uFEFF/, "")); }
        catch (_) { throw new Error("无法读取 config.json，请选择有效的 usque JSON 配置。"); }
        if (!config || typeof config !== "object" || Array.isArray(config) || !config.private_key || !config.endpoint_pub_key) throw new Error("配置缺少 private_key 或 endpoint_pub_key；请使用已注册 WARP 的 usque 配置，而非 WireGuard 配置。");
        fillCredentials(config);
        showMessage("已从配置填入四项凭据字段；未保存到本机，也未导入其他配置项。");
      } finally { $("config-file").value = ""; }
    });
  });
  $("toggle-private-key").addEventListener("click", () => {
    const revealed = $("toggle-private-key").getAttribute("aria-pressed") !== "true";
    $("private-key").classList.toggle("secret-input", !revealed);
    $("toggle-private-key").setAttribute("aria-pressed", String(revealed));
    $("toggle-private-key").textContent = revealed ? "隐藏私钥" : "显示私钥";
  });
  for (const id of ["private-key", "endpoint-pub-key"]) $(id).addEventListener("input", updateControls);
  $("save-credentials").addEventListener("click", () => action(async () => {
    const credentials = readCredentials();
    validateCredentials(credentials);
    if (!window.confirm("确认将 WARP 私钥等凭据保存到本机服务的凭据文件？文件包含敏感密钥，可被拥有该文件读取权限的人访问。仅在信任这台设备时继续。")) return;
    await api("/api/credentials", jsonBody(credentials));
    showMessage("凭据已按你的明确操作保存到本机。可随时使用“删除已保存凭据”移除。");
  }));
  $("load-credentials").addEventListener("click", () => action(async () => {
    fillCredentials(await jsonAPI("/api/credentials"));
    showMessage("已读取本机保存的凭据，当前表单内容已替换。");
  }));
  $("delete-credentials").addEventListener("click", () => action(async () => {
    if (!window.confirm("确认删除本机保存的凭据文件？当前表单中的凭据不会被清空。")) return;
    await api("/api/credentials", { method: "DELETE" });
    showMessage("本机保存的凭据已删除；当前表单未清空，不会自动重新保存。");
  }));
  $("region-level").addEventListener("change", renderRegions);
  $("select-all-regions").addEventListener("change", () => {
    const level = $("region-level").value;
    const checked = $("select-all-regions").checked;
    selections[level] = checked ? new Set(Object.keys(regions[level] || {})) : new Set();
    renderRegions();
  });
  $("quota-mode").addEventListener("change", updateQuotaDescription);
  $("target-count").addEventListener("input", updateQuotaDescription);
  $("start-run").addEventListener("click", () => {
    if (busy) return;
    clearNotices();
    let settings;
    try {
      if (active()) throw new Error("当前测试尚未结束。");
      if (!endpoints.length) throw new Error("请先导入候选节点。");
      settings = readSettings();
    } catch (error) { showError(error); return; }
    action(async () => {
      stateEpoch++;
      window.clearTimeout(pollTimer);
      const next = await jsonAPI("/api/start", jsonBody({ endpoints, settings }));
      // Keep only non-secret quota settings for the run display, never a second credential copy.
      activeSettings = { regions: settings.regions, quota_mode: settings.quota_mode, target_count: settings.target_count };
      renderState(next, true);
      schedulePoll();
    });
  });
  $("stop-run").addEventListener("click", () => action(async () => {
    stateEpoch++;
    window.clearTimeout(pollTimer);
    try { renderState(await jsonAPI("/api/stop", jsonBody({}))); }
    finally { schedulePoll(); }
  }));
  $("export-results").addEventListener("click", () => action(async () => {
    const response = await api("/api/export");
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement("a");
    link.href = url;
    link.download = `masque-qualified-${new Date().toISOString().replace(/[:.]/g, "-")}.csv`;
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    showMessage("已导出达标节点 CSV。");
  }));
  window.addEventListener("pagehide", () => window.clearTimeout(pollTimer));
  window.addEventListener("pageshow", (event) => { if (event.persisted) schedulePoll(); });

  async function initialize() {
    updateControls();
    try { renderState(await jsonAPI("/api/state")); }
    catch (error) {
      showError(error);
      $("run-status").textContent = "未连接";
      $("run-description").textContent = "未能读取运行状态，请检查本地程序与会话令牌后刷新页面。";
    } finally {
      initialized = true;
      updateControls();
      schedulePoll();
    }
  }
  initialize();
})();
