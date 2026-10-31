const { createApp, ref, reactive, onMounted, onUnmounted, computed, watch } = Vue;

createApp({
  setup() {
    const page = ref('dashboard');
    const token = ref(localStorage.getItem('s5m_next_token') || '');
    const loginUser = ref('admin');
    const loginPass = ref('');
    const loggingIn = ref(false);
    const currentUser = ref(localStorage.getItem('s5m_next_user') || '');
    const pwdDialog = ref(false);
    const pwdSaving = ref(false);
    const pwdForm = reactive({ old: '', new: '', confirm: '' });

    const overview = ref({});
    const traffic = ref({ up: 0, down: 0, conns: 0 });
    const realtimeStatus = ref('disconnected');
    let browserEventsSocket = null;
    let browserEventsRetryTimer = null;
    let browserEventsStopped = false;
    let browserEventsConnecting = false;
    let browserEventsGeneration = 0;
    let staleStatusTimer = null;
    const browserWSRequests = new Map();
    let overviewTimer = null;
    const proxies = ref([]);
    const loadingProxies = ref(false);

    const newMachineCode = ref('');
    const generatedToken = ref('');
    const generating = ref(false);
    const agentEntries = ref([]);
    const agentLoadError = ref('');
    const agentLoading = ref(false);
    const agentSearch = ref('');
    const agentStatusFilter = ref('all');
    const filteredAgentEntries = computed(() => {
      const query = String(agentSearch.value || '').trim().toLowerCase();
      return agentEntries.value.filter(item => {
        const matchesQuery = !query || [item.code, item.hostname, item.os, item.arch].some(value => String(value || '').toLowerCase().includes(query));
        const matchesStatus = agentStatusFilter.value === 'all'
          || (agentStatusFilter.value === 'online' && item.online)
          || (agentStatusFilter.value === 'offline' && !item.online);
        return matchesQuery && matchesStatus;
      });
    });
    const subUrl = ref('');
    const retryingNodeConfigSync = ref(false);
    const configYaml = ref('');
    const configTunEnabled = ref(false);
    const configDnsEnabled = ref(false);
    const configDnsNameservers = ref('');
    const selectedConfigNode = ref('');
    const savingConfig = ref(false);
    const smartdnsYaml = ref('');
    const loadingSmartDNS = ref(false);
    const applyingSmartDNS = ref(false);
    const smartdnsResult = ref('');
    const smartdnsStatus = ref({ available:false, running:false, dnsHealthy:false, version:'', configHash:'', lastError:'' });
    let smartdnsLoadGeneration = 0;
    let smartdnsApplyGeneration = 0;
    watch(selectedConfigNode, () => {
      smartdnsLoadGeneration++;
      smartdnsApplyGeneration++;
      applyingSmartDNS.value = false;
      loadingSmartDNS.value = false;
      smartdnsYaml.value = '';
      smartdnsResult.value = '';
      smartdnsStatus.value = { available:false, running:false, dnsHealthy:false, version:'', configHash:'', lastError:'' };
    });
    let nodeConfigLoadGeneration = 0;
    const publishing = ref(false);
    const updatingKernel = ref(false);
    const kernelUpdateDialog = ref(false);
    const kernelUpdateMachineCode = ref('');
    const kernelUpdateVersion = ref('');
    const kernelUpdateSHA256 = ref('');
    const kernelUpdateInfo = ref(null);
    const kernelUpdateInfoLoading = ref(false);
    const queueingKernelUpdate = ref(false);
    const systemLogs = ref('');
    const mainMihomoStatus = ref({ loading: false, version: '未知', service: 'unknown', online: false, binary_path: '/opt/mihomo/mihomo' });
    const loadingSystemLogs = ref(false);
    const restoringBackup = ref(false);

    const proxyDialog = ref(false);
    const proxyForm = reactive({ id: 0, name: '', mode: 'return', type: 'socks5', server: '', port: 1080, machine_code: '', source_cidr: '0.0.0.0/0', enabled: true, username: '', password: '', extra_json: '{}' });
    const savingProxy = ref(false);

    const showImport = ref(false);
    const importTab = ref('text');
    const importText = ref('');
    const importing = ref(false);
    const importMachineCode = ref('');

    // ======== 分组管理逻辑 ========
    const activeGroup = ref('ALL');
    
    // 获取所有存在的机器码（从已注册的 Agent 和 现有代理节点中提取）
    // 绑定下拉框保留所有已注册 Agent；代理分组只显示当前确实有代理的机器码。
    const availableMachineCodes = computed(() => {
      const set = new Set();
      agentEntries.value.forEach(a => { if (a.code) set.add(a.code); });
      proxies.value.forEach(p => { if (p.machine_code && p.machine_code !== '__GLOBAL__') set.add(p.machine_code); });
      return Array.from(set).sort();
    });
    const proxyGroupCodes = computed(() => Array.from(new Set(
      proxies.value.map(p => p.machine_code).filter(Boolean)
    )).sort());
    const agentEntryByCode = computed(() => {
      const map = {};
      agentEntries.value.forEach(item => { if (item && item.code) map[item.code] = item; });
      return map;
    });
    const machineCodeOptionLabel = (code) => {
      const item = agentEntryByCode.value[code];
      if (!item) return code + '（未注册/待核对）';
      return code + (item.hostname ? ' · ' + item.hostname : '') + (item.online ? '（在线）' : '（离线）');
    };
    const machineCodeStatus = (code) => {
      const item = agentEntryByCode.value[code];
      if (!item) return '未找到已授权的节点实例';
      return (item.online ? '在线' : '离线') + (item.hostname ? ' · ' + item.hostname : '');
    };
    const proxyCountForMachine = (code) => {
      const machineCode = String(code || '').trim();
      return proxies.value.filter(p => String(p.machine_code || '').trim() === machineCode).length;
    };
    // Do not infer whether a dedicated YAML exists from the proxy count.
    // The node-config GET endpoint may initialize a default YAML on first access.
    const nodeConfigState = () => '可在配置管理中查看/编辑';
    const openProxiesForMachine = (code) => {
      activeGroup.value = code;
      switchPage('proxies');
    };
    const openNodeConfigForMachine = async (code) => {
      selectedConfigNode.value = code;
      switchPage('config');
      await loadNodeConfig();
    };

    const filteredProxies = computed(() => {
      if (activeGroup.value === 'ALL') return proxies.value;
      if (activeGroup.value === 'UNBOUND') return proxies.value.filter(p => !p.machine_code);
      return proxies.value.filter(p => String(p.machine_code || '').trim() === String(activeGroup.value || '').trim());
    });

    const getUnboundCount = () => proxies.value.filter(p => !p.machine_code).length;
    const getMachineCount = (code) => {
      const machineCode = String(code || '').trim();
      return proxies.value.filter(p => String(p.machine_code || '').trim() === machineCode).length;
    };
    // =============================

    // Normalize upstream Mihomo version strings before the UI adds its display prefix.
    // Accept plain versions and repeated v/V prefixes without rendering vv1.19.33.
    const normalizeMihomoVersion = (value) => {
      return String(value || '').trim().replace(/^(?:v)+/i, '');
    };

    const fmtBytes = (n) => {
      n = Number(n) || 0;
      if (n < 1024) return n + ' B';
      const units = ['KB','MB','GB','TB'];
      let i = -1;
      do { n /= 1024; i++; } while (n >= 1024 && i < units.length - 1);
      return n.toFixed(2) + ' ' + units[i];
    };

    const fmtSpeed = (n) => {
      n = Math.max(0, Number(n) || 0);
      if (n < 1024) return n.toFixed(0) + ' B/s';
      if (n < 1024 * 1024) return (n / 1024).toFixed(2) + ' KB/s';
      if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(2) + ' MB/s';
      return (n / (1024 * 1024 * 1024)).toFixed(2) + ' GB/s';
    };

    const authHeaders = (extra) => Object.assign({ 'Authorization': 'Bearer ' + token.value }, extra || {});
    const showMsg = (msg, type) => { ElementPlus.ElMessage({ message: msg, type: type || 'info', duration: 3000 }); };

    async function api(path, opts) {
      opts = opts || {};
      opts.headers = authHeaders(opts.headers || {});
      const res = await fetch(path, opts);
      if (res.status === 401) { logout(); throw new Error('登录已失效'); }
      return res;
    }

    async function parseErr(res) {
      try { const d = await res.json(); return d.error || d.message || ('HTTP ' + res.status); }
      catch (e) { return 'HTTP ' + res.status; }
    }

    const sendBrowserWSControl = (payload) => new Promise((resolve, reject) => {
      const socket = browserEventsSocket;
      if (!socket || socket.readyState !== WebSocket.OPEN || realtimeStatus.value !== 'connected') {
        reject(new Error('实时通道未连接；请等待 WebSocket 恢复后重试'));
        return;
      }
      const requestId = (window.crypto && typeof window.crypto.randomUUID === 'function')
        ? window.crypto.randomUUID()
        : String(Date.now()) + '-' + Math.random().toString(16).slice(2);
      const timeout = setTimeout(() => {
        browserWSRequests.delete(requestId);
        reject(new Error('实时操作等待超时，请刷新节点状态后确认任务是否已排队'));
      }, 15000);
      browserWSRequests.set(requestId, {
        resolve: (value) => { clearTimeout(timeout); resolve(value); },
        reject: (error) => { clearTimeout(timeout); reject(error); }
      });
      try { socket.send(JSON.stringify({ ...payload, request_id: requestId })); }
      catch (error) {
        clearTimeout(timeout);
        browserWSRequests.delete(requestId);
        reject(new Error('发送实时操作失败：' + (error.message || 'WebSocket 已断开')));
      }
    });

    const rejectPendingBrowserWSRequests = (message) => {
      for (const [requestId, pending] of browserWSRequests.entries()) {
        browserWSRequests.delete(requestId);
        pending.reject(new Error(message));
      }
    };

    const stopBrowserEvents = () => {
      browserEventsStopped = true;
      browserEventsConnecting = false;
      browserEventsGeneration++;
      realtimeStatus.value = 'disconnected';
      if (browserEventsRetryTimer !== null) clearTimeout(browserEventsRetryTimer);
      browserEventsRetryTimer = null;
      rejectPendingBrowserWSRequests('实时通道已断开，请重新连接后重试');
      if (browserEventsSocket) {
        const socket = browserEventsSocket;
        browserEventsSocket = null;
        socket.onclose = null;
        try { socket.close(); } catch (_) {}
      }
    };

    const startStaleStatusTimer = () => {
      if (staleStatusTimer !== null) return;
      staleStatusTimer = setInterval(() => {
        const now = Math.floor(Date.now() / 1000);
        agentEntries.value = agentEntries.value.map(item => {
          const age = now - (Number(item.last_seen) || 0);
          if (item.online && (age < 0 || age >= 90)) {
            return { ...item, online: false, mihomoRunning: false, runtimeMessage: '运行状态已记录，但心跳已超时；当前 Mihomo 状态未知' };
          }
          return item;
        });
      }, 5000);
    };

    const connectBrowserEvents = async () => {
      if (!token.value || browserEventsSocket || browserEventsStopped || browserEventsConnecting) return;
      browserEventsConnecting = true;
      const generation = ++browserEventsGeneration;
      realtimeStatus.value = 'connecting';
      try {
        const res = await api('/api/v1/events/ticket', { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data.ticket) throw new Error(data.error || '获取实时通道授权失败');
        if (generation !== browserEventsGeneration || browserEventsStopped || !token.value) return;
        browserEventsConnecting = false;
        const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const socket = new WebSocket(scheme + '//' + window.location.host + '/api/v1/events/ws?ticket=' + encodeURIComponent(data.ticket));
        browserEventsSocket = socket;
        socket.onopen = () => {
          if (generation !== browserEventsGeneration || browserEventsStopped || !token.value || browserEventsSocket !== socket) {
            try { socket.close(); } catch (_) {}
            return;
          }
          realtimeStatus.value = 'connected';
          // Resync the full snapshot after every connect/reconnect; WebSocket events are deltas.
          loadAgentsData();
          loadOverview();
        };
        socket.onmessage = (event) => {
          if (generation !== browserEventsGeneration || browserEventsStopped || !token.value || browserEventsSocket !== socket) return;
          // Resolve browser-originated control requests on the same primary WebSocket.
          let envelope;
          try { envelope = JSON.parse(event.data); } catch (_) { return; }
          if (envelope.type === 'request.result' && envelope.request_id) {
            const pending = browserWSRequests.get(envelope.request_id);
            if (pending) {
              browserWSRequests.delete(envelope.request_id);
              if (envelope.ok) pending.resolve(envelope);
              else {
                const error = new Error(envelope.error || '实时操作失败');
                if (Array.isArray(envelope.bound_nodes)) error.bound_nodes = envelope.bound_nodes;
                pending.reject(error);
              }
            }
            return;
          }
          let message;
          try { message = JSON.parse(event.data); } catch (_) { return; }
          if (message.type === 'agent.binding.revoked' && message.machine_code) {
            const revokedCode = String(message.machine_code);
            // Invalidate snapshots already in flight: an older agents.list.get
            // response must never resurrect a binding removed by this event.
            agentBindingRevision++;
            agentEntries.value = agentEntries.value.filter(item => item.code !== revokedCode);
            loadAgentsData();
            return;
          }
          if (message.type === 'agent.binding.updated') {
            // A registration/rebind event must invalidate older list snapshots
            // just like revocation; otherwise the newly authorized node can
            // remain absent until another manual refresh or reconnect.
            agentBindingRevision++;
            loadAgentsData();
            return;
          }
          if (message.type === 'agent.status.updated' && message.machine_code) {
            const code = String(message.machine_code);
            const status = message.status && typeof message.status === 'object' ? message.status : {};
            const receivedAt = Number(message.last_seen) || Math.floor(Date.now() / 1000);
            // Live telemetry is authoritative while WebSocket is connected.
            // HTTP is only used for initial/reconnect snapshots, not polling.
            traffic.value = {
              up: Math.max(0, Number(status.upload_speed) || 0),
              down: Math.max(0, Number(status.download_speed) || 0),
              conns: Math.max(0, Number(status.connections) || 0)
            };
            const index = agentEntries.value.findIndex(item => item.code === code);
            if (index >= 0) {
              const previous = agentEntries.value[index];
              const updated = {
                ...previous,
                online: true,
                last_seen: receivedAt,
                hostname: String(status.hostname || previous.hostname || ''),
                os: String(status.os || previous.os || ''),
                arch: String(status.arch || previous.arch || ''),
                mihomoRunning: status.mihomo_healthy === true,
                mihomoVersion: normalizeMihomoVersion(status.mihomo_version || previous.mihomoVersion),
                connections: Number.isFinite(Number(status.connections)) ? Math.max(0, Number(status.connections)) : previous.connections,
                uploadSpeed: Math.max(0, Number(status.upload_speed) || 0),
                downloadSpeed: Math.max(0, Number(status.download_speed) || 0),
                runtimeReported: true,
                lastError: String(status.last_error || ''),
                runtimeMessage: status.mihomo_healthy === true ? '' : String(status.last_error || 'Agent 已连接，但 Mihomo 健康检查未通过'),
                updated_at: new Date(receivedAt * 1000).toLocaleString()
              };
              agentEntries.value.splice(index, 1, updated);
            } else {
              loadAgentsData();
            }
          } else if ((message.type === 'agent.command.updated' || message.type === 'agent.command.queued') && message.machine_code) {
            const code = String(message.machine_code);
            const index = agentEntries.value.findIndex(item => item.code === code);
            if (index >= 0) {
              const previous = agentEntries.value[index];
              const queued = message.type === 'agent.command.queued';
              agentEntries.value.splice(index, 1, {
                ...previous,
                lastCommandId: String(message.command_id || previous.lastCommandId || ''),
                lastCommandStatus: queued ? 'queued' : String(message.status || 'unknown'),
                lastCommandMessage: queued ? ('命令已排队' + (message.version ? '：' + message.version : '')) : String(message.message || ''),
                lastCommandAt: Number(message.at) || Math.floor(Date.now() / 1000)
              });
            }
          }
        };
        socket.onerror = () => { try { socket.close(); } catch (_) {} };
        socket.onclose = () => {
          if (generation !== browserEventsGeneration) return;
          const wasCurrentSocket = browserEventsSocket === socket;
          if (wasCurrentSocket) {
            browserEventsSocket = null;
            // Fail pending requests immediately instead of making each caller wait
            // for its 15-second timeout. The server may have completed a write
            // before the reply was lost, so callers must treat the outcome as unknown.
            rejectPendingBrowserWSRequests('实时通道已断开，操作结果未确认；请刷新状态后再决定是否重试');
          }
          if (!wasCurrentSocket || browserEventsStopped || !token.value) return;
          realtimeStatus.value = 'reconnecting';
          browserEventsRetryTimer = setTimeout(() => {
            browserEventsRetryTimer = null;
            connectBrowserEvents();
          }, 3000);
        };
      } catch (e) {
        if (generation !== browserEventsGeneration) return;
        browserEventsConnecting = false;
        if (browserEventsStopped || !token.value) {
          realtimeStatus.value = 'disconnected';
          return;
        }
        realtimeStatus.value = 'reconnecting';
        if (!browserEventsStopped && token.value) {
          browserEventsRetryTimer = setTimeout(() => {
            browserEventsRetryTimer = null;
            connectBrowserEvents();
          }, 3000);
        }
      }
    };

    const logout = () => {
      stopBrowserEvents();
      localStorage.removeItem('s5m_next_token');
      localStorage.removeItem('s5m_next_user');
      token.value = ''; currentUser.value = ''; loginPass.value = '';
    };

    const handleLoginEnter = (event) => {
      // Chinese/Japanese IMEs emit Enter to commit the composition. Never submit while composing.
      if (event && (event.isComposing || event.keyCode === 229 || event.which === 229)) return;
      doLogin();
    };

    const resetPwdForm = () => { pwdForm.old = ''; pwdForm.new = ''; pwdForm.confirm = ''; };
    const handleUserMenu = (command) => {
      if (command === 'password') { resetPwdForm(); pwdDialog.value = true; }
      if (command === 'logout') logout();
    };
    const changeAdminPassword = async () => {
      if (!pwdForm.old) return showMsg('请输入当前密码', 'warning');
      if (pwdForm.new.length < 6) return showMsg('新密码至少 6 位', 'warning');
      if (pwdForm.new !== pwdForm.confirm) return showMsg('两次输入的新密码不一致', 'warning');
      if (pwdForm.old === pwdForm.new) return showMsg('新密码不能与当前密码相同', 'warning');
      pwdSaving.value = true;
      try {
        const result = await sendBrowserWSControl({ type: 'auth.password.change', old: pwdForm.old, new: pwdForm.new });
        const data = result.data || result;
        showMsg(data.message || '管理员密码已更新', 'success');
        pwdDialog.value = false;
        resetPwdForm();
      } catch (e) { showMsg(e.message || '修改密码失败', 'error'); }
      finally { pwdSaving.value = false; }
    };

    const doLogin = async () => {
      if (!loginUser.value || !loginPass.value) return showMsg('请输入账号密码', 'warning');
      loggingIn.value = true;
      try {
        const res = await fetch('/api/v1/auth/login', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: loginUser.value, password: loginPass.value })
        });
        const data = await res.json().catch(() => ({}));
        if (res.ok && data.token) {
          localStorage.setItem('s5m_next_token', data.token);
          localStorage.setItem('s5m_next_user', data.user.username || loginUser.value);
          token.value = data.token; currentUser.value = data.user.username || loginUser.value;
          loginPass.value = ''; browserEventsStopped = false; switchPage('dashboard'); startStaleStatusTimer(); connectBrowserEvents();
        } else { showMsg(data.error || data.message || '账号或密码错误', 'error'); }
      } catch (e) { showMsg('网络错误', 'error'); }
      loggingIn.value = false;
    };

    const PAGES = ['dashboard','proxies','instances','config','system'];
    const switchPage = (v) => {
      if (!PAGES.includes(v)) v = 'dashboard';
      page.value = v;
      if (v === 'dashboard') loadOverview();
      if (v === 'proxies') { loadProxies(); loadAgentsData(); }
      if (v === 'instances') { loadAgentsData(); loadProxies(); }
      if (v === 'config') { loadAgentsData(); loadSettings(); }
      if (v === 'system') { loadSystemLogs(); loadMainMihomoStatus(); }
    };

    const loadOverview = async () => {
      // The dashboard uses the authenticated browser WebSocket as its primary
      // data channel. Do not silently fall back to repeated HTTP requests.
      try {
        const data = await sendBrowserWSControl({ type: 'monitor.overview.get' });
        overview.value = data.data || {};
      } catch (e) {
        console.warn('通过实时通道读取仪表盘概览失败', e);
      }

      try {
        const data = await sendBrowserWSControl({ type: 'monitor.traffic.get' });
        traffic.value = {
          up: Math.max(0, Number((data.data || {}).up) || 0),
          down: Math.max(0, Number((data.data || {}).down) || 0),
          conns: Math.max(0, Number((data.data || {}).conns) || 0)
        };
      } catch (e) {
        console.warn('通过实时通道读取流量失败', e);
      }
    };

    const recoverMihomoUpdateTask = async () => {
      try {
        const result = await sendBrowserWSControl({ type: 'mihomo.update.latest.get' });
        const task = result.data || null;
        if (!task) { showMsg('没有可恢复的 Mihomo 更新任务', 'info'); return; }
        const statusText = task.status === 'running' || task.status === 'queued' ? '仍在执行' : task.status === 'completed' ? '已完成' : '失败';
        const detail = task.error || task.message || task.version || '';
        showMsg('最近一次主控 Mihomo 更新' + statusText + '（任务 ' + task.task_id + '）' + (detail ? '：' + detail : ''), task.status === 'failed' ? 'error' : 'info');
      } catch (e) { showMsg(e.message || '查询最近更新任务失败', 'error'); }
    };

    const updateKernel = async () => {
      try {
        await ElementPlus.ElMessageBox.confirm(
          '此操作只更新主控服务器上的 Mihomo 二进制文件，并会重启主控机的 mihomo 服务；不会更新各个 Agent 节点。更新期间主控代理流量可能中断，请确认已安排维护窗口。',
          '确认更新主控 Mihomo',
          { type: 'warning', confirmButtonText: '确认更新', cancelButtonText: '取消' }
        );
      } catch (_) {
        return;
      }
      updatingKernel.value = true;
      try {
        const started = await sendBrowserWSControl({ type: 'mihomo.update.start' });
        const taskID = String((started.data || started).task_id || '');
        if (!taskID) throw new Error('更新任务未返回有效任务 ID');
        const deadline = Date.now() + 5 * 60 * 1000;
        let task;
        while (Date.now() < deadline) {
          await new Promise(resolve => setTimeout(resolve, 2000));
          const result = await sendBrowserWSControl({ type: 'mihomo.update.status.get', task_id: taskID });
          task = result.data || result;
          if (task.status === 'completed' || task.status === 'failed') break;
        }
        if (!task || (task.status !== 'completed' && task.status !== 'failed')) throw new Error('更新仍在后台执行，任务 ID：' + taskID + '。可使用“查询最近更新任务”恢复查看。');
        if (task.status === 'failed') throw new Error(task.error || '主控 Mihomo 更新失败');
        await loadMainMihomoStatus();
        const expectedVersion = String(task.version || '').trim();
        const actualVersion = String(mainMihomoStatus.value.version || '').trim();
        if (!mainMihomoStatus.value.online) throw new Error('更新任务已完成，但主控 Mihomo 当前未正常运行，请查看服务日志。');
        if (expectedVersion && actualVersion !== expectedVersion) throw new Error('版本确认不一致：任务返回 ' + expectedVersion + '，状态页读取到 ' + (actualVersion || '未知'));
        showMsg(task.message || 'Mihomo 运行版本已确认', task.result_status === 'latest' ? 'info' : 'success');
        await loadOverview();
      } catch (e) { showMsg(e.message || '网络错误', 'error'); }
      finally { updatingKernel.value = false; }
    };

    const loadMainMihomoStatus = async () => {
      mainMihomoStatus.value = { ...mainMihomoStatus.value, loading: true };
      try {
        const result = await sendBrowserWSControl({ type: 'mihomo.status.get' });
        const data = result.data || {};
        mainMihomoStatus.value = { ...data, loading: false };
      } catch (e) {
        mainMihomoStatus.value = { ...mainMihomoStatus.value, loading: false, online: false, queryError: e.message || '状态查询失败' };
      }
    };

    const loadSystemLogs = async () => {
      loadingSystemLogs.value = true;
      try {
        const result = await sendBrowserWSControl({ type: 'system.logs.get' });
        const data = result.data || {};
        systemLogs.value = data.logs || '';
      } catch (e) {
        showMsg(e.message || '读取系统日志失败', 'error');
      } finally {
        loadingSystemLogs.value = false;
      }
    };

    const downloadBackup = async () => {
      try {
        const res = await fetch('/api/v1/backup', { headers: authHeaders() });
        if (res.status === 401) { logout(); throw new Error('登录已失效'); }
        if (!res.ok) {
          const data = await res.json().catch(() => ({}));
          throw new Error(data.error || data.message || ('HTTP ' + res.status));
        }
        const blob = await res.blob();
        const objectUrl = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = objectUrl;
        link.download = 's5m_backup.db';
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(objectUrl);
        showMsg('数据库备份已开始下载', 'success');
      } catch (e) {
        showMsg(e.message || '下载备份失败', 'error');
      }
    };

    const restoreBackup = async (event) => {
      const file = event && event.target && event.target.files && event.target.files[0];
      if (!file) return;
      // Reset the input so the same file can be selected again after an error.
      event.target.value = '';
      if (file.size <= 0 || file.size > 128 * 1024 * 1024) {
        showMsg('备份文件为空或超过 128 MiB 限制', 'warning');
        return;
      }
      try {
        await ElementPlus.ElMessageBox.confirm(
          '恢复数据库会覆盖当前代理、节点、设置和任务数据。请先下载当前备份；恢复后需要重新登录。',
          '确认恢复数据库',
          { type: 'warning', confirmButtonText: '确认覆盖', cancelButtonText: '取消' }
        );
      } catch (_) {
        return;
      }
      restoringBackup.value = true;
      try {
        const form = new FormData();
        form.append('file', file, file.name);
        const res = await api('/api/v1/restore', { method: 'POST', body: form });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || data.message || ('HTTP ' + res.status));
        showMsg(data.message || '数据库恢复请求已完成，请重新登录并检查数据', 'success');
        logout();
      } catch (e) {
        showMsg(e.message || '恢复数据库失败', 'error');
      } finally {
        restoringBackup.value = false;
      }
    };

    const loadProxies = async () => {
      loadingProxies.value = true;
      try {
        const result = await sendBrowserWSControl({ type: 'proxies.list.get' });
        proxies.value = Array.isArray(result.data) ? result.data : [];
      } catch (e) { console.warn(e); }
      finally {
        loadingProxies.value = false;
        // 删除分组最后一个代理后回到“全部”；Agent 注册记录不会被删除。
        if (activeGroup.value !== 'ALL' && activeGroup.value !== 'UNBOUND' &&
            !proxies.value.some(p => p.machine_code === activeGroup.value)) activeGroup.value = 'ALL';
      }
    };

    const openCreateProxy = () => {
      Object.assign(proxyForm, { id: 0, name: '', mode: 'proxy', type: 'socks5', server: '', port: 1080, machine_code: '', source_cidr: '0.0.0.0/0', enabled: true, username: '', password: '', extra_json: '{}' });
      // 如果当前正在看某个机器的分组，默认绑定该机器
      if (activeGroup.value !== 'ALL' && activeGroup.value !== 'UNBOUND') {
        proxyForm.machine_code = activeGroup.value;
      }
      proxyDialog.value = true;
    };

    const openEditProxy = (row) => {
      const extra = row.extra && typeof row.extra === 'object' && !Array.isArray(row.extra) ? row.extra : {};
      Object.assign(proxyForm, {
        id: row.id || 0, name: row.name || row.proxy_name || '', mode: ({ proxy: 'return', china: 'split' }[row.mode] || row.mode || 'return'),
        type: row.type || row.proxy_type || 'socks5',
        server: row.server || '', port: row.port || 1080, machine_code: row.machine_code || '',
        source_cidr: row.source_cidr || '0.0.0.0/0',
        enabled: row.enabled === true || row.enabled === 1,
        username: extra.username || '', password: extra.password || '',
        extra_json: JSON.stringify(extra, null, 2)
      });
      proxyDialog.value = true;
    };

    const saveProxy = async () => {
      if (!proxyForm.name || !proxyForm.server || !proxyForm.port) return showMsg('请填写名称/服务器/端口', 'warning');
      savingProxy.value = true;
      try {
        const isEdit = proxyForm.id > 0;
        const url = isEdit ? ('/api/v1/proxies/' + proxyForm.id) : '/api/v1/proxies';
        let extra;
        try {
          extra = JSON.parse(proxyForm.extra_json || '{}');
        } catch (_) {
          showMsg('高级参数 JSON 格式无效，请检查后再保存', 'warning');
          savingProxy.value = false;
          return;
        }
        if (!extra || typeof extra !== 'object' || Array.isArray(extra)) {
          showMsg('高级参数必须是 JSON 对象，例如 {"uuid":"..."}', 'warning');
          savingProxy.value = false;
          return;
        }
        // Non-empty credential fields override JSON; empty inputs never silently erase
        // existing credentials while editing unrelated properties.
        if (proxyForm.username) extra.username = proxyForm.username;
        if (proxyForm.password) extra.password = proxyForm.password;

        await sendBrowserWSControl({
          type: 'proxy.save',
          proxy_id: isEdit ? String(proxyForm.id) : '',
          proxy: {
            name: proxyForm.name, mode: proxyForm.mode || 'return', type: proxyForm.type, server: proxyForm.server, port: proxyForm.port,
            machine_code: proxyForm.machine_code, source_cidr: proxyForm.source_cidr || '0.0.0.0/0',
            enabled: Boolean(proxyForm.enabled), extra: extra
          }
        });
        proxyDialog.value = false;
        await loadProxies();
        showMsg('保存成功', 'success');
      } catch (e) {
        const message = e.message || '网络错误';
        // Proxy persistence may succeed even when downstream node sync fails.
        if (message.includes('同步失败') || message.includes('已保存') || message.includes('已更新')) {
          proxyDialog.value = false;
          await loadProxies();
          showMsg('代理数据已保存，但节点配置同步失败：' + message + '。请检查节点状态后重试同步。', 'warning');
        } else {
          showMsg(message, 'error');
        }
      }
      savingProxy.value = false;
    };

    const deleteProxy = async (row) => {
      if (!row.id) return showMsg('该节点无 id，无法删除', 'warning');
      if (!confirm('确定删除节点 "' + (row.name || row.proxy_name || row.id) + '" ？')) return;
      try {
        await sendBrowserWSControl({ type: 'proxy.delete', proxy_id: String(row.id) });
        // Reflect the committed deletion immediately, then reload the authoritative list.
        proxies.value = proxies.value.filter(p => String(p.id) !== String(row.id));
        await loadProxies();
        showMsg('已删除', 'success');
      } catch (e) {
        const message = e.message || '删除失败';
        // The backend may commit the delete before reporting a node-sync failure.
        if (message.includes('代理已删除')) {
          proxies.value = proxies.value.filter(p => String(p.id) !== String(row.id));
          await loadProxies();
          showMsg(message + '。请进入配置管理点击“立即重试同步所有节点”。', 'warning');
          return;
        }
        showMsg(message, 'error');
      }
    };

    const findProxyArray = (obj) => {
      if (Array.isArray(obj)) {
        if (obj.length > 0 && typeof obj[0] === 'object' && (obj[0].server || obj[0].address)) return obj;
        for (let item of obj) { const res = findProxyArray(item); if (res) return res; }
      } else if (obj !== null && typeof obj === 'object') {
        for (let key of ['proxies', 'nodes', 'servers', 'list', 'items', 'data']) {
          if (obj[key]) { const res = findProxyArray(obj[key]); if (res) return res; }
        }
        for (let key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) { const res = findProxyArray(obj[key]); if (res) return res; } }
      }
      return null;
    };

    const handleFileUpload = (e) => {
      const file = e.target.files[0]; if (!file) return;
      const reader = new FileReader();
      reader.onload = (evt) => {
        const content = evt.target.result;
        if (file.name.endsWith('.json')) {
          try {
            const parsedJSON = JSON.parse(content);
            const arr = findProxyArray(parsedJSON);
            if (!arr || !arr.length) throw new Error('找不到包含 server/address 的节点数组');
            const inheritedProtocol = String(parsedJSON && !Array.isArray(parsedJSON) ? (parsedJSON.protocol || parsedJSON.type || parsedJSON.scheme || '') : '').trim().toLowerCase();
            const lines = arr.map((item, index) => {
              const name = String(item.name || item.remark || item.proxy_name || item.ps || `节点-${index + 1}`).trim().replace(/[\r\n#]/g, ' ');
              const directURI = String(item.uri || item.url || item.link || item.proxy || item.vmess_link || item.vmessLink || '').trim();
              if (directURI && /^(socks5|socks|http|https|ss|vmess|vless|trojan):\/\//i.test(directURI)) {
                return directURI.includes('#') ? directURI : directURI + '#' + encodeURIComponent(name);
              }
              let type = String(item.type || item.protocol || item.scheme || inheritedProtocol || '').trim().toLowerCase();
              if (type === 'socks') type = 'socks5';
              if (type === 'https') type = 'http';
              const server = String(item.server || item.address || item.host || item.add || '').trim();
              const port = Number(item.port || item.server_port || item.serverPort || 0);
              if (!server || !Number.isInteger(port) || port < 1 || port > 65535) return '';
              if (!['socks5', 'socks', 'http', 'https', 'ss', 'vmess', 'vless', 'trojan'].includes(type)) return '';
              const host = server.includes(':') && !server.startsWith('[') ? '[' + server + ']' : server;
              const fragment = encodeURIComponent(name);
              const username = item.username == null ? '' : String(item.username);
              const password = item.password == null ? '' : String(item.password);
              if (type === 'vmess') {
                const ws = item['ws-opts'] || item.wsOpts || {};
                const headers = ws.headers || {};
                const uuid = String(item.uuid || item.id || '');
                if (!uuid) return '';
                const vmess = {
                  v: '2', ps: name, add: server, port: String(port),
                  id: uuid, aid: String(item.alterId ?? item.aid ?? 0),
                  scy: String(item.cipher || item.scy || 'auto'),
                  net: String(item.network || item.net || 'tcp'),
                  tls: item.tls ? 'tls' : '',
                  sni: String(item.servername || item.sni || ''),
                  host: String(headers.Host || headers.host || item.host || ''),
                  path: String(ws.path || item.path || '')
                };
                const encoded = btoa(unescape(encodeURIComponent(JSON.stringify(vmess))));
                return 'vmess://' + encoded;
              }
              if (type === 'ss') {
                const cipher = String(item.cipher || item.method || '');
                if (!cipher || !password) return '';
                const auth = btoa(unescape(encodeURIComponent(cipher + ':' + password)));
                return 'ss://' + auth + '@' + host + ':' + port + '#' + fragment;
              }
              const query = new URLSearchParams();
              const network = String(item.network || item.net || '');
              if (network) query.set('type', network);
              const tls = item.tls === true || String(item.tls).toLowerCase() === 'true' || item.security === 'tls' || item.security === 'reality';
              if (tls) query.set('security', item.security || 'tls');
              const sni = String(item.servername || item.sni || '');
              if (sni) query.set('sni', sni);
              const flow = String(item.flow || '');
              if (flow) query.set('flow', flow);
              const ws = item['ws-opts'] || item.wsOpts || {};
              const headers = ws.headers || {};
              if (network === 'ws') {
                if (headers.Host || headers.host) query.set('host', headers.Host || headers.host);
                if (ws.path || item.path) query.set('path', ws.path || item.path);
              }
              const auth = type === 'vless'
                ? encodeURIComponent(String(item.uuid || item.id || username))
                : (type === 'trojan'
                  ? encodeURIComponent(password || username)
                  : ((username || password) ? encodeURIComponent(username) + ':' + encodeURIComponent(password) : ''));
              const queryString = query.toString();
              return type + '://' + auth + (auth ? '@' : '') + host + ':' + port + (queryString ? '?' + queryString : '') + '#' + fragment;
            }).filter(Boolean);
            if (!lines.length) throw new Error('无法识别代理协议或缺少有效服务器/端口。请确保 JSON 节点包含 type/protocol，或提供完整代理链接。');
            importText.value = lines.join('\n'); showMsg(`成功解析 ${lines.length} 条节点；导入时将按协议链接格式提交`, 'success');
          } catch (err) { showMsg('JSON 解析失败：' + err.message, 'error'); importText.value = ''; }
        } else {
          importText.value = content; showMsg('文件读取成功，请点击导入', 'success');
        }
      };
      reader.readAsText(file);
    };

    const importProxies = async () => {
      const content = String(importText.value || '').trim();
      if (!content) return showMsg('请输入或上传代理链接', 'warning');
      if (importing.value) return;
      importing.value = true;
      try {
        // Import is text/JSON content rather than a binary upload, so it uses the
        // authenticated WebSocket control channel like other proxy mutations.
        const result = await sendBrowserWSControl({ type: 'proxies.import', content });
        const data = result.data || result;
        const success = Number(data.success) || 0;
        const fail = Number(data.fail) || 0;
        if (data.sync_failed) {
          showMsg(`代理导入已完成：成功 ${success} 条，失败 ${fail} 条。${data.message || ''}。请进入配置管理点击“立即重试同步所有节点”。`, 'warning');
        } else if (success === 0) {
          showMsg(data.message || '没有成功导入节点，请检查格式和服务端日志', 'warning');
        } else if (fail > 0) {
          showMsg(`导入完成：成功 ${success} 条，失败 ${fail} 条。${data.message || ''}`, 'warning');
        } else {
          showMsg(`导入成功 ${success} 条`, 'success');
        }
        await loadProxies();
        if (success > 0) showImport.value = false;
      } catch (e) {
        showMsg(e.message || '导入失败', 'error');
      } finally {
        importing.value = false;
      }
    };

    const agentRefreshing = ref(false);
    let agentBindingRevision = 0;
    const loadAgentsData = async () => {
      // Never overlap instance requests. Once data exists, refresh silently so
      // the current list and expanded cards remain mounted while the request runs.
      if (agentLoading.value || agentRefreshing.value) return;
      const revocationRevision = agentBindingRevision;
      let retryAfterRevocation = false;
      const hasExistingData = agentEntries.value.length > 0;
      if (hasExistingData) agentRefreshing.value = true;
      else agentLoading.value = true;
      if (!hasExistingData) agentLoadError.value = '';
      try {
        const result = await sendBrowserWSControl({ type: 'agents.list.get' });
        const data = result.data || {};
        const now = Math.floor(Date.now() / 1000);
        const list = [];
        Object.keys(data || {}).forEach(code => {
          const item = data[code] || {};
          const last = Number(item.last_seen) || 0;
          const ageSeconds = now - last;
          const online = last > 0 && ageSeconds >= 0 && ageSeconds < 90;
          const status = item.status && typeof item.status === 'object' ? item.status : {};
          const reportedAt = Number(status.received_at) || 0;
          const hostname = String(status.hostname || '');
          const os = String(status.os || '');
          const arch = String(status.arch || '');
          const mihomoVersion = normalizeMihomoVersion(status.mihomo_version);
          const runtimeReported = reportedAt > 0 || Boolean(hostname || os || arch || mihomoVersion);
          const lastError = String(status.last_error || '');

          let runtimeMessage = '';
          if (!runtimeReported) {
            runtimeMessage = last > 0
              ? '有认证通信记录，但没有有效运行状态；请检查 Agent 心跳上报日志、版本和主控地址'
              : '尚无通信记录；请检查 Agent 是否启动、绑定 Token 和主控地址';
          } else if (!online) {
            runtimeMessage = '运行状态已记录，但心跳已超时；请检查 Agent 进程和网络连接';
          } else if (!status.mihomo_healthy) {
            runtimeMessage = lastError || 'Agent 已上报，但 Mihomo API 未通过健康检查';
          }

          list.push({
            code,
            authorized: item.authorized === true,
            tokenConfigured: item.token_configured === true,
            connections: Number.isFinite(Number(status.connections)) ? Math.max(0, Number(status.connections)) : null,
            uploadSpeed: Math.max(0, Number(status.upload_speed) || 0),
            downloadSpeed: Math.max(0, Number(status.download_speed) || 0),
            online,
            last_seen: last,
            hostname,
            os,
            arch,
            mihomoRunning: online && status.mihomo_healthy === true,
            mihomoVersion,
            runtimeReported,
            runtimeMessage,
            lastError,
            updated_at: (reportedAt > 0 && Number.isFinite(reportedAt)) || (last > 0 && Number.isFinite(last))
              ? new Date(((reportedAt > 0 && Number.isFinite(reportedAt)) ? reportedAt : last) * 1000).toLocaleString()
              : '',
            pendingCommand: item.pending_command && typeof item.pending_command === 'object' ? item.pending_command : null,
            commandResult: item.command_result && typeof item.command_result === 'object' ? item.command_result : null
          });
        });
        list.sort((a, b) => (b.last_seen || 0) - (a.last_seen || 0));
        if (revocationRevision !== agentBindingRevision) {
          // A revoke event arrived while this snapshot was loading. Discard it
          // and fetch a fresh authoritative snapshot after releasing the lock.
          retryAfterRevocation = true;
        } else {
          agentEntries.value = list;
        }
      } catch (e) {
        if (!hasExistingData) {
          agentLoadError.value = '读取实例失败：网络连接异常，请检查主控服务和浏览器连接。';
        } else {
          console.warn('静默刷新实例失败，保留现有列表', e);
        }
        console.error('读取实例失败', e);
        if (!hasExistingData) agentEntries.value = [];
      } finally {
        agentLoading.value = false;
        agentRefreshing.value = false;
        if (retryAfterRevocation) {
          Promise.resolve().then(() => loadAgentsData());
        }
      }
    };

    const generateAgentToken = async () => {
      if (!newMachineCode.value) return showMsg('请输入机器码', 'warning');
      generating.value = true;
      try {
        const result = await sendBrowserWSControl({ type: 'agent.binding.generate', machine_code: newMachineCode.value });
        const data = result.data || result;
        if (data.token) {
          generatedToken.value = data.token; newMachineCode.value = ''; loadAgentsData();
        } else { showMsg(data.error || data.message || '生成失败', 'error'); }
      } catch (e) { showMsg(e.message || '网络错误', 'error'); }
      generating.value = false;
    };

    const loadAgentKernelUpdateInfo = async () => {
      const machineCode = String(kernelUpdateMachineCode.value || '').trim();
      if (!machineCode) return;
      kernelUpdateInfoLoading.value = true;
      kernelUpdateInfo.value = null;
      kernelUpdateVersion.value = '';
      kernelUpdateSHA256.value = '';
      try {
        const result = await sendBrowserWSControl({ type: 'agent.mihomo.update-info', machine_code: machineCode });
        const data = result.data || result;
        kernelUpdateInfo.value = data;
        kernelUpdateVersion.value = String(data.latest_version || '');
        kernelUpdateSHA256.value = String(data.sha256 || '').toLowerCase();
      } catch (e) {
        kernelUpdateInfo.value = { error: e.message || '查询官方版本失败' };
      } finally {
        kernelUpdateInfoLoading.value = false;
      }
    };

    const openAgentKernelUpdate = (code) => {
      kernelUpdateMachineCode.value = String(code || '').trim();
      kernelUpdateVersion.value = '';
      kernelUpdateSHA256.value = '';
      kernelUpdateInfo.value = null;
      kernelUpdateDialog.value = Boolean(kernelUpdateMachineCode.value);
      if (kernelUpdateDialog.value) loadAgentKernelUpdateInfo();
    };

    const queueAgentKernelUpdate = async () => {
      const machineCode = String(kernelUpdateMachineCode.value || '').trim();
      const version = String(kernelUpdateVersion.value || '').trim();
      const sha256 = String(kernelUpdateSHA256.value || '').trim().toLowerCase();
      if (!machineCode) return showMsg('请先选择目标 Agent', 'warning');
      if (kernelUpdateInfoLoading.value) return showMsg('正在查询官方版本和校验值，请稍候', 'warning');
      if (kernelUpdateInfo.value && kernelUpdateInfo.value.error) return showMsg('请先成功获取官方更新信息', 'warning');
      if (!/^v\d+\.\d+\.\d+$/.test(version)) return showMsg('官方版本信息无效，请重新查询', 'warning');
      if (!/^[a-f0-9]{64}$/.test(sha256)) return showMsg('官方 SHA-256 信息无效，请重新查询', 'warning');
      if (queueingKernelUpdate.value) return;
      try {
        await ElementPlus.ElMessageBox.confirm(
          '确认将 Agent ' + machineCode + '（' + (kernelUpdateInfo.value?.arch || '未知架构') + '）从 ' + (kernelUpdateInfo.value?.current_version || '未知版本') + ' 更新到官方稳定版 ' + version + '？Agent 在线时会下载、校验并测试新内核后应用。',
          '确认更新 Mihomo 内核',
          { type: 'warning', confirmButtonText: '一键更新', cancelButtonText: '取消' }
        );
      } catch (_) { return; }
      queueingKernelUpdate.value = true;
      try {
        const data = await sendBrowserWSControl({
          type: 'agent.mihomo.update',
          machine_code: machineCode,
          version,
          sha256
        });
        kernelUpdateDialog.value = false;
        showMsg(data.message || '更新任务已排队；Agent 在线时将执行', 'success');
      } catch (e) {
        showMsg(e.message || '排队更新失败', 'error');
      } finally {
        queueingKernelUpdate.value = false;
      }
    };

    const deleteAgent = async (code) => {
      if (!confirm('确定删除机器码 "' + code + '" 的 Token？')) return;
      try {
        await sendBrowserWSControl({ type: 'agent.binding.revoke', machine_code: code });
        if (selectedConfigNode.value === code) { selectedConfigNode.value = ''; configYaml.value = ''; }
        await loadAgentsData();
        showMsg('已撤销绑定；旧 Token 已失效', 'success');
      } catch (e) { showMsg(e.message || '删除失败', 'error'); }
    };

    const yamlIndent = line => {
      const match = String(line || '').match(/^ */);
      return match ? match[0].length : 0;
    };
    const yamlSectionBounds = (lines, section) => {
      const start = lines.findIndex(line => new RegExp('^' + section + ':\\s*(?:#.*)?$').test(line));
      if (start < 0) return null;
      const sectionIndent = yamlIndent(lines[start]);
      let end = start + 1;
      while (end < lines.length) {
        const line = lines[end];
        if (line.trim() && !/^\s*#/.test(line) && yamlIndent(line) <= sectionIndent) break;
        end++;
      }
      return { start, end, sectionIndent };
    };
    const assertUniqueYamlSections = (lines, sections) => {
      for (const section of sections) {
        const count = lines.filter(line => new RegExp('^' + section + ':\\s*(?:#.*)?$').test(line)).length;
        if (count > 1) throw new Error('YAML 存在重复的顶层 ' + section + ' 配置块；请先重新加载原始 YAML 并检查');
      }
    };
    const yamlChildIndent = (lines, bounds) => {
      let childIndent = Infinity;
      for (let i = bounds.start + 1; i < bounds.end; i++) {
        const line = lines[i];
        if (!line.trim() || /^\s*#/.test(line)) continue;
        const indent = yamlIndent(line);
        if (indent > bounds.sectionIndent) childIndent = Math.min(childIndent, indent);
      }
      return Number.isFinite(childIndent) ? childIndent : bounds.sectionIndent + 2;
    };
    const findYamlChild = (lines, bounds, key) => {
      const childIndent = yamlChildIndent(lines, bounds);
      const keyPattern = new RegExp('^' + key + ':(?:\\s|$)');
      const index = lines.findIndex((line, i) =>
        i > bounds.start && i < bounds.end &&
        yamlIndent(line) === childIndent &&
        keyPattern.test(line.trim())
      );
      return { index, indent: index >= 0 ? yamlIndent(lines[index]) : childIndent };
    };
    const setYamlScalar = (yaml, section, key, value) => {
      const lines = String(yaml || '').split(/\r?\n/);
      const bounds = yamlSectionBounds(lines, section);
      if (!bounds) {
        if (lines.length && lines[lines.length - 1].trim()) lines.push('');
        lines.push(section + ':', '  ' + key + ': ' + value);
      } else {
        const child = findYamlChild(lines, bounds, key);
        if (child.index >= 0) {
          const original = lines[child.index];
          const inlineComment = original.match(/\s+#.*$/);
          lines[child.index] = ' '.repeat(child.indent) + key + ': ' + value + (inlineComment ? inlineComment[0] : '');
        }
        else lines.splice(bounds.start + 1, 0, ' '.repeat(child.indent) + key + ': ' + value);
      }
      return lines.join('\n');
    };
    const readYamlScalar = (yaml, section, key) => {
      const lines = String(yaml || '').split(/\r?\n/), bounds = yamlSectionBounds(lines, section);
      if (!bounds) return '';
      const child = findYamlChild(lines, bounds, key);
      return child.index >= 0
        ? lines[child.index].trim().slice(key.length + 1).split('#')[0].trim().replace(/^['"]|['"]$/g, '')
        : '';
    };
    const syncConfigQuickSettingsFromYaml = () => {
      const isYamlEnabled = value => /^(?:true|yes|on)$/i.test(String(value || '').trim().replace(/^['"]|['"]$/g, ''));
      configTunEnabled.value = isYamlEnabled(readYamlScalar(configYaml.value, 'tun', 'enable'));
      configDnsEnabled.value = isYamlEnabled(readYamlScalar(configYaml.value, 'dns', 'enable'));
      const lines = String(configYaml.value || '').split(/\r?\n/), bounds = yamlSectionBounds(lines, 'dns');
      if (!bounds) { configDnsNameservers.value = ''; return; }
      const child = findYamlChild(lines, bounds, 'nameserver');
      if (child.index < 0) { configDnsNameservers.value = ''; return; }
      const values = [];
      for (let i = child.index + 1; i < bounds.end; i++) {
        const line = lines[i];
        if (!line.trim() || /^\s*#/.test(line)) continue;
        if (yamlIndent(line) <= child.indent) break;
        const match = line.trim().match(/^-[ \t]*(.*)$/);
        if (match) values.push(match[1].replace(/^['"]|['"]$/g, '').trim());
      }
      configDnsNameservers.value = values.join('\n');
    };
    const applyConfigQuickSettings = () => {
      if (!selectedConfigNode.value) return showMsg('请先选择节点', 'warning');
      try {
        let lines = String(configYaml.value || '').split(/\r?\n/);
        assertUniqueYamlSections(lines, ['tun', 'dns']);
        let yaml = setYamlScalar(lines.join('\n'), 'tun', 'enable', configTunEnabled.value ? 'true' : 'false');
        yaml = setYamlScalar(yaml, 'dns', 'enable', configDnsEnabled.value ? 'true' : 'false');
        lines = yaml.split(/\r?\n/);
        const bounds = yamlSectionBounds(lines, 'dns');
        const values = String(configDnsNameservers.value || '').split(/\r?\n/).map(v => v.trim()).filter(Boolean);
        if (bounds) {
          const child = findYamlChild(lines, bounds, 'nameserver');
          let index = child.index;
          if (index < 0) {
            lines.splice(bounds.end, 0, ' '.repeat(child.indent) + 'nameserver:');
            index = bounds.end;
          }
          const keyIndent = yamlIndent(lines[index]);
          let end = index + 1;
          while (end < lines.length) {
            const line = lines[end];
            if (line.trim() && yamlIndent(line) <= keyIndent) break;
            end++;
          }
          const listIndent = keyIndent + 2;
          lines.splice(index + 1, end - index - 1, ...values.map(value => ' '.repeat(listIndent) + '- ' + JSON.stringify(value)));
        } else {
          lines.push('dns:', '  enable: ' + (configDnsEnabled.value ? 'true' : 'false'), '  nameserver:',
            ...values.map(value => '    - ' + JSON.stringify(value)));
        }
        configYaml.value = lines.join('\n').replace(/\n*$/, '\n');
        syncConfigQuickSettingsFromYaml();
        showMsg('快捷设置已更新 YAML（尚未保存），请检查后保存', 'success');
      } catch (error) {
        showMsg('快捷设置未写入：' + (error.message || String(error)), 'error');
      }
    };

    const loadNodeConfig = async () => {
      const code = String(selectedConfigNode.value || '').trim();
      const generation = ++nodeConfigLoadGeneration;
      configYaml.value = '';
      syncConfigQuickSettingsFromYaml();
      if (!code) return;
      try {
        const result = await sendBrowserWSControl({ type: 'node.config.get', machine_code: code });
        const data = result.data || result;
        if (generation !== nodeConfigLoadGeneration || String(selectedConfigNode.value || '').trim() !== code) return;
        configYaml.value = String(data.config_yaml || '');
        syncConfigQuickSettingsFromYaml();
        showMsg('已加载节点 ' + code + ' 的独立 YAML', 'success');
      } catch (e) {
        if (generation !== nodeConfigLoadGeneration || String(selectedConfigNode.value || '').trim() !== code) return;
        configYaml.value = '';
        syncConfigQuickSettingsFromYaml();
        showMsg(e.message || '该节点尚无独立 YAML，请编辑后保存', 'warning');
      }
    };

    const saveNodeConfig = async () => {
      const code = String(selectedConfigNode.value || '').trim(), yaml = String(configYaml.value || '');
      if (!code) return showMsg('保存失败：请先选择节点机器码', 'warning');
      if (!yaml.trim()) return showMsg('保存失败：YAML 配置不能为空', 'warning');
      if (savingConfig.value) return;
      savingConfig.value = true;
      try {
        const result = await sendBrowserWSControl({ type: 'node.config.save', machine_code: code, config_yaml: yaml });
        const data = result.data || result;
        if (result.ok === false || data.ok === false || data.error) throw new Error(result.error || data.error || data.message || '服务器拒绝保存配置');
        const verifyResult = await sendBrowserWSControl({ type: 'node.config.get', machine_code: code });
        const verify = verifyResult.data || verifyResult;
        if (String(verify.config_yaml || '') !== yaml) {
          showMsg('保存已返回，但 WebSocket 回读内容不一致；请重新加载核对', 'error');
          return;
        }
        if (String(selectedConfigNode.value || '').trim() !== code) return;
        if (String(configYaml.value || '') !== yaml) {
          showMsg('已保存并验证提交时的 YAML；编辑器内容在保存期间发生变化，请再次保存最新修改', 'warning');
          return;
        }
        showMsg(data.message || '节点 YAML 保存并回读验证成功', 'success');
      } catch (e) {
        if (String(selectedConfigNode.value || '').trim() === code) showMsg('保存失败：' + (e.message || String(e)), 'error');
        console.error('[S5M node config] WebSocket save failed', { code, error: e });
      } finally { savingConfig.value = false; }
    };

    const loadSmartDNSConfig = async () => {
      const code = String(selectedConfigNode.value || '').trim();
      if (!code || loadingSmartDNS.value) return;
      loadingSmartDNS.value = true;
      const generation = ++smartdnsLoadGeneration;
      try {
        const agents = await sendBrowserWSControl({ type: 'agents.list.get' });
        if (generation !== smartdnsLoadGeneration || String(selectedConfigNode.value || '').trim() !== code) return;
        const item = (agents.data || {})[code] || {};
        const status = item.status || {};
        smartdnsStatus.value = {
          available: status.smartdns_available === true,
          running: status.smartdns_running === true,
          dnsHealthy: status.smartdns_dns_healthy === true,
          version: String(status.smartdns_version || ''),
          configHash: String(status.smartdns_config_sha256 || ''),
          lastError: String(status.smartdns_last_error || '')
        };
        const requested = await sendBrowserWSControl({ type: 'smartdns.config.read', machine_code: code });
        if (generation !== smartdnsLoadGeneration || String(selectedConfigNode.value || '').trim() !== code) return;
        smartdnsResult.value = requested.message || '已请求 Agent 读取实际配置；请稍后再次刷新';
        const saved = await sendBrowserWSControl({ type: 'smartdns.config.get', machine_code: code });
        if (generation !== smartdnsLoadGeneration || String(selectedConfigNode.value || '').trim() !== code) return;
        smartdnsYaml.value = String((saved.data || {}).config || '');
        smartdnsResult.value += smartdnsYaml.value ? '；显示的是主控最近保存副本，Agent 回传完成后再次点击刷新获取最新内容' : '；等待 Agent 首次回传';
      } catch (e) {
        if (generation !== smartdnsLoadGeneration || String(selectedConfigNode.value || '').trim() !== code) return;
        smartdnsResult.value = '读取失败：' + (e.message || String(e));
        showMsg(smartdnsResult.value, 'error');
      } finally { if (generation === smartdnsLoadGeneration) loadingSmartDNS.value = false; }
    };

    const applySmartDNSConfig = async () => {
      const code = String(selectedConfigNode.value || '').trim();
      const config = String(smartdnsYaml.value || '');
      if (!code) return showMsg('请先选择 Agent 节点', 'warning');
      if (!config.trim()) return showMsg('SmartDNS 配置不能为空', 'warning');
      if (applyingSmartDNS.value) return;
      if (!confirm('确认将 SmartDNS 配置发送到节点 ' + code + ' 并应用？此操作只影响 SmartDNS。')) return;
      applyingSmartDNS.value = true;
      const generation = ++smartdnsApplyGeneration;
      try {
        const result = await sendBrowserWSControl({ type: 'smartdns.config.apply', machine_code: code, config });
        if (generation !== smartdnsApplyGeneration || String(selectedConfigNode.value || '').trim() !== code) return;
        if (result.ok === false) throw new Error(result.error || '主控拒绝 SmartDNS 配置命令');
        smartdnsResult.value = result.message || '已排队，尚未确认 Agent 应用结果';
        showMsg(smartdnsResult.value, 'info');
      } catch (e) {
        if (generation !== smartdnsApplyGeneration || String(selectedConfigNode.value || '').trim() !== code) return;
        smartdnsResult.value = '提交失败：' + (e.message || String(e));
        showMsg(smartdnsResult.value, 'error');
      } finally { if (generation === smartdnsApplyGeneration) applyingSmartDNS.value = false; }
    };

    const safeCopy = async (text) => {
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(String(text ?? ''));
        } else {
          const t = document.createElement('textarea');
          t.value = String(text ?? '');
          t.style.position = 'fixed';
          t.style.left = '-9999px';
          document.body.appendChild(t);
          t.select();
          const ok = document.execCommand('copy');
          document.body.removeChild(t);
          if (!ok) throw new Error('浏览器复制操作失败');
        }
        showMsg('复制成功', 'success');
      } catch (e) {
        showMsg('复制失败：' + (e.message || '请检查浏览器权限'), 'error');
      }
    };

    const retryNodeConfigSync = async () => {
      if (retryingNodeConfigSync.value) return;
      retryingNodeConfigSync.value = true;
      try {
        const result = await sendBrowserWSControl({ type: 'nodes.config-sync.retry' });
        const data = result.data || {};
        if (!result.ok || data.ok === false) throw new Error(result.error || data.error || data.message || '节点配置同步失败');
        showMsg(data.message || '节点配置已重新生成', 'success');
      } catch (e) {
        showMsg(e.message || '节点配置同步失败', 'error');
      } finally {
        retryingNodeConfigSync.value = false;
      }
    };

    const loadSettings = async () => {
      // Always show a usable absolute subscription URL. Older servers may omit
      // subscribe_url, and settings may contain an empty/whitespace value.
      const fallback = new URL('/api/v1/subscribe', window.location.href).toString();
      subUrl.value = fallback;
      try {
        const result = await sendBrowserWSControl({ type: 'settings.get' });
        const s = result.data || {};
        const configured = String(s.subscribe_url || s.sub_url || '').trim();
        subUrl.value = configured || fallback;
      } catch (e) {
        subUrl.value = fallback;
      }
    };

    onMounted(() => {
      if (token.value) {
        fetch('/api/v1/auth/me', { headers: authHeaders() }).then(r => { if (r.status === 401) logout(); }).catch(() => {});
        switchPage('dashboard');
        loadAgentsData(); // 预加载一次 Agent 列表，以便下拉框有数据
        browserEventsStopped = false;
        connectBrowserEvents();
        startStaleStatusTimer();
      }
    });

    onUnmounted(() => {
      if (overviewTimer !== null) clearInterval(overviewTimer);
      overviewTimer = null;
      if (staleStatusTimer !== null) clearInterval(staleStatusTimer);
      staleStatusTimer = null;
      stopBrowserEvents();
    });

    return {
      page, token, loginUser, loginPass, loggingIn, currentUser,
      pwdDialog, pwdSaving, pwdForm, handleLoginEnter, handleUserMenu, resetPwdForm, changeAdminPassword,
      overview, traffic, realtimeStatus, connectBrowserEvents, proxies, loadingProxies, filteredProxies, availableMachineCodes, proxyGroupCodes, activeGroup,
      getUnboundCount, getMachineCount, machineCodeOptionLabel, machineCodeStatus, proxyCountForMachine, nodeConfigState, openProxiesForMachine, openNodeConfigForMachine,
      newMachineCode, generatedToken, generating, agentEntries, agentLoading, agentRefreshing, agentSearch, agentStatusFilter, filteredAgentEntries,
      retryingNodeConfigSync, retryNodeConfigSync,
      configYaml, configTunEnabled, configDnsEnabled, configDnsNameservers, syncConfigQuickSettingsFromYaml, applyConfigQuickSettings,
      selectedConfigNode, savingConfig, publishing, updatingKernel,
      smartdnsYaml, loadingSmartDNS, applyingSmartDNS, smartdnsResult, smartdnsStatus, loadSmartDNSConfig, applySmartDNSConfig,
      kernelUpdateDialog, kernelUpdateMachineCode, kernelUpdateVersion, kernelUpdateSHA256, queueingKernelUpdate, kernelUpdateInfo, kernelUpdateInfoLoading,
      openAgentKernelUpdate, loadAgentKernelUpdateInfo, queueAgentKernelUpdate,
      systemLogs, loadingSystemLogs, restoringBackup, loadSystemLogs, downloadBackup, restoreBackup,
      mainMihomoStatus, loadMainMihomoStatus,
      proxyDialog, proxyForm, savingProxy,
      showImport, importTab, importText, importing, importMachineCode,
      switchPage, doLogin, logout, loadOverview,
      updateKernel, recoverMihomoUpdateTask, loadProxies, openCreateProxy, openEditProxy, saveProxy, deleteProxy, importProxies, handleFileUpload,
      loadAgentsData, generateAgentToken, deleteAgent, safeCopy,
      loadNodeConfig, loadSettings, saveNodeConfig,
      fmtBytes, fmtSpeed
    };
  }
}).use(ElementPlus).mount('#app');
