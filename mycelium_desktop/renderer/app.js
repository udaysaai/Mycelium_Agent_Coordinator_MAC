/**
 * US Neural - Mycelium Desktop Application
 * Frontend Application Controller
 * High-Energy Designer GUI (Cyber-Carbon Lime & Sunset Tangerine)
 * End-to-End Multi-Provider LLM Gateway & Live Semantic Mesh Pipeline
 */

(function () {
  const state = {
    workspacePath: '',
    privilegeTier: 'PERSON',
    currentQuarantineId: null,
    drawerOpen: false,
    activeDrawerTab: 'terminal-tab',
    selectedFileContent: '',
    config: {
      provider: 'groq',
      groqApiKey: '',
      groqModel: 'llama-3.3-70b-versatile',
      geminiApiKey: '',
      geminiModel: 'gemini-2.0-flash',
      anthropicApiKey: '',
      anthropicModel: 'claude-3-5-sonnet-20241022',
      openaiApiKey: '',
      openaiModel: 'gpt-4o-mini',
      ollamaEndpoint: 'http://localhost:11434',
      ollamaModel: 'llama3.2',
      customBaseUrl: 'https://openrouter.ai/api/v1',
      customApiKey: '',
      customModel: 'deepseek/deepseek-r1',
      registryUrl: 'http://127.0.0.1:8000/api/v1',
      enterpriseKey: '',
      autoSpawnRegistry: true,

      // Appearance Suite
      theme: 'charcoal',
      accentColor: '#00ff9d',
      fontFamily: 'JetBrains Mono',
      fontSize: 14,
      zoomFactor: 1.0,
      performanceMode: false,

      // General & System
      workspacePath: '',
      minimizeToTray: false,
      launchOnStartup: false,
      autoScrollStream: true,
      notificationsEnabled: true,
      soundEffectsEnabled: true,

      // Real-Time Key Verification State
      is_verified: false,
      last_verified: null,
      verificationStatus: {}
    },
    registryStatus: {
      online: false,
      total: 0,
      latencyMs: 0,
      agents: []
    },
    isPollingRegistry: false,
    isDispatching: false,
    sessionTokens: 0,
    conversationHistory: [],
    subAgentCycles: 0,
    currentDelegationDepth: 1,
    holPolicy: 'STRICT',
    slashMenuVisible: false,
    slashSelectedIndex: 0,
    slashFilteredCommands: [],
    lastExecutionError: null,
    lastPrompt: ''
  };

  // Reliability & Circuit Breaker Limits
  const MAX_SUB_AGENT_CYCLES = 3;
  const MAX_DELEGATION_DEPTH = 2;

  // DOM Elements Map
  const el = {
    // Header & Brand
    workspaceCrumb: document.getElementById('workspace-crumb'),
    registryBadge: document.getElementById('nodes-active-badge') || document.getElementById('registry-badge'),
    registryPingDot: document.getElementById('registry-ping-dot'),
    registryBadgeText: document.getElementById('registry-badge-text'),
    toggleDrawerBtn: document.getElementById('toggle-drawer-btn'),
    settingsBtn: document.getElementById('settings-btn'),

    // Sidebar & Explorer
    sidebar: document.querySelector('.sidebar'),
    fileTree: document.getElementById('file-tree'),
    refreshTreeBtn: document.getElementById('refresh-tree-btn'),
    sidebarFileCount: document.getElementById('sidebar-file-count'),
    meshStatusTooltip: document.getElementById('mesh-status-tooltip'),
    footerPulseCore: document.getElementById('footer-pulse-core'),
    footerPulseRing: document.getElementById('footer-pulse-ring'),
    footerStatusText: document.getElementById('footer-status-text'),
    footerProviderText: document.getElementById('footer-provider-text'),
    footerLatencyPill: document.getElementById('footer-latency-pill'),

    // Stream & Feed
    streamFeed: document.getElementById('stream-feed'),
    emptyState: document.getElementById('empty-state'),
    registryAlertBanner: document.getElementById('registry-alert-banner'),
    launchRegistryBannerBtn: document.getElementById('launch-registry-banner-btn'),

    // Input Dock & Slash Commands
    promptInput: document.getElementById('prompt-input'),
    sendBtn: document.getElementById('send-btn'),
    sendBtnIcon: document.getElementById('send-btn-icon'),
    sendBtnLabel: document.getElementById('send-btn-label'),
    sendKeyHint: document.getElementById('send-key-hint'),
    privilegeToggle: document.getElementById('privilege-toggle'),
    privilegeLabel: document.getElementById('privilege-label'),
    activeModelBadge: document.getElementById('active-model-badge'),
    activeModelLabel: document.getElementById('active-model-label'),
    activeModelVerifiedDot: document.getElementById('active-model-verified-dot'),
    tokenCounterBadge: document.getElementById('token-counter-badge'),
    tokenCounterText: document.getElementById('token-counter-text'),
    slashCommandMenu: document.getElementById('slash-command-menu'),
    slashCommandItems: document.getElementById('slash-command-items'),

    // Floating Token Architecture Teaser
    tokenTeaserCard: document.getElementById('token-teaser-card'),
    closeTeaserBtn: document.getElementById('close-teaser-btn'),

    // Execution & Terminal Drawer
    executionDrawer: document.getElementById('execution-drawer'),
    closeDrawerBtn: document.getElementById('close-drawer-btn'),
    clearTerminalBtn: document.getElementById('clear-terminal-btn'),
    terminalLogs: document.getElementById('terminal-logs'),
    drawerTabs: document.querySelectorAll('.drawer-tab'),
    diffFileTitle: document.getElementById('diff-file-title'),
    diffContent: document.getElementById('diff-content'),
    copyFileBtn: document.getElementById('copy-file-btn'),
    auditTableBody: document.getElementById('audit-table-body'),

    // HOL Guard Modal
    holModalBackdrop: document.getElementById('hol-modal-backdrop'),
    modalIntent: document.getElementById('modal-intent'),
    modalSafetyTier: document.getElementById('modal-safety-tier'),
    modalPrivilegeTier: document.getElementById('modal-privilege-tier'),
    modalPayloadCode: document.getElementById('modal-payload-code'),
    modalQid: document.getElementById('modal-qid'),
    holApproveBtn: document.getElementById('hol-approve-btn'),
    holRejectBtn: document.getElementById('hol-reject-btn'),

    // Settings Provider & Mesh Hub Modal
    settingsModalBackdrop: document.getElementById('settings-modal-backdrop'),
    closeSettingsBtn: document.getElementById('close-settings-btn'),
    cancelSettingsBtn: document.getElementById('cancel-settings-btn'),
    saveSettingsBtn: document.getElementById('save-settings-btn'),
    settingsSaveFeedback: document.getElementById('settings-save-feedback'),
    footerActiveEngineChip: document.getElementById('footer-active-engine-chip'),
    hubProviderSelect: document.getElementById('hub-provider-select'),

    // Mesh Tab Elements
    settingRegistryUrl: document.getElementById('setting-registry-url'),
    settingEnterpriseKey: document.getElementById('setting-enterprise-key'),
    settingAutospawnToggle: document.getElementById('setting-autospawn-toggle'),
    settingsStatusDot: document.getElementById('settings-status-dot'),
    settingsStatusText: document.getElementById('settings-status-text'),
    testConnectionBtn: document.getElementById('test-connection-btn'),
    launchRegistryModalBtn: document.getElementById('launch-registry-modal-btn'),

    // Provider Config Elements
    settingGroqModel: document.getElementById('setting-groq-model'),
    settingGroqKey: document.getElementById('setting-groq-key'),
    settingAnthropicModel: document.getElementById('setting-anthropic-model'),
    settingAnthropicKey: document.getElementById('setting-anthropic-key'),
    settingOpenaiModel: document.getElementById('setting-openai-model'),
    settingOpenaiKey: document.getElementById('setting-openai-key'),
    settingGeminiModel: document.getElementById('setting-gemini-model'),
    settingGeminiKey: document.getElementById('setting-gemini-key'),
    settingOllamaEndpoint: document.getElementById('setting-ollama-endpoint'),
    settingOllamaModel: document.getElementById('setting-ollama-model'),
    settingCustomBaseUrl: document.getElementById('setting-custom-base-url'),
    settingCustomModel: document.getElementById('setting-custom-model'),
    settingCustomKey: document.getElementById('setting-custom-key'),

    // Appearance & System Settings Suite Elements
    settingsNavPills: document.querySelectorAll('.settings-nav-pill'),
    themeCards: document.querySelectorAll('.theme-card'),
    accentSwatchBtns: document.querySelectorAll('.accent-swatch-btn'),
    settingFontFamily: document.getElementById('setting-font-family'),
    settingFontSizeSlider: document.getElementById('setting-font-size-slider'),
    settingFontSizeVal: document.getElementById('setting-font-size-val'),
    settingZoomSelect: document.getElementById('setting-zoom-select'),
    settingPerformanceToggle: document.getElementById('setting-performance-toggle'),
    settingWorkspacePath: document.getElementById('setting-workspace-path'),
    settingBrowseWorkspaceBtn: document.getElementById('setting-browse-workspace-btn'),
    settingMinimizeTrayToggle: document.getElementById('setting-minimize-tray-toggle'),
    settingLaunchStartupToggle: document.getElementById('setting-launch-startup-toggle'),
    settingAutoscrollToggle: document.getElementById('setting-autoscroll-toggle'),
    settingNotificationsToggle: document.getElementById('setting-notifications-toggle'),
    settingSoundToggle: document.getElementById('setting-sound-toggle'),
    settingTestSoundBtn: document.getElementById('setting-test-sound-btn'),
    settingClearCacheBtn: document.getElementById('setting-clear-cache-btn')
  };

  // Provider Friendly Labels
  const PROVIDER_NAMES = {
    groq: 'Groq Llama 3.3 70B',
    gemini: 'Google Gemini Flash',
    openai: 'OpenAI GPT-4o Mini',
    claude: 'Anthropic Claude 3.5 Sonnet',
    ollama: 'Ollama Local (Offline)',
    custom: 'Custom OpenAI-Compatible'
  };

  // Slash Command Registry Definition
  const SLASH_COMMANDS = [
    {
      cmd: '/clear',
      desc: 'Instantly flushes chat memory, clears active context, resets token counter.',
      tag: 'action',
      handler: () => handleClearCommand()
    },
    {
      cmd: '/abort',
      desc: 'Sends instant SIGKILL signal to running subprocesses and halts active streams.',
      tag: 'action',
      handler: () => handleAbortCommand()
    },
    {
      cmd: '/status',
      desc: 'Renders in-stream telemetry summary (Active Brain, Tokens, Mesh Health, HOL).',
      tag: 'system',
      handler: () => handleStatusCommand()
    },
    {
      cmd: '/mesh',
      desc: 'Queries 127.0.0.1:8000/api/v1/agents and displays all capabilities in a clean table.',
      tag: 'system',
      handler: () => handleMeshCommand()
    },
    {
      cmd: '/hol',
      desc: 'Toggles between STRICT and PERMISSIVE execution authorization modes.',
      tag: 'system',
      handler: () => handleHolToggleCommand()
    },
    {
      cmd: '/model',
      desc: 'Displays quick inline switcher for active providers and models.',
      tag: 'system',
      handler: () => handleModelCommand()
    }
  ];

  // -------------------------------------------------------------------------
  // Initialization
  // -------------------------------------------------------------------------
  async function init() {
    setExecutionActive(false);
    setupEventListeners();

    if (!window.mycelium) {
      logTerminal('stderr', '[System Error] window.mycelium IPC bridge is unavailable.');
      return;
    }

    // 1. Load initial persisted configuration
    await loadConfig();

    // 2. Wire Coordinator IPC Listeners
    setupCoordinatorListeners();

    // 3. Request workspace file tree immediately
    if (window.mycelium && window.mycelium.getWorkspaceTree) {
      window.mycelium.getWorkspaceTree();
    }

    // 4. Sync Live Registry Health (silent on boot, no stderr spam)
    await syncRegistryHealth(false);

    // Redundant workspace sync fallback to guarantee file tree renders
    setTimeout(() => {
      if (el.fileTree && el.fileTree.querySelector('.tree-loading') && window.mycelium && window.mycelium.getWorkspaceTree) {
        window.mycelium.getWorkspaceTree();
      }
    }, 400);

    // Clean operational startup notice
    logTerminal('info', `[Engine Supervisor] Sandboxed execution engine operational. Active Brain: ${PROVIDER_NAMES[state.config.provider] || 'Groq Llama 3.3 70B'}.`);

    // 5. Periodic mesh ping (every 30s)
    setInterval(() => {
      syncRegistryHealth(false);
    }, 30000);

    // 6. Initialize Token Architecture Teaser with 24h cooldown
    initTokenTeaser();
  }

  // -------------------------------------------------------------------------
  // Coordinator IPC Handlers
  // -------------------------------------------------------------------------
  function setupCoordinatorListeners() {
    // Handshake: Python Coordinator Ready
    window.mycelium.onSystemReady((data) => {
      state.workspacePath = data.workspace;
      const folderName = data.workspace.replace(/\\/g, '/').split('/').pop() || 'workspace';
      el.workspaceCrumb.textContent = folderName;
      el.workspaceCrumb.title = data.workspace;

      logTerminal('info', `[Coordinator Ready] Workspace sandbox: ${data.workspace}`);
      window.mycelium.getWorkspaceTree();
    });

    // Semantic Discovery Event (Sub-10ms match notification)
    window.mycelium.onSemanticDiscovery((data) => {
      renderInlineDiscoveryStep(data);
    });

    // Native Graphical HOL Guard Quarantine Trigger
    window.mycelium.onHolQuarantine((data) => {
      triggerHolModal(data);
      logTerminal(
        'stderr',
        `[HOL Guard Quarantine] Action '${data.intent}' intercepted. Operator authorization required.`
      );
    });

    // Execution Result
    window.mycelium.onExecutionComplete((data) => {
      setExecutionActive(false);
      hideHolModal();
      removeThinkingBubble();
      renderExecutionOutcome(data);
      recordAuditLog(data);

      if (data.success) {
        state.subAgentCycles = 0;
        state.lastExecutionError = null;
        showDesktopNotification(
          'Task Completed Successfully',
          `${data.matchedTool || 'Coordinator'} finished in ${data.latencyMs ? data.latencyMs.toFixed(1) : '0'}ms`
        );
        logTerminal(
          'success',
          `[Execution Success] ${data.matchedTool || 'daemon'} finished in ${data.latencyMs.toFixed(2)}ms (Exit 0)`
        );
        if (data.stdout) {
          logTerminal('stdout', data.stdout);
        }
      } else {
        state.subAgentCycles++;
        state.lastExecutionError = data.stderr || `Command exited with code ${data.exitCode}`;
        showDesktopNotification(
          'HOL Guard / Task Alert',
          `Execution halted: ${data.stderr || 'Action failed'}`
        );
        logTerminal('stderr', `[Execution Blocked/Failed] Exit: ${data.exitCode} | ${data.stderr}`);

        // Circuit Breaker Enforcement: Ceiling of 3 iterations
        if (state.subAgentCycles >= MAX_SUB_AGENT_CYCLES) {
          renderCircuitBreakerCard(
            'Action halted after 3 failed attempts to protect token balance.',
            state.lastExecutionError
          );
          logTerminal('stderr', '[Circuit Breaker Tripped] 3 failed attempts reached. Action halted.');
        }
      }

      // Refresh file tree if mutating action altered workspace
      if (data.safetyTier === 'MUTATING') {
        window.mycelium.getWorkspaceTree();
      }
    });

    // Execution Aborted Signal from daemon
    if (window.mycelium.onExecutionAborted) {
      window.mycelium.onExecutionAborted((data) => {
        setExecutionActive(false);
        hideHolModal();
        removeThinkingBubble();
        renderAbortedMessage();
        logTerminal('stderr', '[Supervisor] Subprocesses and streams safely terminated.');
      });
    }

    // Workspace Tree Data
    window.mycelium.onWorkspaceTree((data) => {
      if (data.tree) {
        renderWorkspaceTree(data.tree);
      }
    });

    // File Content Response
    window.mycelium.onFileContent((data) => {
      if (data.success) {
        displayFileContent(data.filePath, data.content);
      } else {
        logTerminal('stderr', `Could not read file '${data.filePath}': ${data.error}`);
      }
    });

    // Bridge Error
    window.mycelium.onBridgeError((data) => {
      logTerminal('stderr', `[Daemon Error] ${data.error}`);
    });
  }

  // -------------------------------------------------------------------------
  // Config & Settings Management
  // -------------------------------------------------------------------------
  async function loadConfig() {
    try {
      const cfg = await window.mycelium.getConfig();
      state.config = { ...state.config, ...cfg };

      // Apply saved appearance and typography immediately before render
      applyAppearanceSettings(state.config);

      // Populate input controls across all tabs
      if (el.settingRegistryUrl) el.settingRegistryUrl.value = state.config.registryUrl || 'http://127.0.0.1:8000/api/v1';
      if (el.settingEnterpriseKey) el.settingEnterpriseKey.value = state.config.enterpriseKey || '';
      if (el.settingAutospawnToggle) el.settingAutospawnToggle.checked = state.config.autoSpawnRegistry !== false;

      // Appearance: Theme Presets
      const activeTheme = state.config.theme || 'charcoal';
      document.querySelectorAll('.theme-card').forEach((card) => {
        card.classList.toggle('active', card.getAttribute('data-theme') === activeTheme);
      });

      // Appearance: Accent Palette
      const activeAccent = (state.config.accentColor || '#00ff9d').toLowerCase();
      document.querySelectorAll('.accent-swatch-btn').forEach((btn) => {
        btn.classList.toggle('active', (btn.getAttribute('data-accent') || '').toLowerCase() === activeAccent);
      });

      // Appearance: Typography
      if (el.settingFontFamily) el.settingFontFamily.value = state.config.fontFamily || 'JetBrains Mono';
      const fontSize = state.config.fontSize || 14;
      if (el.settingFontSizeSlider) el.settingFontSizeSlider.value = fontSize;
      if (el.settingFontSizeVal) el.settingFontSizeVal.textContent = `${fontSize}px`;

      // Appearance: Zoom & Performance
      if (el.settingZoomSelect) el.settingZoomSelect.value = String(state.config.zoomFactor || 1.0);
      if (el.settingPerformanceToggle) el.settingPerformanceToggle.checked = Boolean(state.config.performanceMode);

      // General: Workspace Directory
      if (el.settingWorkspacePath) el.settingWorkspacePath.value = state.workspacePath || state.config.workspacePath || '';

      // General: System & Behavior Toggles
      if (el.settingMinimizeTrayToggle) el.settingMinimizeTrayToggle.checked = Boolean(state.config.minimizeToTray);
      if (el.settingLaunchStartupToggle) el.settingLaunchStartupToggle.checked = Boolean(state.config.launchOnStartup);
      if (el.settingAutoscrollToggle) el.settingAutoscrollToggle.checked = state.config.autoScrollStream !== false;
      if (el.settingNotificationsToggle) el.settingNotificationsToggle.checked = state.config.notificationsEnabled !== false;
      if (el.settingSoundToggle) el.settingSoundToggle.checked = state.config.soundEffectsEnabled !== false;

      // Groq
      if (el.settingGroqModel) el.settingGroqModel.value = state.config.groqModel || 'llama-3.3-70b-versatile';
      if (el.settingGroqKey) el.settingGroqKey.value = state.config.groqApiKey || '';

      // Anthropic
      if (el.settingAnthropicModel) el.settingAnthropicModel.value = state.config.anthropicModel || 'claude-3-5-sonnet-20241022';
      if (el.settingAnthropicKey) el.settingAnthropicKey.value = state.config.anthropicApiKey || '';

      // OpenAI
      if (el.settingOpenaiModel) el.settingOpenaiModel.value = state.config.openaiModel || 'gpt-4o-mini';
      if (el.settingOpenaiKey) el.settingOpenaiKey.value = state.config.openaiApiKey || '';

      // Gemini
      if (el.settingGeminiModel) el.settingGeminiModel.value = state.config.geminiModel || 'gemini-2.0-flash';
      if (el.settingGeminiKey) el.settingGeminiKey.value = state.config.geminiApiKey || '';

      // Ollama
      if (el.settingOllamaEndpoint) el.settingOllamaEndpoint.value = state.config.ollamaEndpoint || 'http://localhost:11434';
      if (el.settingOllamaModel) el.settingOllamaModel.value = state.config.ollamaModel || 'llama3.2';

      // Custom
      if (el.settingCustomBaseUrl) el.settingCustomBaseUrl.value = state.config.customBaseUrl || 'https://openrouter.ai/api/v1';
      if (el.settingCustomModel) el.settingCustomModel.value = state.config.customModel || 'deepseek/deepseek-r1';
      if (el.settingCustomKey) el.settingCustomKey.value = state.config.customApiKey || '';

      // Restore persisted provider key verification pills
      if (state.config.verificationStatus && typeof state.config.verificationStatus === 'object') {
        Object.entries(state.config.verificationStatus).forEach(([provKey, status]) => {
          const normKey = provKey === 'claude' ? 'anthropic' : provKey;
          const pillId = `${normKey}-validation-pill`;
          const pill = document.getElementById(pillId);
          if (pill && status && status.message) {
            pill.className = `validation-pill ${status.is_verified ? 'valid' : 'invalid'}`;
            const icon = status.is_verified ? '✔' : '✘';
            const prefix = status.is_verified ? 'Key Active & Verified:' : 'Verification Failed:';
            pill.innerHTML = `<span class="pill-icon">${icon}</span> ${prefix} ${escapeHtml(status.message)}`;
          }
        });
      }

      updateActiveEngineUI();
    } catch (err) {
      console.warn('Error loading config:', err);
    }
  }

  function applyAppearanceSettings(cfg) {
    if (!cfg) return;

    // 1. Theme Presets
    const theme = cfg.theme || 'charcoal';
    document.body.classList.remove('theme-midnight', 'theme-charcoal', 'theme-cyber-slate');
    document.body.classList.add(`theme-${theme}`);
    try {
      localStorage.setItem('mycelium_theme', theme);
    } catch (e) {}

    // 2. Performance Mode
    document.body.classList.toggle('low-perf-mode', Boolean(cfg.performanceMode));

    // 3. Accent Palette Tokens
    const accent = cfg.accentColor || '#00ff9d';
    const root = document.documentElement;
    root.style.setProperty('--accent-mint', accent);
    root.style.setProperty('--accent-color', accent);
    root.style.setProperty('--badge-color', accent);
    root.style.setProperty('--border-focus', accent);

    if (accent === '#00ff9d') {
      root.style.setProperty('--accent-mint-glow', 'rgba(0, 255, 157, 0.4)');
      root.style.setProperty('--border-glow-primary', 'rgba(0, 255, 157, 0.35)');
      root.style.setProperty('--grad-emerald-mint', 'linear-gradient(135deg, #00ff9d 0%, #10b981 100%)');
    } else if (accent === '#00e5ff') {
      root.style.setProperty('--accent-mint-glow', 'rgba(0, 229, 255, 0.4)');
      root.style.setProperty('--border-glow-primary', 'rgba(0, 229, 255, 0.35)');
      root.style.setProperty('--grad-emerald-mint', 'linear-gradient(135deg, #00e5ff 0%, #0091ea 100%)');
    } else if (accent === '#a855f7') {
      root.style.setProperty('--accent-mint-glow', 'rgba(168, 85, 247, 0.4)');
      root.style.setProperty('--border-glow-primary', 'rgba(168, 85, 247, 0.35)');
      root.style.setProperty('--grad-emerald-mint', 'linear-gradient(135deg, #a855f7 0%, #7c3aed 100%)');
    } else {
      root.style.setProperty('--accent-mint-glow', 'rgba(255, 255, 255, 0.4)');
      root.style.setProperty('--border-glow-primary', 'rgba(255, 255, 255, 0.35)');
      root.style.setProperty('--grad-emerald-mint', 'linear-gradient(135deg, #ffffff 0%, #cbd5e1 100%)');
    }

    // 4. Typography
    const fonts = {
      'JetBrains Mono': '"JetBrains Mono", Consolas, monospace',
      'Fira Code': '"Fira Code", monospace',
      'Cascadia Code': '"Cascadia Code", Consolas, monospace',
      'System Monospace': 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace'
    };
    if (cfg.fontFamily && fonts[cfg.fontFamily]) {
      root.style.setProperty('--font-mono', fonts[cfg.fontFamily]);
    }

    if (cfg.fontSize) {
      root.style.setProperty('--base-font-size', `${cfg.fontSize}px`);
    }

    // 5. Window Zoom
    if (cfg.zoomFactor && window.mycelium && window.mycelium.setZoomFactor) {
      window.mycelium.setZoomFactor(Number(cfg.zoomFactor));
    }
  }

  function playAuthorizationChime(type = 'success') {
    if (state.config.soundEffectsEnabled === false) return;
    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtx) return;
      const ctx = new AudioCtx();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);
      const now = ctx.currentTime;
      if (type === 'success') {
        osc.frequency.setValueAtTime(523.25, now);
        osc.frequency.exponentialRampToValueAtTime(659.25, now + 0.08);
        osc.frequency.exponentialRampToValueAtTime(783.99, now + 0.16);
        gain.gain.setValueAtTime(0.08, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.35);
        osc.start(now);
        osc.stop(now + 0.35);
      } else {
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(440, now);
        osc.frequency.exponentialRampToValueAtTime(330, now + 0.12);
        gain.gain.setValueAtTime(0.1, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.3);
        osc.start(now);
        osc.stop(now + 0.3);
      }
    } catch (e) {}
  }

  function showDesktopNotification(title, body) {
    if (state.config.notificationsEnabled === false) return;
    try {
      if (typeof Notification !== 'undefined') {
        if (Notification.permission === 'granted') {
          new Notification(title, { body });
        } else if (Notification.permission !== 'denied') {
          Notification.requestPermission().then((permission) => {
            if (permission === 'granted') {
              new Notification(title, { body });
            }
          });
        }
      }
    } catch (e) {}
  }

  function updateVerifiedIndicator(isVerified) {
    const dot = el.activeModelVerifiedDot || document.getElementById('active-model-verified-dot');
    if (!dot) return;
    dot.classList.remove('verified', 'unverified', 'error');
    if (isVerified) {
      dot.classList.add('verified');
      dot.title = 'Active LLM Provider Verified & Operational';
    } else {
      dot.classList.add('unverified');
      dot.title = 'Active LLM Provider Unverified (Click Settings to Test)';
    }
  }

  async function runProviderKeyValidation(prov, isAutoSaveCheck = false) {
    const normProv = (prov === 'claude' || prov === 'anthropic') ? 'claude' : (prov || '').toLowerCase();
    const pillId = normProv === 'claude' ? 'anthropic-validation-pill' : `${normProv}-validation-pill`;
    const pill = document.getElementById(pillId);
    const btn = document.querySelector(`.test-connection-btn[data-provider="${prov}"]`) ||
                document.querySelector(`.validate-key-btn[data-provider="${prov}"]`);

    let key = '';
    let model = '';
    let endpoint = '';
    let baseUrl = '';
    let registryUrl = '';
    let enterpriseKey = '';

    if (normProv === 'groq') {
      key = el.settingGroqKey ? el.settingGroqKey.value.trim() : '';
      model = el.settingGroqModel ? el.settingGroqModel.value : '';
    } else if (normProv === 'claude') {
      key = el.settingAnthropicKey ? el.settingAnthropicKey.value.trim() : '';
      model = el.settingAnthropicModel ? el.settingAnthropicModel.value : '';
    } else if (normProv === 'openai') {
      key = el.settingOpenaiKey ? el.settingOpenaiKey.value.trim() : '';
      model = el.settingOpenaiModel ? el.settingOpenaiModel.value : '';
    } else if (normProv === 'gemini') {
      key = el.settingGeminiKey ? el.settingGeminiKey.value.trim() : '';
      model = el.settingGeminiModel ? el.settingGeminiModel.value : '';
    } else if (normProv === 'ollama') {
      endpoint = el.settingOllamaEndpoint ? el.settingOllamaEndpoint.value.trim() : '';
      model = el.settingOllamaModel ? el.settingOllamaModel.value.trim() : '';
    } else if (normProv === 'custom') {
      baseUrl = el.settingCustomBaseUrl ? el.settingCustomBaseUrl.value.trim() : '';
      model = el.settingCustomModel ? el.settingCustomModel.value.trim() : '';
      key = el.settingCustomKey ? el.settingCustomKey.value.trim() : '';
    } else if (normProv === 'mesh' || normProv === 'mycelium') {
      registryUrl = el.settingRegistryUrl ? el.settingRegistryUrl.value.trim() : '';
      enterpriseKey = el.settingEnterpriseKey ? el.settingEnterpriseKey.value.trim() : '';
    }

    if (btn) btn.disabled = true;
    if (pill) {
      pill.className = 'validation-pill verifying';
      pill.innerHTML = `<span class="pill-spinner"></span> Verifying key with provider...`;
    }

    try {
      const testMethod = (window.mycelium && window.mycelium.testProviderConnection)
        ? window.mycelium.testProviderConnection
        : (window.mycelium && window.mycelium.validateProviderKey);

      if (!testMethod) {
        throw new Error('Connection test bridge unavailable');
      }

      const res = await testMethod({
        provider: normProv,
        key,
        apiKey: key,
        model,
        endpoint,
        baseUrl,
        registryUrl,
        enterpriseKey
      });

      const isSuccess = Boolean(res.success || res.valid);
      const msg = res.message || (isSuccess ? 'Connected successfully' : 'Verification failed');

      // Update in-memory state
      if (!state.config.verificationStatus) state.config.verificationStatus = {};
      state.config.verificationStatus[normProv] = {
        is_verified: isSuccess,
        last_verified: new Date().toISOString(),
        message: msg
      };

      const currentActive = (state.config.provider || 'groq').toLowerCase();
      const normActive = currentActive === 'anthropic' ? 'claude' : currentActive;
      if (normProv === normActive) {
        state.config.is_verified = isSuccess;
        state.config.last_verified = new Date().toISOString();
        updateVerifiedIndicator(isSuccess);
      }

      if (pill) {
        if (isSuccess) {
          pill.className = 'validation-pill valid';
          pill.innerHTML = `<span class="pill-icon">✔</span> Key Active & Verified: ${escapeHtml(msg)}`;
        } else {
          pill.className = 'validation-pill invalid';
          pill.innerHTML = `<span class="pill-icon">✘</span> Verification Failed: ${escapeHtml(msg)}`;
        }
      }

      // Also sync mesh status text if mesh
      if (normProv === 'mesh' || normProv === 'mycelium') {
        if (el.settingsStatusText) {
          el.settingsStatusText.textContent = msg;
        }
        if (el.settingsStatusDot) {
          el.settingsStatusDot.className = isSuccess ? 'status-dot-green' : 'status-dot-amber';
        }
      }

      // Persist verified state
      if (window.mycelium && window.mycelium.saveConfig) {
        window.mycelium.saveConfig({
          verificationStatus: state.config.verificationStatus,
          is_verified: state.config.is_verified,
          last_verified: state.config.last_verified
        });
      }

      return { success: isSuccess, message: msg };
    } catch (err) {
      const errMsg = `Verification failed: ${err.message}`;
      if (pill) {
        pill.className = 'validation-pill invalid';
        pill.innerHTML = `<span class="pill-icon">✘</span> Verification Failed: ${escapeHtml(errMsg)}`;
      }
      return { success: false, message: errMsg };
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  function updateActiveEngineUI() {
    const activeProv = (state.config.provider || 'groq').toLowerCase();
    const displayName = PROVIDER_NAMES[activeProv] || activeProv.toUpperCase();

    // 1. Tag Active Provider in Dropdown Options
    if (el.hubProviderSelect) {
      Array.from(el.hubProviderSelect.options).forEach((opt) => {
        const p = opt.getAttribute('data-provider');
        let raw = opt.getAttribute('data-raw-text');
        if (!raw) {
          raw = opt.textContent.replace(' [ACTIVE]', '');
          opt.setAttribute('data-raw-text', raw);
        }
        if (p === activeProv) {
          opt.textContent = `${raw} [ACTIVE]`;
        } else {
          opt.textContent = raw;
        }
      });
    }

    // 2. Active Engine buttons in panels
    document.querySelectorAll('.use-as-engine-btn').forEach((btn) => {
      const p = btn.getAttribute('data-provider');
      const isThis = (p === activeProv);
      btn.classList.toggle('is-active', isThis);
      const textSpan = btn.querySelector('.btn-engine-text');
      if (textSpan) {
        textSpan.textContent = isThis ? 'Active Engine' : 'Set as Active Engine';
      }
    });

    // 3. Status dots in provider panels
    document.querySelectorAll('.engine-indicator-dot').forEach((dot) => {
      const id = dot.id.replace('dot-', '');
      const isThis = (id === activeProv || (id === 'anthropic' && activeProv === 'claude'));
      dot.classList.toggle('is-active', isThis);
    });

    // 4. Modal Footer chip
    if (el.footerActiveEngineChip) {
      el.footerActiveEngineChip.textContent = `Active Brain: ${displayName}`;
    }

    // 5. Input Dock & Sidebar Badges
    if (el.activeModelLabel) el.activeModelLabel.textContent = displayName;
    if (el.footerProviderText) el.footerProviderText.textContent = `${displayName} Gateway`;

    // 6. Real-time Verified Status Indicator Dot
    const normActive = activeProv === 'anthropic' ? 'claude' : activeProv;
    const provStatus = state.config.verificationStatus && state.config.verificationStatus[normActive];
    const isVerified = Boolean(provStatus ? provStatus.is_verified : state.config.is_verified);
    updateVerifiedIndicator(isVerified);
  }

  async function handleSaveSettings() {
    const activeProv = (state.config.provider || 'groq').toLowerCase();
    const normActive = activeProv === 'anthropic' ? 'claude' : activeProv;

    el.saveSettingsBtn.disabled = true;
    el.saveSettingsBtn.textContent = 'Verifying Active Engine...';

    // Real-Time Pre-Save Guard: Verify currently active engine key
    const check = await runProviderKeyValidation(normActive, true);
    if (!check.success) {
      showSaveFeedback(`Save Blocked: ${check.message}`, 'error');
      playAuthorizationChime('alert');

      // Automatically switch to active provider tab to highlight the failure
      const provToTab = {
        'groq': 'tab-groq',
        'claude': 'tab-anthropic',
        'anthropic': 'tab-anthropic',
        'openai': 'tab-openai',
        'gemini': 'tab-gemini',
        'ollama': 'tab-ollama',
        'custom': 'tab-custom'
      };
      if (provToTab[normActive]) {
        switchProviderPanel(provToTab[normActive]);
      }

      el.saveSettingsBtn.disabled = false;
      el.saveSettingsBtn.textContent = 'Save & Apply Preferences';
      return; // BLOCK SAVE
    }

    const newConfig = {
      provider: state.config.provider || 'groq',
      registryUrl: el.settingRegistryUrl.value.trim() || 'http://127.0.0.1:8000/api/v1',
      enterpriseKey: el.settingEnterpriseKey.value.trim(),
      autoSpawnRegistry: el.settingAutospawnToggle ? el.settingAutospawnToggle.checked : true,

      // Appearance Suite
      theme: state.config.theme || 'charcoal',
      accentColor: state.config.accentColor || '#00ff9d',
      fontFamily: el.settingFontFamily ? el.settingFontFamily.value : (state.config.fontFamily || 'JetBrains Mono'),
      fontSize: el.settingFontSizeSlider ? Number(el.settingFontSizeSlider.value) : (state.config.fontSize || 14),
      zoomFactor: el.settingZoomSelect ? Number(el.settingZoomSelect.value) : (state.config.zoomFactor || 1.0),
      performanceMode: el.settingPerformanceToggle ? el.settingPerformanceToggle.checked : false,

      // General & System
      workspacePath: el.settingWorkspacePath ? el.settingWorkspacePath.value.trim() : (state.workspacePath || ''),
      minimizeToTray: el.settingMinimizeTrayToggle ? el.settingMinimizeTrayToggle.checked : false,
      launchOnStartup: el.settingLaunchStartupToggle ? el.settingLaunchStartupToggle.checked : false,
      autoScrollStream: el.settingAutoscrollToggle ? el.settingAutoscrollToggle.checked : true,
      notificationsEnabled: el.settingNotificationsToggle ? el.settingNotificationsToggle.checked : true,
      soundEffectsEnabled: el.settingSoundToggle ? el.settingSoundToggle.checked : true,

      // Provider Credentials
      groqModel: el.settingGroqModel ? el.settingGroqModel.value : 'llama-3.3-70b-versatile',
      groqApiKey: el.settingGroqKey ? el.settingGroqKey.value.trim() : '',

      anthropicModel: el.settingAnthropicModel ? el.settingAnthropicModel.value : 'claude-3-5-sonnet-20241022',
      anthropicApiKey: el.settingAnthropicKey ? el.settingAnthropicKey.value.trim() : '',

      openaiModel: el.settingOpenaiModel ? el.settingOpenaiModel.value : 'gpt-4o-mini',
      openaiApiKey: el.settingOpenaiKey ? el.settingOpenaiKey.value.trim() : '',

      geminiModel: el.settingGeminiModel ? el.settingGeminiModel.value : 'gemini-2.0-flash',
      geminiApiKey: el.settingGeminiKey ? el.settingGeminiKey.value.trim() : '',

      ollamaEndpoint: el.settingOllamaEndpoint ? el.settingOllamaEndpoint.value.trim() : 'http://localhost:11434',
      ollamaModel: el.settingOllamaModel ? el.settingOllamaModel.value.trim() : 'llama3.2',

      customBaseUrl: el.settingCustomBaseUrl ? el.settingCustomBaseUrl.value.trim() : 'https://openrouter.ai/api/v1',
      customModel: el.settingCustomModel ? el.settingCustomModel.value.trim() : 'deepseek/deepseek-r1',
      customApiKey: el.settingCustomKey ? el.settingCustomKey.value.trim() : '',

      // Key Verification State
      is_verified: true,
      last_verified: new Date().toISOString(),
      verificationStatus: state.config.verificationStatus || {}
    };

    try {
      const res = await window.mycelium.saveConfig(newConfig);
      if (res.success) {
        state.config = { ...state.config, ...newConfig };
        applyAppearanceSettings(state.config);
        updateActiveEngineUI();
        playAuthorizationChime('success');

        showSaveFeedback('✔ Verified & Preferences Saved!', 'success');
        logTerminal('info', `[Settings Hub] Preferences saved. Brain verified: ${PROVIDER_NAMES[state.config.provider] || state.config.provider}`);

        // Re-check registry connection with updated URL
        await syncRegistryHealth(true);

        setTimeout(() => {
          closeSettingsModal();
        }, 900);
      } else {
        showSaveFeedback(`Failed: ${res.error}`, 'error');
      }
    } catch (err) {
      showSaveFeedback(`Save error: ${err.message}`, 'error');
    } finally {
      el.saveSettingsBtn.disabled = false;
      el.saveSettingsBtn.textContent = 'Save & Apply Preferences';
    }
  }

  function showSaveFeedback(text, type = 'success') {
    if (!el.settingsSaveFeedback) return;
    el.settingsSaveFeedback.textContent = text;
    el.settingsSaveFeedback.style.color = type === 'success' ? '#00ff9d' : '#ff7843';
    setTimeout(() => {
      if (el.settingsSaveFeedback) el.settingsSaveFeedback.textContent = '';
    }, 4000);
  }

  function openSettingsModal(targetPanel) {
    el.settingsModalBackdrop.classList.remove('hidden');
    testRegistryConnection();

    // Default to Appearance Suite tab unless explicitly requesting a provider or panel
    const desiredTab = targetPanel || 'tab-appearance';
    switchProviderPanel(desiredTab);
  }

  function switchProviderPanel(targetTabId) {
    if (el.hubProviderSelect) {
      el.hubProviderSelect.value = targetTabId;
    }
    document.querySelectorAll('.settings-tab-panel').forEach((panel) => {
      panel.classList.toggle('active', panel.id === targetTabId);
    });
    // Highlight matching navigation pill (model providers grouped under Model Providers pill)
    const isModelTab = ['tab-groq', 'tab-anthropic', 'tab-openai', 'tab-gemini', 'tab-ollama', 'tab-custom'].includes(targetTabId);
    document.querySelectorAll('.settings-nav-pill').forEach((pill) => {
      const pTab = pill.getAttribute('data-tab');
      if (pTab === targetTabId) {
        pill.classList.add('active');
      } else if (pTab === 'tab-groq' && isModelTab) {
        pill.classList.add('active');
      } else {
        pill.classList.remove('active');
      }
    });
  }

  function closeSettingsModal() {
    el.settingsModalBackdrop.classList.add('hidden');
    // Hide any open tooltips
    document.querySelectorAll('.help-tooltip-card').forEach((tt) => tt.classList.add('hidden'));
  }

  // -------------------------------------------------------------------------
  // Real-Time Mycelium Mesh Sync
  // -------------------------------------------------------------------------
  async function syncRegistryHealth(logStatus = false) {
    if (!window.mycelium) return;
    const url = state.config.registryUrl || 'http://127.0.0.1:8000/api/v1';

    try {
      const res = await window.mycelium.checkRegistryHealth(url);
      state.registryStatus = res;

      if (res.online) {
        // Online Mesh Registry Connected
        el.registryBadge.classList.add('online');
        el.registryBadge.classList.remove('offline');
        el.registryBadgeText.textContent = `• ${res.total} NODES ACTIVE • ${res.latencyMs.toFixed(0)}ms`;
        el.registryPingDot.style.background = '#00ff9d';

        // Keep In-Stream Alert Banner Permanently Hidden
        el.registryAlertBanner.classList.add('hidden');
        el.registryAlertBanner.style.display = 'none';

        // Sidebar Footer Status
        el.footerStatusText.textContent = `Vector-Mesh Active (${res.total} nodes)`;
        el.footerLatencyPill.textContent = `${res.latencyMs.toFixed(0)}ms`;
        el.footerLatencyPill.style.color = '#00ff9d';
        el.footerPulseCore.style.background = '#00ff9d';
        el.footerPulseRing.style.borderColor = 'rgba(0, 255, 157, 0.4)';

        // Settings Modal Status Strip
        if (el.settingsStatusDot) el.settingsStatusDot.className = 'status-dot-emerald';
        if (el.settingsStatusText) el.settingsStatusText.textContent = `Mesh Registry: Connected (${res.total} nodes, ${res.latencyMs.toFixed(0)}ms)`;

        if (logStatus) {
          logTerminal('success', `[Registry Mesh] Synced: ${res.total} nodes online (${res.latencyMs.toFixed(1)}ms).`);
        }
      } else {
        // Autonomous Engine Mode: Confident, Active, Ready (No false "Offline" alarms)
        el.registryBadge.classList.add('online');
        el.registryBadge.classList.remove('offline');
        el.registryBadgeText.textContent = `• AUTONOMOUS ENGINE • READY`;
        el.registryPingDot.style.background = '#00ff9d';

        // Keep In-Stream Alert Banner Permanently Hidden
        el.registryAlertBanner.classList.add('hidden');
        el.registryAlertBanner.style.display = 'none';

        // Sidebar Footer Status: Active & Operational
        el.footerStatusText.textContent = 'Autonomous Engine Active';
        el.footerLatencyPill.textContent = 'READY';
        el.footerLatencyPill.style.color = '#00ff9d';
        el.footerPulseCore.style.background = '#00ff9d';
        el.footerPulseRing.style.borderColor = 'rgba(0, 255, 157, 0.4)';

        // Settings Modal Status Strip
        if (el.settingsStatusDot) el.settingsStatusDot.className = 'status-dot-amber';
        if (el.settingsStatusText) el.settingsStatusText.textContent = `Mesh Registry: Standalone Mode (Mesh Hub available for optional multi-agent discovery)`;

        if (logStatus) {
          logTerminal('info', `[Registry] Standalone mode active. Autonomous engine ready.`);
        }
      }
    } catch (err) {
      console.warn('Mesh health check failed:', err);
    }
  }

  async function testRegistryConnection() {
    el.settingsStatusText.textContent = 'Probing semantic registry...';
    el.settingsStatusDot.className = 'status-dot-amber';
    await runProviderKeyValidation('mesh');
    await syncRegistryHealth(true);
  }

  async function handleLaunchLocalRegistry(triggerBtn) {
    if (state.isPollingRegistry) return;
    state.isPollingRegistry = true;

    if (triggerBtn) {
      triggerBtn.disabled = true;
      triggerBtn.textContent = 'Launching Server...';
    }

    logTerminal('cmd', `$ python -m uvicorn server.app:app --host 127.0.0.1 --port 8000`);
    const launchRes = await window.mycelium.launchRegistry();

    if (launchRes.success) {
      logTerminal('info', `[Registry Supervisor] ${launchRes.message}`);

      let attempts = 0;
      const pollInterval = setInterval(async () => {
        attempts++;
        const health = await window.mycelium.checkRegistryHealth(state.config.registryUrl);
        if (health.online) {
          clearInterval(pollInterval);
          state.isPollingRegistry = false;
          await syncRegistryHealth(true);
          if (triggerBtn) {
            triggerBtn.disabled = false;
            triggerBtn.textContent = 'Registry Online';
            setTimeout(() => {
              triggerBtn.textContent = 'Launch Registry';
            }, 3000);
          }
        } else if (attempts >= 12) {
          clearInterval(pollInterval);
          state.isPollingRegistry = false;
          if (triggerBtn) {
            triggerBtn.disabled = false;
            triggerBtn.textContent = 'Launch Local Registry';
          }
          logTerminal('stderr', '[Registry Supervisor] Launch timeout. Check uvicorn dependencies in terminal.');
        }
      }, 1500);
    } else {
      state.isPollingRegistry = false;
      if (triggerBtn) {
        triggerBtn.disabled = false;
        triggerBtn.textContent = 'Launch Failed';
      }
      logTerminal('stderr', `[Registry Supervisor] Failed to spawn uvicorn: ${launchRes.error}`);
    }
  }



  // -------------------------------------------------------------------------
  // Event Listeners
  // -------------------------------------------------------------------------
  function setupEventListeners() {
    // Send Button: Sends or Aborts based on execution state
    el.sendBtn.addEventListener('click', () => {
      if (state.isDispatching) {
        abortActiveExecution();
      } else {
        handleSendPrompt();
      }
    });

    // Keydown handling for slash navigation and execution
    el.promptInput.addEventListener('keydown', handlePromptKeydown);

    // Auto-expand Textarea & Slash detection
    el.promptInput.addEventListener('input', handlePromptInput);

    // Outside click closes slash command popover
    document.addEventListener('click', (e) => {
      if (!e.target.closest('#slash-command-menu') && e.target !== el.promptInput) {
        hideSlashMenu();
      }
    });

    // Starter Suggestion Chips
    document.querySelectorAll('.starter-chip').forEach((chip) => {
      chip.addEventListener('click', () => {
        const promptText = chip.getAttribute('data-prompt');
        el.promptInput.value = promptText;
        handleSendPrompt();
      });
    });

    // Privilege Toggle (PERSON vs BACKGROUND)
    el.privilegeToggle.addEventListener('click', () => {
      if (state.privilegeTier === 'PERSON') {
        state.privilegeTier = 'BACKGROUND';
        el.privilegeLabel.textContent = 'BACKGROUND (Automated)';
        el.privilegeToggle.classList.add('background');
      } else {
        state.privilegeTier = 'PERSON';
        el.privilegeLabel.textContent = 'PERSON (Foreground)';
        el.privilegeToggle.classList.remove('background');
      }
    });

    // Refresh Files & Sync Mesh
    el.refreshTreeBtn.addEventListener('click', () => {
      if (window.mycelium) {
        window.mycelium.getWorkspaceTree();
        syncRegistryHealth(true);
        logTerminal('info', '[Workspace] Refreshing file tree and syncing mesh...');
      }
    });

    // Top Header Registry / Nodes Active Badge: Inspect active mesh nodes (/mesh)
    if (el.registryBadge) {
      el.registryBadge.addEventListener('click', () => {
        handleMeshCommand();
      });
    }

    // Settings Modal Open / Close
    el.settingsBtn.addEventListener('click', openSettingsModal);
    el.closeSettingsBtn.addEventListener('click', closeSettingsModal);
    if (el.cancelSettingsBtn) el.cancelSettingsBtn.addEventListener('click', closeSettingsModal);
    el.settingsModalBackdrop.addEventListener('click', (e) => {
      if (e.target === el.settingsModalBackdrop) {
        closeSettingsModal();
      }
    });

    // Provider Dropdown Selection Listener
    if (el.hubProviderSelect) {
      el.hubProviderSelect.addEventListener('change', (e) => {
        switchProviderPanel(e.target.value);
      });
    }

    // "Set as Active Engine" Buttons
    document.querySelectorAll('.use-as-engine-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        const prov = btn.getAttribute('data-provider');
        if (prov) {
          state.config.provider = prov;
          updateActiveEngineUI();
          showSaveFeedback(`Switched active brain to ${PROVIDER_NAMES[prov] || prov}`, 'success');
          logTerminal('info', `[Engine Switch] Active brain selected: ${PROVIDER_NAMES[prov] || prov}`);
        }
      });
    });

    // Interactive Question Help Badges (?)
    document.querySelectorAll('.help-question-btn').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const tooltipId = btn.getAttribute('data-tooltip');
        const target = document.getElementById(tooltipId);
        if (target) {
          const wasHidden = target.classList.contains('hidden');
          // Close other tooltips first
          document.querySelectorAll('.help-tooltip-card').forEach((tt) => tt.classList.add('hidden'));
          if (wasHidden) {
            target.classList.remove('hidden');
          }
        }
      });
    });

    // Click outside closes tooltips
    document.addEventListener('click', (e) => {
      if (!e.target.closest('.help-tooltip-card') && !e.target.closest('.help-question-btn')) {
        document.querySelectorAll('.help-tooltip-card').forEach((tt) => tt.classList.add('hidden'));
      }
    });

    // External Browser Link Launcher (shell.openExternal)
    document.querySelectorAll('.open-external-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        const url = btn.getAttribute('data-url');
        if (url && window.mycelium && window.mycelium.openExternal) {
          window.mycelium.openExternal(url);
          logTerminal('info', `[Browser Launcher] Opened ${url}`);
        }
      });
    });

    // Live Key & Endpoint Validation Buttons
    document.querySelectorAll('.test-connection-btn, .validate-key-btn').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const prov = btn.getAttribute('data-provider');
        if (prov) {
          runProviderKeyValidation(prov);
        }
      });
    });

    // Reset verification pill and dock indicator when key/endpoint inputs are modified
    ['setting-groq-key', 'setting-anthropic-key', 'setting-openai-key', 'setting-gemini-key', 'setting-ollama-endpoint', 'setting-custom-key'].forEach((id) => {
      const input = document.getElementById(id);
      if (input) {
        input.addEventListener('input', () => {
          const provMap = {
            'setting-groq-key': 'groq',
            'setting-anthropic-key': 'claude',
            'setting-openai-key': 'openai',
            'setting-gemini-key': 'gemini',
            'setting-ollama-endpoint': 'ollama',
            'setting-custom-key': 'custom'
          };
          const prov = provMap[id];
          const pillId = prov === 'claude' ? 'anthropic-validation-pill' : `${prov}-validation-pill`;
          const pill = document.getElementById(pillId);
          if (pill) {
            pill.className = 'validation-pill hidden';
          }
          if (state.config.verificationStatus && state.config.verificationStatus[prov]) {
            state.config.verificationStatus[prov].is_verified = false;
          }
          const currentActive = (state.config.provider || 'groq').toLowerCase();
          const normActive = currentActive === 'anthropic' ? 'claude' : currentActive;
          if (prov === normActive) {
            state.config.is_verified = false;
            updateVerifiedIndicator(false);
          }
        });
      }
    });

    // Quick Model Selection Chips
    document.querySelectorAll('.quick-chip').forEach((chip) => {
      chip.addEventListener('click', () => {
        const targetId = chip.getAttribute('data-target');
        const val = chip.getAttribute('data-val');
        const input = document.getElementById(targetId);
        if (input && val) {
          input.value = val;
        }
      });
    });

    // -----------------------------------------------------------------------
    // Appearance & System Settings Suite Event Handlers
    // -----------------------------------------------------------------------
    // Settings Navigation Pills
    document.querySelectorAll('.settings-nav-pill').forEach((pill) => {
      pill.addEventListener('click', () => {
        const targetTab = pill.getAttribute('data-tab');
        switchProviderPanel(targetTab);
      });
    });

    // Theme Presets Card Selection
    document.querySelectorAll('.theme-card').forEach((card) => {
      card.addEventListener('click', () => {
        const theme = card.getAttribute('data-theme');
        document.querySelectorAll('.theme-card').forEach((c) => c.classList.remove('active'));
        card.classList.add('active');
        state.config.theme = theme;
        applyAppearanceSettings(state.config);
        if (window.mycelium && window.mycelium.saveConfig) {
          window.mycelium.saveConfig({ theme });
        }
        logTerminal('info', `[Appearance] Theme preset applied: ${theme}`);
      });
    });

    // Accent Palette Swatches
    document.querySelectorAll('.accent-swatch-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        const accent = btn.getAttribute('data-accent');
        document.querySelectorAll('.accent-swatch-btn').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        state.config.accentColor = accent;
        applyAppearanceSettings(state.config);
        if (window.mycelium && window.mycelium.saveConfig) {
          window.mycelium.saveConfig({ accentColor: accent });
        }
        logTerminal('info', `[Appearance] Accent color palette updated: ${accent}`);
      });
    });

    // Typography: Font Family Dropdown
    if (el.settingFontFamily) {
      el.settingFontFamily.addEventListener('change', (e) => {
        const fontFamily = e.target.value;
        state.config.fontFamily = fontFamily;
        applyAppearanceSettings(state.config);
        if (window.mycelium && window.mycelium.saveConfig) {
          window.mycelium.saveConfig({ fontFamily });
        }
        logTerminal('info', `[Appearance] Editor font family changed: ${fontFamily}`);
      });
    }

    // Typography: Font Size Slider
    if (el.settingFontSizeSlider) {
      el.settingFontSizeSlider.addEventListener('input', (e) => {
        const size = Number(e.target.value);
        if (el.settingFontSizeVal) el.settingFontSizeVal.textContent = `${size}px`;
        state.config.fontSize = size;
        applyAppearanceSettings(state.config);
      });
      el.settingFontSizeSlider.addEventListener('change', (e) => {
        const size = Number(e.target.value);
        if (window.mycelium && window.mycelium.saveConfig) {
          window.mycelium.saveConfig({ fontSize: size });
        }
      });
    }

    // Window Zoom Factor
    if (el.settingZoomSelect) {
      el.settingZoomSelect.addEventListener('change', (e) => {
        const zoomFactor = Number(e.target.value);
        state.config.zoomFactor = zoomFactor;
        if (window.mycelium && window.mycelium.setZoomFactor) {
          window.mycelium.setZoomFactor(zoomFactor);
        }
        if (window.mycelium && window.mycelium.saveConfig) {
          window.mycelium.saveConfig({ zoomFactor });
        }
        logTerminal('info', `[Appearance] Window zoom factor set to ${Math.round(zoomFactor * 100)}%`);
      });
    }

    // Performance / Low Spec Mode Toggle
    if (el.settingPerformanceToggle) {
      el.settingPerformanceToggle.addEventListener('change', (e) => {
        const performanceMode = e.target.checked;
        state.config.performanceMode = performanceMode;
        applyAppearanceSettings(state.config);
        if (window.mycelium && window.mycelium.saveConfig) {
          window.mycelium.saveConfig({ performanceMode });
        }
        logTerminal('info', `[Appearance] Performance mode ${performanceMode ? 'ENABLED (zero blurs)' : 'DISABLED'}`);
      });
    }

    // Active Workspace Selector: Browse Folder Button
    if (el.settingBrowseWorkspaceBtn) {
      el.settingBrowseWorkspaceBtn.addEventListener('click', async () => {
        if (!window.mycelium || !window.mycelium.selectWorkspaceDirectory) return;
        const res = await window.mycelium.selectWorkspaceDirectory();
        if (!res.canceled && res.path) {
          state.workspacePath = res.path;
          if (el.settingWorkspacePath) el.settingWorkspacePath.value = res.path;
          const folderName = res.path.replace(/\\/g, '/').split('/').pop() || 'workspace';
          el.workspaceCrumb.textContent = folderName;
          el.workspaceCrumb.title = res.path;
          logTerminal('success', `[Workspace] Active workspace switched to: ${res.path}`);
          if (window.mycelium.getWorkspaceTree) {
            window.mycelium.getWorkspaceTree();
          }
        }
      });
    }

    // Desktop Behavior Toggles
    if (el.settingMinimizeTrayToggle) {
      el.settingMinimizeTrayToggle.addEventListener('change', (e) => {
        const minimizeToTray = e.target.checked;
        state.config.minimizeToTray = minimizeToTray;
        if (window.mycelium && window.mycelium.saveConfig) {
          window.mycelium.saveConfig({ minimizeToTray });
        }
      });
    }

    if (el.settingLaunchStartupToggle) {
      el.settingLaunchStartupToggle.addEventListener('change', (e) => {
        const launchOnStartup = e.target.checked;
        state.config.launchOnStartup = launchOnStartup;
        if (window.mycelium && window.mycelium.setLoginItemSettings) {
          window.mycelium.setLoginItemSettings(launchOnStartup);
        }
        if (window.mycelium && window.mycelium.saveConfig) {
          window.mycelium.saveConfig({ launchOnStartup });
        }
      });
    }

    if (el.settingAutoscrollToggle) {
      el.settingAutoscrollToggle.addEventListener('change', (e) => {
        const autoScrollStream = e.target.checked;
        state.config.autoScrollStream = autoScrollStream;
        if (window.mycelium && window.mycelium.saveConfig) {
          window.mycelium.saveConfig({ autoScrollStream });
        }
      });
    }

    if (el.settingNotificationsToggle) {
      el.settingNotificationsToggle.addEventListener('change', (e) => {
        const notificationsEnabled = e.target.checked;
        state.config.notificationsEnabled = notificationsEnabled;
        if (notificationsEnabled && typeof Notification !== 'undefined') {
          if (Notification.permission !== 'granted') {
            Notification.requestPermission();
          }
        }
        if (window.mycelium && window.mycelium.saveConfig) {
          window.mycelium.saveConfig({ notificationsEnabled });
        }
      });
    }

    if (el.settingSoundToggle) {
      el.settingSoundToggle.addEventListener('change', (e) => {
        const soundEffectsEnabled = e.target.checked;
        state.config.soundEffectsEnabled = soundEffectsEnabled;
        if (window.mycelium && window.mycelium.saveConfig) {
          window.mycelium.saveConfig({ soundEffectsEnabled });
        }
      });
    }

    if (el.settingTestSoundBtn) {
      el.settingTestSoundBtn.addEventListener('click', () => {
        playAuthorizationChime('success');
      });
    }

    // Maintenance & Cache Reset Button
    if (el.settingClearCacheBtn) {
      el.settingClearCacheBtn.addEventListener('click', async () => {
        const confirmed = window.confirm(
          'Are you sure you want to flush session cache and clear local desktop storage data?'
        );
        if (!confirmed) return;
        el.settingClearCacheBtn.disabled = true;
        el.settingClearCacheBtn.textContent = 'Clearing...';
        try {
          if (window.mycelium && window.mycelium.clearAppData) {
            await window.mycelium.clearAppData();
          }
          logTerminal('success', '[Maintenance] Session cache and local storage data cleared.');
          showSaveFeedback('Session cache flushed successfully!', 'success');
        } catch (err) {
          logTerminal('stderr', `[Maintenance Error] ${err.message}`);
        } finally {
          el.settingClearCacheBtn.disabled = false;
          el.settingClearCacheBtn.innerHTML = `
            <svg viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.8">
              <path d="M2 4h12M5.3 4V2.7A1.3 1.3 0 0 1 6.7 1.3h2.6a1.3 1.3 0 0 1 1.3 1.4V4m2 0v9.3a1.3 1.3 0 0 1-1.3 1.4H4.7a1.3 1.3 0 0 1-1.4-1.4V4"></path>
            </svg>
            <span>Flush Cache</span>
          `;
        }
      });
    }

    // Settings Save & Connect Actions
    el.saveSettingsBtn.addEventListener('click', handleSaveSettings);
    el.testConnectionBtn.addEventListener('click', testRegistryConnection);
    el.launchRegistryModalBtn.addEventListener('click', () => handleLaunchLocalRegistry(el.launchRegistryModalBtn));
    el.launchRegistryBannerBtn.addEventListener('click', () => handleLaunchLocalRegistry(el.launchRegistryBannerBtn));

    // Show/Hide Password Eye Buttons with clean vector SVGs
    const SVG_EYE_VISIBLE = `<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>`;
    const SVG_EYE_HIDDEN = `<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>`;

    document.querySelectorAll('.toggle-visibility-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        const targetId = btn.getAttribute('data-target');
        const input = document.getElementById(targetId);
        if (input) {
          if (input.type === 'password') {
            input.type = 'text';
            btn.innerHTML = SVG_EYE_HIDDEN;
          } else {
            input.type = 'password';
            btn.innerHTML = SVG_EYE_VISIBLE;
          }
        }
      });
    });

    // Drawer Controls
    el.toggleDrawerBtn.addEventListener('click', toggleDrawer);
    el.closeDrawerBtn.addEventListener('click', () => setDrawerState(false));

    el.clearTerminalBtn.addEventListener('click', () => {
      el.terminalLogs.innerHTML = '<div class="term-row dim">[Terminal cleared]</div>';
    });

    // Drawer Tabs
    el.drawerTabs.forEach((tab) => {
      tab.addEventListener('click', () => {
        const target = tab.getAttribute('data-tab');
        switchDrawerTab(target);
      });
    });

    // Copy File Content
    el.copyFileBtn.addEventListener('click', () => {
      if (state.selectedFileContent) {
        navigator.clipboard.writeText(state.selectedFileContent).then(() => {
          el.copyFileBtn.textContent = 'Copied to Clipboard!';
          setTimeout(() => {
            el.copyFileBtn.textContent = 'Copy Content';
          }, 1800);
        });
      }
    });

    // HOL Modal Operator Actions
    el.holApproveBtn.addEventListener('click', () => {
      if (state.currentQuarantineId && window.mycelium) {
        playAuthorizationChime('success');
        window.mycelium.submitHolDecision(state.currentQuarantineId, true);
        logTerminal(
          'success',
          `[HOL Guard] Operator AUTHORIZED action (QID: ${state.currentQuarantineId.substring(0, 8)})`
        );
        hideHolModal();
      }
    });

    el.holRejectBtn.addEventListener('click', () => {
      if (state.currentQuarantineId && window.mycelium) {
        playAuthorizationChime('alert');
        window.mycelium.submitHolDecision(state.currentQuarantineId, false);
        logTerminal(
          'stderr',
          `[HOL Guard] Operator DENIED action (QID: ${state.currentQuarantineId.substring(0, 8)})`
        );
        hideHolModal();
      }
    });

    // Wire Universal Developer Keyboard Shortcuts
    setupUniversalShortcuts();
  }

  // -------------------------------------------------------------------------
  // Universal Developer Shortcuts (Ctrl+,, Ctrl+B, Ctrl+K, Ctrl+`, Escape)
  // -------------------------------------------------------------------------
  function setupUniversalShortcuts() {
    let lastTriggerTime = 0;

    function handleShortcutAction(action) {
      const now = Date.now();
      if (now - lastTriggerTime < 100) return;
      lastTriggerTime = now;

      switch (action) {
        case 'toggle-settings':
          if (el.settingsModalBackdrop && !el.settingsModalBackdrop.classList.contains('hidden')) {
            closeSettingsModal();
          } else {
            openSettingsModal();
          }
          break;

        case 'toggle-sidebar':
          toggleSidebar();
          break;

        case 'focus-prompt':
          focusSlashPrompt();
          break;

        case 'toggle-drawer':
          toggleDrawer();
          break;

        case 'escape':
          handleEscapeDismiss();
          break;
      }
    }

    function toggleSidebar() {
      const sidebarEl = el.sidebar || document.querySelector('.sidebar');
      if (sidebarEl) {
        sidebarEl.classList.toggle('collapsed');
      }
    }

    function focusSlashPrompt() {
      if (!el.promptInput) return;
      el.promptInput.focus();
      if (!el.promptInput.value.startsWith('/')) {
        el.promptInput.value = '/' + el.promptInput.value;
      }
      el.promptInput.dispatchEvent(new Event('input', { bubbles: true }));
      el.promptInput.selectionStart = el.promptInput.selectionEnd = el.promptInput.value.length;
    }

    function handleEscapeDismiss() {
      // 1. Close active slash autocomplete popover
      if (state.slashMenuVisible) {
        hideSlashMenu();
        return;
      }

      // 2. Close active Settings Modal
      if (el.settingsModalBackdrop && !el.settingsModalBackdrop.classList.contains('hidden')) {
        closeSettingsModal();
        return;
      }

      // 3. Close active HOL Guard security modal
      if (el.holModalBackdrop && !el.holModalBackdrop.classList.contains('hidden')) {
        hideHolModal();
        return;
      }

      // 4. Defocus active input or textarea
      const activeEl = document.activeElement;
      if (activeEl && (activeEl.tagName === 'INPUT' || activeEl.tagName === 'TEXTAREA')) {
        activeEl.blur();
        return;
      }
    }

    // Capture-phase global keyboard listener
    window.addEventListener('keydown', (e) => {
      const isCmdOrCtrl = e.ctrlKey || e.metaKey;
      const target = e.target;
      const targetTag = target && target.tagName ? target.tagName.toUpperCase() : '';
      const isRegularInput = (targetTag === 'INPUT' || targetTag === 'TEXTAREA') && target !== el.promptInput;
      const isPromptInput = target === el.promptInput;

      // Escape: Universal dedicated hotkey (always triggers)
      if (e.key === 'Escape') {
        e.preventDefault();
        e.stopPropagation();
        handleShortcutAction('escape');
        return;
      }

      // Ctrl + , (or Cmd + ,): Universal dedicated hotkey for Settings (always triggers)
      if (isCmdOrCtrl && (e.key === ',' || e.code === 'Comma')) {
        e.preventDefault();
        e.stopPropagation();
        handleShortcutAction('toggle-settings');
        return;
      }

      // Dedicated hotkey: Ctrl + K on the chat prompt bar or outside inputs
      if (isCmdOrCtrl && (e.key === 'k' || e.key === 'K')) {
        if (!isRegularInput) {
          e.preventDefault();
          e.stopPropagation();
          handleShortcutAction('focus-prompt');
          return;
        }
      }

      // If user is editing regular text inside an input or textarea, DO NOT intercept regular typing
      if (isRegularInput || (isPromptInput && !isCmdOrCtrl)) {
        return;
      }

      // Ctrl + B (or Cmd + B): Toggle Workspace Explorer sidebar (when not editing text inputs)
      if (isCmdOrCtrl && (e.key === 'b' || e.key === 'B')) {
        e.preventDefault();
        e.stopPropagation();
        handleShortcutAction('toggle-sidebar');
        return;
      }

      // Ctrl + ` (Backtick): Toggle bottom Terminal / Logs drawer (when not editing text inputs)
      if (isCmdOrCtrl && (e.key === '`' || e.code === 'Backquote')) {
        e.preventDefault();
        e.stopPropagation();
        handleShortcutAction('toggle-drawer');
        return;
      }
    }, true);

    // Native IPC shortcut bridge from Electron Menu accelerators
    if (window.mycelium && window.mycelium.onShortcut) {
      window.mycelium.onShortcut((action) => {
        handleShortcutAction(action);
      });
    }
  }

  // -------------------------------------------------------------------------
  // Slash Command Engine & Prompt Input Handlers
  // -------------------------------------------------------------------------
  function handlePromptInput() {
    // Auto-expand textarea
    el.promptInput.style.height = 'auto';
    el.promptInput.style.height = Math.min(el.promptInput.scrollHeight, 160) + 'px';

    const val = el.promptInput.value.trim();
    if (val.startsWith('/')) {
      const query = val.toLowerCase();
      state.slashFilteredCommands = SLASH_COMMANDS.filter((cmd) => cmd.cmd.startsWith(query));
      if (state.slashFilteredCommands.length > 0) {
        state.slashSelectedIndex = 0;
        renderSlashMenu();
        showSlashMenu();
      } else {
        hideSlashMenu();
      }
    } else {
      hideSlashMenu();
    }
  }

  function handlePromptKeydown(e) {
    if (state.slashMenuVisible) {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        state.slashSelectedIndex = (state.slashSelectedIndex + 1) % state.slashFilteredCommands.length;
        updateSlashMenuSelection();
        return;
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        state.slashSelectedIndex = (state.slashSelectedIndex - 1 + state.slashFilteredCommands.length) % state.slashFilteredCommands.length;
        updateSlashMenuSelection();
        return;
      }
      if (e.key === 'Enter' || e.key === 'Tab') {
        e.preventDefault();
        const selected = state.slashFilteredCommands[state.slashSelectedIndex];
        if (selected) {
          hideSlashMenu();
          selected.handler();
        }
        return;
      }
      if (e.key === 'Escape') {
        e.preventDefault();
        hideSlashMenu();
        return;
      }
    }

    if (e.key === 'Escape' && state.isDispatching) {
      e.preventDefault();
      abortActiveExecution();
      return;
    }

    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      if (state.isDispatching) {
        abortActiveExecution();
      } else {
        handleSendPrompt();
      }
    }
  }

  function renderSlashMenu() {
    if (!el.slashCommandItems) return;
    el.slashCommandItems.innerHTML = '';

    state.slashFilteredCommands.forEach((cmdObj, idx) => {
      const item = document.createElement('div');
      item.className = `slash-item ${idx === state.slashSelectedIndex ? 'selected' : ''}`;
      item.innerHTML = `
        <span class="slash-item-cmd">${escapeHtml(cmdObj.cmd)}</span>
        <span class="slash-item-desc">${escapeHtml(cmdObj.desc)}</span>
        <span class="slash-item-tag ${cmdObj.tag}">${escapeHtml(cmdObj.tag)}</span>
      `;
      item.addEventListener('click', () => {
        hideSlashMenu();
        cmdObj.handler();
      });
      el.slashCommandItems.appendChild(item);
    });
  }

  function updateSlashMenuSelection() {
    if (!el.slashCommandItems) return;
    const items = el.slashCommandItems.querySelectorAll('.slash-item');
    items.forEach((item, idx) => {
      item.classList.toggle('selected', idx === state.slashSelectedIndex);
    });
  }

  function showSlashMenu() {
    if (!el.slashCommandMenu) return;
    state.slashMenuVisible = true;
    el.slashCommandMenu.classList.remove('hidden');
  }

  function hideSlashMenu() {
    if (!el.slashCommandMenu) return;
    state.slashMenuVisible = false;
    el.slashCommandMenu.classList.add('hidden');
  }

  // -------------------------------------------------------------------------
  // Token Consumption & Sliding History Buffer
  // -------------------------------------------------------------------------
  function estimateTokens(text) {
    if (!text) return 0;
    return Math.ceil(text.length / 4);
  }

  function updateTokenTally(addedTokens) {
    state.sessionTokens += (addedTokens || 0);
    const estCost = ((state.sessionTokens / 1000) * 0.0005).toFixed(4);
    if (el.tokenCounterText) {
      el.tokenCounterText.textContent = `Session Tokens: ~${state.sessionTokens} (Est: $${estCost})`;
    }
  }

  // -------------------------------------------------------------------------
  // Visual Stop / Abort Button & Process Killer
  // -------------------------------------------------------------------------
  function setExecutionActive(active) {
    state.isDispatching = active;
    if (!el.sendBtn) return;

    if (active) {
      el.sendBtn.classList.add('is-aborting');
      el.sendBtn.title = 'Stop Execution (SIGKILL)';
      if (el.sendBtnIcon) {
        el.sendBtnIcon.innerHTML = '<rect x="3" y="3" width="10" height="10" rx="1.5" fill="currentColor"></rect>';
      }
      if (el.sendBtnLabel) {
        el.sendBtnLabel.classList.remove('hidden');
        el.sendBtnLabel.style.display = 'inline-block';
      }
      if (el.sendKeyHint) {
        el.sendKeyHint.textContent = 'Esc';
      }
    } else {
      el.sendBtn.classList.remove('is-aborting');
      el.sendBtn.title = 'Send Request';
      if (el.sendBtnIcon) {
        el.sendBtnIcon.innerHTML = '<path d="M3.2 2.2a.75.75 0 01.8-.1l9.5 5a.75.75 0 010 1.3l-9.5 5a.75.75 0 01-1-.9L4.8 8 2.5 3.5a.75.75 0 01.7-1.3z"></path>';
      }
      if (el.sendBtnLabel) {
        el.sendBtnLabel.classList.add('hidden');
        el.sendBtnLabel.style.display = 'none';
      }
      if (el.sendKeyHint) {
        el.sendKeyHint.textContent = 'Enter';
      }
    }
  }

  async function abortActiveExecution() {
    logTerminal('stderr', '[Process Abort] Dispatching SIGKILL / taskkill signal to subprocesses...');
    setExecutionActive(false);
    removeThinkingBubble();

    // If quarantine modal is waiting on operator, dismiss it with denial
    if (state.currentQuarantineId && window.mycelium) {
      window.mycelium.submitHolDecision(state.currentQuarantineId, false);
      hideHolModal();
    }

    if (window.mycelium && window.mycelium.abortExecution) {
      try {
        await window.mycelium.abortExecution();
      } catch (e) {
        console.warn('Abort IPC exception:', e);
      }
    }

    renderAbortedMessage();
  }

  function renderAbortedMessage() {
    const card = document.createElement('div');
    card.className = 'stream-step';
    card.innerHTML = `
      <div class="step-pill" style="border-color:rgba(255,77,77,0.4); background:rgba(255,77,77,0.08)">
        <span class="step-arrow" style="color:#ff4d4d">#</span>
        <span class="step-label" style="color:#ff4d4d; font-weight:700">EXECUTION ABORTED BY OPERATOR</span>
        <span class="step-latency">SIGKILL</span>
      </div>
    `;
    el.streamFeed.appendChild(card);
    scrollToBottom();
    logTerminal('stderr', '[Execution Aborted] Active subprocesses and streams terminated. UI unlocked.');
  }

  // -------------------------------------------------------------------------
  // Circuit Breaker UI Card
  // -------------------------------------------------------------------------
  function renderCircuitBreakerCard(message, errorDetails) {
    const card = document.createElement('div');
    card.className = 'circuit-breaker-card';
    card.innerHTML = `
      <div class="circuit-breaker-header">
        <span class="circuit-breaker-badge">CIRCUIT BREAKER</span>
        <span class="circuit-breaker-title">${escapeHtml(message)}</span>
      </div>
      <div class="circuit-breaker-desc">
        ${escapeHtml(errorDetails || 'Action halted after 3 failed attempts to protect token balance and prevent process deadlocks.')}
      </div>
      <div class="circuit-breaker-actions">
        <button class="btn-circuit-inspect" id="cb-inspect-btn">Inspect Error</button>
        <button class="btn-circuit-retry" id="cb-retry-btn">Retry Once</button>
      </div>
    `;

    card.querySelector('#cb-inspect-btn').addEventListener('click', () => {
      switchDrawerTab('terminal-tab');
    });

    card.querySelector('#cb-retry-btn').addEventListener('click', () => {
      card.remove();
      state.subAgentCycles = 0;
      if (state.lastPrompt) {
        el.promptInput.value = state.lastPrompt;
        handleSendPrompt();
      }
    });

    el.streamFeed.appendChild(card);
    scrollToBottom();
  }

  // -------------------------------------------------------------------------
  // Slash Command Handlers
  // -------------------------------------------------------------------------
  function handleClearCommand() {
    el.promptInput.value = '';
    el.promptInput.style.height = 'auto';
    hideSlashMenu();
    el.streamFeed.innerHTML = '';
    if (el.emptyState) {
      el.streamFeed.appendChild(el.emptyState);
      el.emptyState.style.display = 'block';
    }
    state.conversationHistory = [];
    state.sessionTokens = 0;
    state.subAgentCycles = 0;
    state.lastExecutionError = null;
    updateTokenTally(0);
    logTerminal('info', '[Context Flush] Flushed chat memory, cleared active context buffer, and reset token counter.');
  }

  function handleAbortCommand() {
    el.promptInput.value = '';
    el.promptInput.style.height = 'auto';
    hideSlashMenu();
    abortActiveExecution();
  }

  function handleStatusCommand() {
    el.promptInput.value = '';
    el.promptInput.style.height = 'auto';
    hideSlashMenu();
    if (el.emptyState) el.emptyState.style.display = 'none';

    const prov = state.config.provider || 'groq';
    const provName = PROVIDER_NAMES[prov] || prov.toUpperCase();
    const modelName = state.config[prov + 'Model'] || state.config.groqModel || 'Default';
    const estCost = ((state.sessionTokens / 1000) * 0.0005).toFixed(4);
    const meshStatus = state.registryStatus.online ? 'ONLINE' : 'FALLBACK';

    const card = document.createElement('div');
    card.className = 'telemetry-status-card';
    card.innerHTML = `
      <div class="telemetry-status-header">
        <span class="telemetry-status-title">SYSTEM TELEMETRY SUMMARY</span>
        <span class="mono-qid">[${new Date().toTimeString().split(' ')[0]}]</span>
      </div>
      <div class="telemetry-status-grid">
        <div class="telemetry-metric-box">
          <span class="telemetry-metric-label">Active Brain</span>
          <span class="telemetry-metric-val" style="color:var(--accent-mint)">${escapeHtml(provName)}</span>
        </div>
        <div class="telemetry-metric-box">
          <span class="telemetry-metric-label">Active Model</span>
          <span class="telemetry-metric-val">${escapeHtml(modelName)}</span>
        </div>
        <div class="telemetry-metric-box">
          <span class="telemetry-metric-label">Session Tokens</span>
          <span class="telemetry-metric-val" style="color:#a3e635">~${state.sessionTokens} (Est: $${estCost})</span>
        </div>
        <div class="telemetry-metric-box">
          <span class="telemetry-metric-label">Mesh Registry</span>
          <span class="telemetry-metric-val" style="color:${state.registryStatus.online ? '#00ff9d' : '#ff7843'}">${meshStatus} (${state.registryStatus.latencyMs}ms)</span>
        </div>
        <div class="telemetry-metric-box">
          <span class="telemetry-metric-label">Discovered Nodes</span>
          <span class="telemetry-metric-val">${state.registryStatus.total} Agents Registered</span>
        </div>
        <div class="telemetry-metric-box">
          <span class="telemetry-metric-label">HOL Guard Mode</span>
          <span class="telemetry-metric-val" style="color:${state.holPolicy === 'STRICT' ? '#ff7843' : '#00ff9d'}">${state.holPolicy} (${state.privilegeTier})</span>
        </div>
        <div class="telemetry-metric-box">
          <span class="telemetry-metric-label">Circuit Breaker</span>
          <span class="telemetry-metric-val" style="color:${state.subAgentCycles >= MAX_SUB_AGENT_CYCLES ? '#ff4d4d' : '#00ff9d'}">${state.subAgentCycles}/${MAX_SUB_AGENT_CYCLES} Cycles (NORMAL)</span>
        </div>
        <div class="telemetry-metric-box">
          <span class="telemetry-metric-label">Delegation Depth</span>
          <span class="telemetry-metric-val">${state.currentDelegationDepth}/${MAX_DELEGATION_DEPTH} Max Lock</span>
        </div>
      </div>
    `;
    el.streamFeed.appendChild(card);
    scrollToBottom();
    logTerminal('info', '[Telemetry] In-stream telemetry summary generated.');
  }

  async function handleMeshCommand() {
    el.promptInput.value = '';
    el.promptInput.style.height = 'auto';
    hideSlashMenu();
    if (el.emptyState) el.emptyState.style.display = 'none';

    renderThinkingBubble('Querying Mycelium Mesh Registry (127.0.0.1:8000)...');
    try {
      const res = await window.mycelium.checkRegistryHealth(state.config.registryUrl);
      removeThinkingBubble();

      const card = document.createElement('div');
      card.className = 'mesh-table-card';
      const agents = res.agents || [];

      let rowsHtml = '';
      if (agents.length === 0) {
        rowsHtml = `<tr><td colspan="4" style="text-align:center; padding: 18px; color:var(--text-dim)">No agents discovered on mesh. Registry is running in local mode.</td></tr>`;
      } else {
        agents.forEach((ag) => {
          let capsStr = '';
          if (Array.isArray(ag.capabilities)) {
            capsStr = ag.capabilities.map((c) => (typeof c === 'object' ? c.name : c)).join(', ');
          } else if (typeof ag.capabilities === 'string') {
            capsStr = ag.capabilities;
          } else {
            capsStr = ag.description || 'General Agent';
          }
          const isMutating = (ag.tags || '').includes('mutating') || (capsStr || '').toLowerCase().includes('mutating');
          rowsHtml += `
            <tr>
              <td style="font-family:var(--font-mono); font-weight:700; color:var(--accent-mint)">${escapeHtml(ag.agent_id || ag.name)}</td>
              <td>${escapeHtml(ag.name || ag.agent_id)}</td>
              <td style="font-size:10px; color:#94a3b8">${escapeHtml(capsStr)}</td>
              <td><span style="font-size:9px; font-weight:700; font-family:var(--font-mono); color:${isMutating ? '#ff7843' : '#00ff9d'}">${isMutating ? 'MUTATING' : 'READ_ONLY'}</span></td>
            </tr>
          `;
        });
      }

      card.innerHTML = `
        <div class="mesh-table-card-header">
          <span class="mesh-table-card-title">DISCOVERED MESH CAPABILITIES (${agents.length} NODES)</span>
          <span class="mono-qid">${res.online ? 'ONLINE' : 'OFFLINE'} &bull; ${res.latencyMs}ms</span>
        </div>
        <table class="mesh-table">
          <thead>
            <tr>
              <th>Agent ID</th>
              <th>Display Name</th>
              <th>Capabilities</th>
              <th>Safety Tier</th>
            </tr>
          </thead>
          <tbody>
            ${rowsHtml}
          </tbody>
        </table>
      `;
      el.streamFeed.appendChild(card);
      scrollToBottom();
      logTerminal('info', `[Mesh Table] Rendered ${agents.length} discoverable capabilities.`);
    } catch (err) {
      removeThinkingBubble();
      logTerminal('stderr', `[Mesh Error] Could not query registry: ${err.message}`);
    }
  }

  function handleHolToggleCommand() {
    el.promptInput.value = '';
    el.promptInput.style.height = 'auto';
    hideSlashMenu();
    if (el.emptyState) el.emptyState.style.display = 'none';

    state.holPolicy = state.holPolicy === 'STRICT' ? 'PERMISSIVE' : 'STRICT';
    const msg = document.createElement('div');
    msg.className = 'stream-msg-assistant';
    msg.innerHTML = `<strong>[HOL Guard Mode Updated]</strong> Execution policy toggled to <code>${state.holPolicy}</code>.<br><span style="font-size:11px; color:#94a3b8">${state.holPolicy === 'STRICT' ? 'All mutating commands and file modifications require interactive operator sign-off.' : 'Permissive automation enabled for non-destructive operations.'}</span>`;
    el.streamFeed.appendChild(msg);
    scrollToBottom();
    logTerminal('info', `[HOL Policy] Toggled to ${state.holPolicy}`);
  }

  function handleModelCommand() {
    el.promptInput.value = '';
    el.promptInput.style.height = 'auto';
    hideSlashMenu();
    openSettingsModal();
  }

  // -------------------------------------------------------------------------
  // End-to-End Chat & Tool Execution Pipeline
  // -------------------------------------------------------------------------
  async function handleSendPrompt() {
    const text = el.promptInput.value.trim();
    if (!text || state.isDispatching) return;

    // Check for exact slash commands executed via send
    if (text.startsWith('/')) {
      const matchedCmd = SLASH_COMMANDS.find((c) => c.cmd === text.toLowerCase());
      if (matchedCmd) {
        matchedCmd.handler();
        return;
      }
    }

    // Circuit Breaker Guard: Max 3 failed cycles
    if (state.subAgentCycles >= MAX_SUB_AGENT_CYCLES) {
      renderCircuitBreakerCard(
        'Action halted after 3 failed attempts to protect token balance.',
        state.lastExecutionError
      );
      return;
    }

    // Agent Hierarchy Depth Lock: Hard-capped at 2
    if (state.currentDelegationDepth > MAX_DELEGATION_DEPTH) {
      renderAssistantMessage('[Depth Lock] Maximum delegation depth hard-capped at 2 (Orchestrator -> Atomic Worker). Recursive spawn blocked.');
      return;
    }

    if (el.emptyState) {
      el.emptyState.style.display = 'none';
    }

    state.lastPrompt = text;
    setExecutionActive(true);

    // 1. Append user message to stream and track tokens
    appendUserMessage(text);
    updateTokenTally(estimateTokens(text));
    state.conversationHistory.push({ role: 'user', content: text });

    el.promptInput.value = '';
    el.promptInput.style.height = 'auto';
    hideSlashMenu();

    // 2. Display thinking badge
    const provName = PROVIDER_NAMES[state.config.provider] || state.config.provider.toUpperCase();
    renderThinkingBubble(`Analyzing intent with ${provName}...`);
    logTerminal('cmd', `$ [User Prompt]: ${text}`);

    try {
      // Step A: Call selected LLM Provider with Sliding 4-Turn History Buffer
      const llmRes = await window.mycelium.executePrompt(text, {
        workspace: state.workspacePath,
        privilegeTier: state.privilegeTier,
        history: state.conversationHistory.slice(-4)
      });

      // Handle user cancellation
      if (llmRes.aborted) {
        setExecutionActive(false);
        removeThinkingBubble();
        renderAbortedMessage();
        return;
      }

      // Handle missing API key graceful notice
      if (llmRes.success === false && llmRes.error === 'MISSING_API_KEY') {
        removeThinkingBubble();
        setExecutionActive(false);
        renderApiKeyMissingCard(llmRes.provider, llmRes.hint);
        dispatchLocalCoordinatorFallback(text);
        return;
      }

      // Handle other LLM errors (e.g. 401 invalid key, rate limit)
      if (llmRes.success === false) {
        removeThinkingBubble();
        setExecutionActive(false);
        if (llmRes.error && (llmRes.error.includes('401') || llmRes.error.toLowerCase().includes('api key') || llmRes.error.toLowerCase().includes('unauthorized'))) {
          renderApiKeyMissingCard(llmRes.provider, `Provider key invalid or unauthorized: ${llmRes.error}. Update credentials in Settings.`);
        }
        logTerminal('stderr', `[LLM Gateway Notice] ${llmRes.error}. Executing via Local Coordinator.`);
        dispatchLocalCoordinatorFallback(text);
        return;
      }

      // Step B: If LLM produced an action, route to Mycelium Semantic Discovery
      if (llmRes.actionRequired && llmRes.action) {
        const action = llmRes.action;
        updateTokenTally(estimateTokens(JSON.stringify(action)));
        state.conversationHistory.push({ role: 'assistant', content: JSON.stringify(action) });

        // Render explanation if provided
        if (action.explanation) {
          renderAssistantMessage(action.explanation);
        }

        // Sub-10ms Semantic Discovery Query
        const discoveryQuery = action.tool_intent || action.tool_name || text;
        const discRes = await window.mycelium.discoverRegistry(discoveryQuery, state.config.registryUrl);

        if (discRes.success && discRes.matches && discRes.matches.length > 0) {
          const topMatch = discRes.matches[0];
          renderInlineDiscoveryStep({
            matchedTool: topMatch.name || topMatch.agent_id || action.tool_name,
            discoveryLatencyMs: discRes.latencyMs || 4.2,
            similarityScore: topMatch.score || 0.94,
            matchedToolSafety: topMatch.safetyTier || (action.tool_name === 'execute_shell_command' ? 'MUTATING' : 'READ_ONLY'),
            intent: discoveryQuery
          });
        }

        // Prepare Execution Payload
        const payload = action.parameters || {};
        if (action.tool_name === 'execute_shell_command' && !payload.command) {
          payload.command = text.replace(/^(run|execute)\s+/i, '').trim();
        }

        // Dispatch via Python Coordinator
        window.mycelium.dispatchIntent({
          intent: action.tool_intent || text,
          privilegeTier: state.privilegeTier,
          payload: payload,
          toolName: action.tool_name
        });
      } else {
        // Step D: Conversational / Coding Markdown Response
        removeThinkingBubble();
        setExecutionActive(false);
        const replyText = llmRes.text || 'No response returned from model.';
        updateTokenTally(estimateTokens(replyText));
        state.conversationHistory.push({ role: 'assistant', content: replyText });
        renderAssistantMessage(replyText);
        logTerminal('info', `[LLM Response] ${provName} answered in stream.`);
      }
    } catch (err) {
      removeThinkingBubble();
      setExecutionActive(false);
      logTerminal('stderr', `[Pipeline Error] ${err.message}`);
      dispatchLocalCoordinatorFallback(text);
    }
  }

  function dispatchLocalCoordinatorFallback(text) {
    const payload = {};
    const lower = text.toLowerCase();
    if (lower.startsWith('run ') || lower.startsWith('dir') || lower.startsWith('ls') || lower.includes('terminal')) {
      let cmd = text;
      if (lower.startsWith('run ')) {
        cmd = text.substring(4).trim();
      }
      payload.command = cmd;
    } else if (lower.includes('read ') && lower.includes('.json')) {
      const match = text.match(/([a-zA-Z0-9_\-\.]+\.json)/);
      if (match) {
        payload.file_path = match[1];
      }
    }

    logTerminal('info', '[Local Coordinator] Dispatching intent directly to Python engine...');
    setExecutionActive(true);
    window.mycelium.dispatchIntent({
      intent: text,
      privilegeTier: state.privilegeTier,
      payload: payload
    });
  }

  // -------------------------------------------------------------------------
  // Stream Feed Rendering
  // -------------------------------------------------------------------------
  function appendUserMessage(text) {
    const msg = document.createElement('div');
    msg.className = 'stream-msg-user';
    msg.textContent = text;
    el.streamFeed.appendChild(msg);
    scrollToBottom();
  }

  function renderAssistantMessage(markdownText) {
    const msg = document.createElement('div');
    msg.className = 'stream-msg-assistant';
    msg.innerHTML = formatMarkdown(markdownText);
    el.streamFeed.appendChild(msg);
    scrollToBottom();
  }

  function renderThinkingBubble(statusText) {
    removeThinkingBubble();
    const bubble = document.createElement('div');
    bubble.id = 'active-thinking-bubble';
    bubble.className = 'stream-thinking-bubble';
    bubble.innerHTML = `
      <span class="thinking-spinner"></span>
      <span>${escapeHtml(statusText)}</span>
    `;
    el.streamFeed.appendChild(bubble);
    scrollToBottom();
  }

  function removeThinkingBubble() {
    const existing = document.getElementById('active-thinking-bubble');
    if (existing) {
      existing.remove();
    }
  }

  function renderApiKeyMissingCard(providerName, hint) {
    const card = document.createElement('div');
    card.className = 'stream-alert-card';
    card.innerHTML = `
      <div class="alert-card-header">
        <span class="alert-badge">API KEY REQUIRED</span>
        <span class="alert-provider">${escapeHtml(providerName)}</span>
      </div>
      <p>${escapeHtml(hint || 'Please configure your API key in the Provider & Mesh Hub.')}</p>
      <div class="alert-card-actions">
        <button class="alert-settings-btn">Open Provider Hub</button>
      </div>
    `;

    card.querySelector('.alert-settings-btn').addEventListener('click', () => {
      openSettingsModal();
    });

    el.streamFeed.appendChild(card);
    scrollToBottom();
  }

  function renderInlineDiscoveryStep(data) {
    const wrap = document.createElement('div');
    wrap.className = 'stream-step';

    const pill = document.createElement('div');
    pill.className = 'step-pill';

    const toolName = data.matchedTool || 'system_router';
    pill.innerHTML = `
      <span class="step-arrow">▸</span>
      <span class="step-label">Routed to ${escapeHtml(toolName)}</span>
      <span class="step-latency">${data.discoveryLatencyMs.toFixed(3)}ms</span>
    `;

    const details = document.createElement('div');
    details.className = 'step-details';
    details.innerHTML = `
      <div class="step-details-header">
        <span>Vector Cosine Similarity: ${((data.similarityScore || 0.95) * 100).toFixed(1)}%</span>
        <span>Safety Tier: ${data.matchedToolSafety || 'READ_ONLY'}</span>
      </div>
      <pre>Semantic Vector Mesh resolved "${escapeHtml(data.intent)}" to ${escapeHtml(toolName)} in ${data.discoveryLatencyMs.toFixed(3)}ms</pre>
    `;

    pill.addEventListener('click', () => {
      const isOpen = pill.classList.toggle('open');
      details.classList.toggle('open', isOpen);
    });

    wrap.appendChild(pill);
    wrap.appendChild(details);
    el.streamFeed.appendChild(wrap);
    scrollToBottom();
  }

  function renderExecutionOutcome(data) {
    // 1. Collapsible execution step
    const wrap = document.createElement('div');
    wrap.className = 'stream-step';

    const pill = document.createElement('div');
    pill.className = 'step-pill';

    const statusText = data.success
      ? `Ran ${data.matchedTool || 'task'}`
      : `Quarantined / Blocked`;

    pill.innerHTML = `
      <span class="step-arrow">▸</span>
      <span class="step-label">${statusText}</span>
      <span class="step-latency">${data.latencyMs.toFixed(2)}ms</span>
    `;

    const details = document.createElement('div');
    details.className = 'step-details';
    details.innerHTML = `
      <div class="step-details-header">
        <span>Exit Code: ${data.exitCode}</span>
        <span>${data.safetyTier} &bull; ${data.privilegeTier}</span>
      </div>
      <pre>${escapeHtml(data.stdout || data.stderr || 'No stream output.')}</pre>
    `;

    pill.addEventListener('click', () => {
      const isOpen = pill.classList.toggle('open');
      details.classList.toggle('open', isOpen);
    });

    wrap.appendChild(pill);
    wrap.appendChild(details);
    el.streamFeed.appendChild(wrap);

    // 2. If stdout is substantive, display in clean code block with copy button
    if (data.stdout && data.stdout.trim().length > 0) {
      const card = document.createElement('div');
      card.className = 'stream-code-card';

      let formatted = data.stdout;
      try {
        if (formatted.trim().startsWith('{') || formatted.trim().startsWith('[')) {
          formatted = JSON.stringify(JSON.parse(formatted), null, 2);
        }
      } catch (e) {}

      card.innerHTML = `
        <div class="code-card-header">
          <span>Output &bull; ${escapeHtml(data.matchedTool || 'stdout')}</span>
          <button class="copy-btn">Copy</button>
        </div>
        <pre>${escapeHtml(formatted)}</pre>
      `;

      const copyBtn = card.querySelector('.copy-btn');
      copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(formatted).then(() => {
          copyBtn.textContent = 'Copied!';
          setTimeout(() => {
            copyBtn.textContent = 'Copy';
          }, 1800);
        });
      });

      el.streamFeed.appendChild(card);
    }

    scrollToBottom();
  }

  function scrollToBottom() {
    if (state.config.autoScrollStream === false) return;
    el.streamFeed.scrollTop = el.streamFeed.scrollHeight;
  }

  // -------------------------------------------------------------------------
  // Native HOL Guard Graphical Modal
  // -------------------------------------------------------------------------
  function triggerHolModal(data) {
    state.currentQuarantineId = data.quarantineId;
    el.modalIntent.textContent = data.intent;
    el.modalSafetyTier.textContent = data.safetyTier;
    el.modalPrivilegeTier.textContent = data.privilegeTier;

    let payloadStr = '';
    if (data.payload && data.payload.command) {
      payloadStr = data.payload.command;
    } else {
      payloadStr = JSON.stringify(data.payload, null, 2);
    }

    el.modalPayloadCode.textContent = payloadStr;
    el.modalQid.textContent = data.quarantineId.substring(0, 8);
    el.holModalBackdrop.classList.remove('hidden');

    showDesktopNotification(
      'HOL Guard Quarantine Alert',
      `Operator authorization required for: ${data.intent}`
    );
    playAuthorizationChime('alert');
  }

  function hideHolModal() {
    el.holModalBackdrop.classList.add('hidden');
    state.currentQuarantineId = null;
  }

  // -------------------------------------------------------------------------
  // Workspace File Explorer
  // -------------------------------------------------------------------------
  function renderWorkspaceTree(node) {
    el.fileTree.innerHTML = '';
    let totalFiles = 0;

    function buildNode(item, depth = 0) {
      const row = document.createElement('div');
      row.className = `tree-item ${item.isDir ? 'is-dir' : 'is-file'}`;
      row.style.paddingLeft = `${depth * 12 + 8}px`;

      const ext = item.isDir ? '' : item.name.split('.').pop() || '';
      const extLower = ext.toLowerCase();

      const iconSvg = item.isDir
        ? `<svg class="tree-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M1.75 2.5A.75.75 0 001 3.25v9.5c0 .414.336.75.75.75h12.5a.75.75 0 00.75-.75v-7.5a.75.75 0 00-.75-.75H7.31L5.88 3H1.75z"></path></svg>`
        : `<svg class="tree-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M3.75 1.5A1.75 1.75 0 002 3.25v9.5c0 .966.784 1.75 1.75 1.75h8.5A1.75 1.75 0 0014 12.75v-7L9.5 1.5H3.75z"></path></svg>`;

      const extBadge = !item.isDir && ext ? `<span class="tree-ext ${extLower}">${ext}</span>` : '';

      if (!item.isDir) {
        totalFiles++;
      }

      row.innerHTML = `${iconSvg} <span>${escapeHtml(item.name)}</span> ${extBadge}`;

      if (!item.isDir) {
        row.addEventListener('click', () => {
          if (window.mycelium) {
            window.mycelium.readFile(item.path);
          }
        });
      }

      el.fileTree.appendChild(row);

      if (item.isDir && item.children) {
        item.children.forEach((child) => buildNode(child, depth + 1));
      }
    }

    if (node.name && el.workspaceCrumb) {
      el.workspaceCrumb.textContent = node.name;
    }

    if (node.children && node.children.length > 0) {
      node.children.forEach((child) => buildNode(child, 0));
    } else {
      el.fileTree.innerHTML = '<div class="tree-loading"><span>Workspace empty</span></div>';
    }

    if (el.sidebarFileCount) {
      el.sidebarFileCount.textContent = totalFiles;
    }
  }

  // -------------------------------------------------------------------------
  // Bottom Drawer & Subshell Terminal
  // -------------------------------------------------------------------------
  function toggleDrawer() {
    setDrawerState(!state.drawerOpen);
  }

  function setDrawerState(open) {
    state.drawerOpen = open;
    if (open) {
      el.executionDrawer.classList.remove('collapsed');
    } else {
      el.executionDrawer.classList.add('collapsed');
    }
  }

  function switchDrawerTab(targetId) {
    setDrawerState(true);
    state.activeDrawerTab = targetId;

    el.drawerTabs.forEach((tab) => {
      tab.classList.toggle('active', tab.getAttribute('data-tab') === targetId);
    });

    document.querySelectorAll('.drawer-panel').forEach((panel) => {
      panel.classList.toggle('active', panel.id === targetId);
    });
  }

  function logTerminal(type, text) {
    const row = document.createElement('div');
    row.className = `term-row ${type}`;
    row.textContent = text;
    el.terminalLogs.appendChild(row);
    el.terminalLogs.scrollTop = el.terminalLogs.scrollHeight;
  }

  function displayFileContent(filePath, content) {
    switchDrawerTab('diff-tab');
    state.selectedFileContent = content;
    el.diffFileTitle.textContent = filePath;

    const lines = content.split('\n');
    const numbered = lines.map((l, i) => `${(i + 1).toString().padStart(3, ' ')} | ${l}`).join('\n');
    el.diffContent.textContent = numbered;
  }

  function recordAuditLog(data) {
    const tr = document.createElement('tr');
    const timeStr = new Date().toTimeString().split(' ')[0];
    const isSuccess = data.success;
    tr.innerHTML = `
      <td>${timeStr}</td>
      <td>${escapeHtml(data.intent.substring(0, 32))}</td>
      <td><span style="color:${data.safetyTier === 'READ_ONLY' ? '#00ff9d' : '#ff7843'}; font-weight:700">${data.safetyTier}</span></td>
      <td>${data.privilegeTier}</td>
      <td><span style="color:#00ff9d; font-weight:700">${data.latencyMs.toFixed(2)}ms</span></td>
      <td><span style="color:${isSuccess ? '#00ff9d' : '#ff4b5c'}; font-weight:700">${isSuccess ? 'APPROVED' : 'BLOCKED'}</span></td>
    `;
    el.auditTableBody.prepend(tr);
  }

  // -------------------------------------------------------------------------
  // Markdown & Utilities
  // -------------------------------------------------------------------------
  function formatMarkdown(text) {
    if (!text) return '';
    let html = escapeHtml(text);

    // Code blocks
    html = html.replace(/```([a-zA-Z0-9_\-\.]*)\n([\s\S]*?)```/g, (_match, _lang, code) => {
      return `<pre class="md-code-block"><code>${code}</code></pre>`;
    });

    // Inline code
    html = html.replace(/`([^`]+)`/g, '<code class="md-inline-code">$1</code>');

    // Bold & italic
    html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');

    // Newlines
    html = html.replace(/\n\n/g, '<br><br>');
    html = html.replace(/\n/g, '<br>');

    return html;
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // -------------------------------------------------------------------------
  // Floating Side Teaser: Token Architecture & Quota Planner
  // -------------------------------------------------------------------------
  const TEASER_STORAGE_KEY = 'mycelium_token_teaser_last_shown';
  const TEASER_COOLDOWN_MS = 24 * 60 * 60 * 1000; // 24 hours
  let teaserDismissTimer = null;

  function initTokenTeaser() {
    if (el.closeTeaserBtn) {
      el.closeTeaserBtn.addEventListener('click', () => {
        dismissTokenTeaser();
      });
    }

    // Developer test override exposed on window
    window.showTokenTeaser = (force = true) => {
      displayTokenTeaser(force);
    };

    // Scheduled boot check: 1.5 seconds after app boot
    setTimeout(() => {
      try {
        const lastShown = localStorage.getItem(TEASER_STORAGE_KEY);
        const now = Date.now();
        if (!lastShown || (now - Number(lastShown)) >= TEASER_COOLDOWN_MS) {
          displayTokenTeaser(false);
        }
      } catch (err) {
        // Fallback gracefully if localStorage is restricted
        console.warn('[Teaser] Could not inspect localStorage:', err);
      }
    }, 1500);
  }

  function displayTokenTeaser(force = false) {
    if (!el.tokenTeaserCard) return;

    if (!force) {
      try {
        localStorage.setItem(TEASER_STORAGE_KEY, Date.now().toString());
      } catch (err) {
        console.warn('[Teaser] Could not save timestamp:', err);
      }
    }

    // Clear previous dismiss timer if active
    if (teaserDismissTimer) {
      clearTimeout(teaserDismissTimer);
      teaserDismissTimer = null;
    }

    // Reset classes and trigger smooth entrance animation
    el.tokenTeaserCard.classList.remove('hidden', 'dismissing');
    el.tokenTeaserCard.classList.add('visible');

    // Auto-dismiss after exactly 10 seconds
    teaserDismissTimer = setTimeout(() => {
      dismissTokenTeaser();
    }, 10000);
  }

  function dismissTokenTeaser() {
    if (!el.tokenTeaserCard || !el.tokenTeaserCard.classList.contains('visible')) return;

    if (teaserDismissTimer) {
      clearTimeout(teaserDismissTimer);
      teaserDismissTimer = null;
    }

    // Trigger smooth fade-out / slide-out exit animation
    el.tokenTeaserCard.classList.remove('visible');
    el.tokenTeaserCard.classList.add('dismissing');

    // Remove from active display after animation ends (350ms)
    setTimeout(() => {
      el.tokenTeaserCard.classList.remove('dismissing');
      el.tokenTeaserCard.classList.add('hidden');
    }, 350);
  }

  document.addEventListener('DOMContentLoaded', init);
})();
