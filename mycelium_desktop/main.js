/**
 * US Neural - Mycelium Desktop Application
 * Main Process & Python Daemon Supervisor
 * Wires Live Mycelium Semantic Registry (http://127.0.0.1:8000)
 * Multi-Provider LLM Gateway (Groq, Gemini, OpenAI, Claude)
 * Config store (~/.mycelium/desktop_config.json)
 */

const { app, BrowserWindow, ipcMain, Menu, shell, dialog, Tray, nativeImage } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn } = require('child_process');
const readline = require('readline');

if (app && app.commandLine) {
  app.commandLine.appendSwitch('disable-gpu-shader-disk-cache');
}

let mainWindow = null;
let pythonDaemon = null;
let pythonRl = null;
let registryProcess = null;
let activeLLMAbortController = null;
let tray = null;

// Paths
const COORDINATOR_DIR = path.resolve(__dirname, '..');
const ENGINE_SCRIPT = path.join(COORDINATOR_DIR, 'engine_bridge.py');
const MYCELIUM_SERVER_DIR = path.resolve(COORDINATOR_DIR, '..', 'mycelium');
const CONFIG_DIR = path.join(os.homedir(), '.mycelium');
const CONFIG_FILE = path.join(CONFIG_DIR, 'desktop_config.json');

// ---------------------------------------------------------------------------
// 1. Config Management (~/.mycelium/desktop_config.json)
// ---------------------------------------------------------------------------

function loadEnvFileKey(keyName) {
  try {
    const envPath = path.join(MYCELIUM_SERVER_DIR, '.env');
    if (fs.existsSync(envPath)) {
      const content = fs.readFileSync(envPath, 'utf-8');
      for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (trimmed.startsWith(`${keyName}=`)) {
          return trimmed.split('=')[1].trim();
        }
      }
    }
  } catch (e) {
    // ignore
  }
  return '';
}

function getStoredConfig() {
  const envGroq = process.env.GROQ_API_KEY || loadEnvFileKey('GROQ_API_KEY') || '';
  const envGemini = process.env.GEMINI_API_KEY || loadEnvFileKey('GEMINI_API_KEY') || '';
  const envOpenAI = process.env.OPENAI_API_KEY || loadEnvFileKey('OPENAI_API_KEY') || '';
  const envClaude = process.env.ANTHROPIC_API_KEY || loadEnvFileKey('ANTHROPIC_API_KEY') || '';

  const defaults = {
    provider: 'groq',
    groqModel: 'llama-3.3-70b-versatile',
    geminiModel: 'gemini-2.0-flash',
    openaiModel: 'gpt-4o-mini',
    anthropicModel: 'claude-3-5-sonnet-20241022',
    ollamaEndpoint: 'http://localhost:11434',
    ollamaModel: 'llama3.2',
    customBaseUrl: 'https://openrouter.ai/api/v1',
    customApiKey: '',
    customModel: 'deepseek/deepseek-r1',
    registryUrl: 'http://127.0.0.1:8000/api/v1',
    enterpriseKey: '',
    autoSpawnRegistry: true,
    groqApiKey: envGroq,
    geminiApiKey: envGemini,
    openaiApiKey: envOpenAI,
    anthropicApiKey: envClaude,

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
  };

  try {
    if (fs.existsSync(CONFIG_FILE)) {
      const raw = fs.readFileSync(CONFIG_FILE, 'utf-8');
      const saved = JSON.parse(raw);
      return { ...defaults, ...saved };
    }
  } catch (err) {
    console.warn('[Config] Error reading config file:', err.message);
  }

  return defaults;
}

function saveStoredConfig(newConfig) {
  try {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
    const current = getStoredConfig();
    const updated = { ...current, ...newConfig };
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(updated, null, 2), 'utf-8');
    return { success: true, config: updated };
  } catch (err) {
    console.error('[Config] Error saving config file:', err);
    return { success: false, error: err.message };
  }
}

// ---------------------------------------------------------------------------
// 2. Python MAC Coordinator Supervisor (engine_bridge.py)
// ---------------------------------------------------------------------------

function spawnPythonDaemon() {
  const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';

  pythonDaemon = spawn(pythonCmd, [ENGINE_SCRIPT], {
    cwd: COORDINATOR_DIR,
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, PYTHONUNBUFFERED: '1' }
  });

  pythonRl = readline.createInterface({
    input: pythonDaemon.stdout,
    terminal: false
  });

  pythonRl.on('line', (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    try {
      const msg = JSON.parse(trimmed);
      handleDaemonMessage(msg);
    } catch (err) {
      // ignore
    }
  });

  pythonDaemon.stderr.on('data', (data) => {
    const errText = data.toString('utf-8');
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('bridge-error', { error: errText });
    }
  });

  pythonDaemon.on('exit', (code, signal) => {
    console.log(`[Supervisor] Daemon exited with code ${code}, signal ${signal}`);
  });
}

function sendToDaemon(message) {
  if (pythonDaemon && pythonDaemon.stdin && !pythonDaemon.stdin.destroyed) {
    const jsonStr = JSON.stringify(message) + '\n';
    pythonDaemon.stdin.write(jsonStr);
  }
}

function handleDaemonMessage(msg) {
  if (!mainWindow || mainWindow.isDestroyed()) return;

  switch (msg.type) {
    case 'SYSTEM_READY':
      mainWindow.webContents.send('system-ready', msg);
      break;
    case 'SEMANTIC_DISCOVERY_EVENT':
      mainWindow.webContents.send('semantic-discovery', msg);
      break;
    case 'HOL_QUARANTINE_TRIGGERED':
      mainWindow.webContents.send('hol-quarantine', msg);
      break;
    case 'EXECUTION_COMPLETE':
      mainWindow.webContents.send('execution-complete', msg);
      break;
    case 'WORKSPACE_TREE_DATA':
      mainWindow.webContents.send('workspace-tree', msg);
      break;
    case 'MESH_NODES_DATA':
      mainWindow.webContents.send('mesh-nodes', msg);
      break;
    case 'FILE_CONTENT_DATA':
      mainWindow.webContents.send('file-content', msg);
      break;
    case 'FILE_WRITTEN_DATA':
      mainWindow.webContents.send('file-written', msg);
      break;
    case 'EXECUTION_ABORTED':
      mainWindow.webContents.send('execution-aborted', msg);
      break;
  }
}

// ---------------------------------------------------------------------------
// 3. Live Mycelium Semantic Registry Sync & Spawner
// ---------------------------------------------------------------------------

async function checkRegistryHealth(registryUrl) {
  const targetUrl = (registryUrl || 'http://127.0.0.1:8000/api/v1').replace(/\/+$/, '');
  const agentsUrl = `${targetUrl}/agents`;
  const start = Date.now();

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2800);

    const res = await fetch(agentsUrl, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      signal: controller.signal
    });
    clearTimeout(timeout);

    const latencyMs = Date.now() - start;
    if (res.ok) {
      const data = await res.json();
      const agents = data.agents || [];
      const total = data.total || data.network_size || agents.length;
      return {
        online: true,
        total,
        latencyMs,
        agents: agents.slice(0, 20),
        url: targetUrl
      };
    } else {
      return { online: false, total: 0, latencyMs, error: `HTTP ${res.status}`, url: targetUrl };
    }
  } catch (err) {
    return { online: false, total: 0, latencyMs: Date.now() - start, error: err.message, url: targetUrl };
  }
}

async function discoverRegistryAgents(registryUrl, query) {
  const targetUrl = (registryUrl || 'http://127.0.0.1:8000/api/v1').replace(/\/+$/, '');
  const discoverUrl = `${targetUrl}/agents/discover?q=${encodeURIComponent(query)}&semantic=true`;
  const start = Date.now();

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3500);

    const res = await fetch(discoverUrl, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      signal: controller.signal
    });
    clearTimeout(timeout);

    const latencyMs = Date.now() - start;
    if (res.ok) {
      const data = await res.json();
      return {
        success: true,
        latencyMs,
        matches: data.matches || data.results || data.agents || []
      };
    }
  } catch (e) {
    // fallback
  }

  return { success: false, matches: [], latencyMs: Date.now() - start };
}

function launchLocalRegistryServer() {
  if (registryProcess && !registryProcess.killed) {
    return { success: true, message: 'Registry server process already active.' };
  }

  const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';
  try {
    registryProcess = spawn(
      pythonCmd,
      ['-m', 'uvicorn', 'server.app:app', '--host', '127.0.0.1', '--port', '8000'],
      {
        cwd: MYCELIUM_SERVER_DIR,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: { ...process.env, PYTHONUNBUFFERED: '1' }
      }
    );

    registryProcess.stdout.on('data', (d) => {
      console.log('[Registry stdout]:', d.toString().trim());
    });

    registryProcess.stderr.on('data', (d) => {
      console.log('[Registry stderr]:', d.toString().trim());
    });

    return { success: true, message: 'Spawning uvicorn server.app:app in background on port 8000...' };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ---------------------------------------------------------------------------
// 4. Multi-Provider LLM Gateway & Real-Time Key Validation Engine
// ---------------------------------------------------------------------------

async function testProviderConnection({ provider, key, apiKey, endpoint, model, baseUrl, registryUrl, enterpriseKey }) {
  const p = (provider || '').toLowerCase();
  const token = (apiKey || key || '').trim();
  const start = Date.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    // 1. GROQ (Llama 3.3 / LPU Acceleration)
    if (p === 'groq') {
      if (!token) return { success: false, valid: false, message: 'Missing Groq API Key' };
      try {
        const res = await fetch('https://api.groq.com/openai/v1/models', {
          method: 'GET',
          headers: { 'Authorization': `Bearer ${token}` },
          signal: controller.signal
        });
        clearTimeout(timeout);
        const latencyMs = Date.now() - start;
        if (res.status === 200) {
          return { success: true, valid: true, message: 'Connected to Groq (LPU Active)', latencyMs };
        }
        if (res.status === 401 || res.status === 403) {
          return { success: false, valid: false, message: 'Invalid Groq API Key (401 Unauthorized)', latencyMs };
        }
        const data = await res.json().catch(() => ({}));
        return { success: false, valid: false, message: data.error?.message || `Groq returned HTTP ${res.status}`, latencyMs };
      } catch (err) {
        clearTimeout(timeout);
        if (err.name === 'AbortError') {
          return { success: false, valid: false, message: 'Groq verification timed out after 5 seconds' };
        }
        return { success: false, valid: false, message: `Groq unreachable: ${err.message}` };
      }
    }

    // 2. GOOGLE GEMINI (Google AI Studio)
    if (p === 'gemini') {
      if (!token) return { success: false, valid: false, message: 'Missing Gemini API Key' };
      try {
        const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${token}`, {
          method: 'GET',
          signal: controller.signal
        });
        clearTimeout(timeout);
        const latencyMs = Date.now() - start;
        if (res.status === 200) {
          return { success: true, valid: true, message: 'Google AI Studio Verified (Gemini 1.5/2.0 Active)', latencyMs };
        }
        if (res.status === 400 || res.status === 403) {
          return { success: false, valid: false, message: 'Invalid Gemini API Key or API not enabled', latencyMs };
        }
        const data = await res.json().catch(() => ({}));
        return { success: false, valid: false, message: data.error?.message || `Google AI Studio returned HTTP ${res.status}`, latencyMs };
      } catch (err) {
        clearTimeout(timeout);
        if (err.name === 'AbortError') {
          return { success: false, valid: false, message: 'Gemini verification timed out after 5 seconds' };
        }
        return { success: false, valid: false, message: `Gemini unreachable: ${err.message}` };
      }
    }

    // 3. OPENAI (GPT-4o / o1)
    if (p === 'openai') {
      if (!token) return { success: false, valid: false, message: 'Missing OpenAI API Key' };
      try {
        const res = await fetch('https://api.openai.com/v1/models', {
          method: 'GET',
          headers: { 'Authorization': `Bearer ${token}` },
          signal: controller.signal
        });
        clearTimeout(timeout);
        const latencyMs = Date.now() - start;
        if (res.status === 200) {
          return { success: true, valid: true, message: 'Connected to OpenAI (GPT-4o/o1 Active)', latencyMs };
        }
        if (res.status === 401 || res.status === 403) {
          return { success: false, valid: false, message: 'Invalid OpenAI API Key (401 Unauthorized)', latencyMs };
        }
        const data = await res.json().catch(() => ({}));
        return { success: false, valid: false, message: data.error?.message || `OpenAI returned HTTP ${res.status}`, latencyMs };
      } catch (err) {
        clearTimeout(timeout);
        if (err.name === 'AbortError') {
          return { success: false, valid: false, message: 'OpenAI verification timed out after 5 seconds' };
        }
        return { success: false, valid: false, message: `OpenAI unreachable: ${err.message}` };
      }
    }

    // 4. ANTHROPIC (Claude 3.5 Sonnet)
    if (p === 'anthropic' || p === 'claude') {
      if (!token) return { success: false, valid: false, message: 'Missing Anthropic API Key' };
      try {
        const res = await fetch('https://api.anthropic.com/v1/models', {
          method: 'GET',
          headers: {
            'x-api-key': token,
            'anthropic-version': '2023-06-01'
          },
          signal: controller.signal
        });
        clearTimeout(timeout);
        const latencyMs = Date.now() - start;
        if (res.status === 200) {
          return { success: true, valid: true, message: 'Connected to Anthropic (Claude 3.5 Active)', latencyMs };
        }
        if (res.status === 401 || res.status === 403) {
          return { success: false, valid: false, message: 'Invalid Anthropic Key (401 Unauthorized)', latencyMs };
        }
        const data = await res.json().catch(() => ({}));
        return { success: false, valid: false, message: data.error?.message || `Anthropic returned HTTP ${res.status}`, latencyMs };
      } catch (err) {
        clearTimeout(timeout);
        if (err.name === 'AbortError') {
          return { success: false, valid: false, message: 'Anthropic verification timed out after 5 seconds' };
        }
        return { success: false, valid: false, message: `Anthropic unreachable: ${err.message}` };
      }
    }

    // 5. OLLAMA / LOCAL (100% Offline)
    if (p === 'ollama') {
      const host = (endpoint || baseUrl || 'http://localhost:11434').replace(/\/+$/, '');
      try {
        const res = await fetch(`${host}/api/tags`, {
          method: 'GET',
          signal: controller.signal
        });
        clearTimeout(timeout);
        const latencyMs = Date.now() - start;
        if (res.status === 200) {
          const data = await res.json().catch(() => ({}));
          const count = data.models ? data.models.length : 0;
          return {
            success: true,
            valid: true,
            message: `Ollama Daemon Connected Locally (${count} models available)`,
            count,
            latencyMs
          };
        }
        return { success: false, valid: false, message: `Ollama daemon returned HTTP ${res.status}`, latencyMs };
      } catch (err) {
        clearTimeout(timeout);
        return { success: false, valid: false, message: `Ollama daemon unreachable on ${host}. Ensure Ollama is running.` };
      }
    }

    // 6. MYCELIUM SEMANTIC MESH REGISTRY
    if (p === 'mycelium' || p === 'mesh') {
      const target = (registryUrl || baseUrl || getStoredConfig().registryUrl || 'http://127.0.0.1:8000/api/v1').replace(/\/+$/, '');
      const entKey = enterpriseKey || token || getStoredConfig().enterpriseKey || '';
      const headers = { 'Accept': 'application/json' };
      if (entKey) {
        headers['X-Mycelium-API-Key'] = entKey;
        headers['Authorization'] = `Bearer ${entKey}`;
      }

      try {
        const baseRoot = target.endsWith('/api/v1') ? target.slice(0, -7) : target;
        let res = await fetch(`${baseRoot}/health`, { method: 'GET', headers, signal: controller.signal }).catch(() => null);
        if (!res || !res.ok) {
          res = await fetch(`${target}/agents`, { method: 'GET', headers, signal: controller.signal });
        }
        clearTimeout(timeout);
        const latencyMs = Date.now() - start;
        if (res.status === 200) {
          const data = await res.json().catch(() => ({}));
          const nodes = data.network_size || data.total || (data.agents ? data.agents.length : 0);
          return {
            success: true,
            valid: true,
            message: `Mycelium Semantic Mesh Active (${nodes} nodes)`,
            nodes,
            latencyMs
          };
        }
        if (res.status === 401 || res.status === 403) {
          return { success: false, valid: false, message: 'Invalid Mycelium Enterprise Key (401 Unauthorized)', latencyMs };
        }
        return { success: false, valid: false, message: `Mycelium Registry returned HTTP ${res.status}`, latencyMs };
      } catch (err) {
        clearTimeout(timeout);
        return { success: false, valid: false, message: `Mycelium Registry unreachable on ${target}: ${err.message}` };
      }
    }

    // 7. CUSTOM OPENAI-COMPATIBLE ENDPOINT
    if (p === 'custom') {
      const target = (baseUrl || endpoint || 'https://openrouter.ai/api/v1').replace(/\/+$/, '');
      const headers = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;
      try {
        const res = await fetch(`${target}/models`, { method: 'GET', headers, signal: controller.signal });
        clearTimeout(timeout);
        const latencyMs = Date.now() - start;
        if (res.status === 200) {
          return { success: true, valid: true, message: 'Custom OpenAI-Compatible Endpoint Verified', latencyMs };
        }
        if (res.status === 401 || res.status === 403) {
          return { success: false, valid: false, message: `Custom endpoint rejected key (HTTP ${res.status})`, latencyMs };
        }
        const data = await res.json().catch(() => ({}));
        return { success: false, valid: false, message: data.error?.message || `Endpoint returned HTTP ${res.status}`, latencyMs };
      } catch (err) {
        clearTimeout(timeout);
        return { success: false, valid: false, message: `Custom endpoint unreachable on ${target}: ${err.message}` };
      }
    }

    clearTimeout(timeout);
    return { success: false, valid: false, message: `Unknown provider: ${provider}` };
  } catch (err) {
    clearTimeout(timeout);
    return { success: false, valid: false, message: `Connection failed: ${err.message}` };
  }
}

const validateProviderCredentials = testProviderConnection;

async function executeLLMPrompt(prompt, context = {}) {
  const cfg = getStoredConfig();
  const provider = (cfg.provider || 'groq').toLowerCase();

  const controller = new AbortController();
  activeLLMAbortController = controller;
  const signal = controller.signal;

  const systemInstruction = `You are the core intelligence for the US Neural Mycelium Agent Coordinator (MAC).
Your workspace root contains project files and code.
When user asks for actions (reading files, directory listing, bash/shell execution, diagnostics, weather, crypto), return a single strict JSON object:
{
  "action_required": true,
  "tool_intent": "<short semantic intent description>",
  "tool_name": "<execute_shell_command | read_workspace_file | write_workspace_file | system_diagnostics | weather_sensor_node | crypto_telemetry_node>",
  "parameters": { ... },
  "explanation": "<brief natural language description of what you will do>"
}
If no tool is required (direct questions, explanations, coding advice), respond directly in clear, helpful Markdown text without wrapping in JSON.`;

  // Sliding History Buffer: Keep strictly only the last 4 conversational turns in context
  const historyTurns = (context && Array.isArray(context.history) ? context.history : []).slice(-4);
  const formattedChatMessages = [
    { role: 'system', content: systemInstruction },
    ...historyTurns.map(t => ({
      role: t.role === 'assistant' ? 'assistant' : 'user',
      content: t.content || ''
    })),
    { role: 'user', content: prompt }
  ];

  try {
    // 1. GROQ (Llama 3.3 70B - Default)
    if (provider === 'groq') {
      if (!cfg.groqApiKey) {
        return { success: false, error: 'MISSING_API_KEY', provider: 'Groq', hint: 'Please configure GROQ_API_KEY in Settings.' };
      }
      try {
        const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
          method: 'POST',
          signal,
          headers: {
            'Authorization': `Bearer ${cfg.groqApiKey.trim()}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            model: cfg.groqModel || 'llama-3.3-70b-versatile',
            messages: formattedChatMessages,
            temperature: 0.2,
            max_tokens: 1024
          })
        });

        const data = await res.json();
        if (!res.ok) {
          return { success: false, error: data.error?.message || `Groq HTTP ${res.status}`, provider: 'Groq' };
        }

        const text = data.choices?.[0]?.message?.content || '';
        return parseLLMOutput(text, provider, cfg.groqModel);
      } catch (err) {
        if (err.name === 'AbortError' || signal.aborted) {
          return { success: false, aborted: true, error: 'Execution halted by operator.' };
        }
        return { success: false, error: err.message, provider: 'Groq' };
      }
    }

    // 2. GOOGLE GEMINI
    if (provider === 'gemini') {
      if (!cfg.geminiApiKey) {
        return { success: false, error: 'MISSING_API_KEY', provider: 'Google Gemini', hint: 'Please configure GEMINI_API_KEY in Settings.' };
      }
      try {
        const model = cfg.geminiModel || 'gemini-2.0-flash';
        const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${cfg.geminiApiKey.trim()}`;

        const geminiContents = [
          ...historyTurns.map(t => ({
            role: t.role === 'assistant' ? 'model' : 'user',
            parts: [{ text: t.content || '' }]
          })),
          { role: 'user', parts: [{ text: `${systemInstruction}\n\nUser Request: ${prompt}` }] }
        ];

        const res = await fetch(url, {
          method: 'POST',
          signal,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contents: geminiContents,
            generationConfig: { temperature: 0.2, maxOutputTokens: 1024 }
          })
        });

        const data = await res.json();
        if (!res.ok) {
          return { success: false, error: data.error?.message || `Gemini HTTP ${res.status}`, provider: 'Gemini' };
        }

        const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
        return parseLLMOutput(text, provider, model);
      } catch (err) {
        if (err.name === 'AbortError' || signal.aborted) {
          return { success: false, aborted: true, error: 'Execution halted by operator.' };
        }
        return { success: false, error: err.message, provider: 'Gemini' };
      }
    }

    // 3. OPENAI
    if (provider === 'openai') {
      if (!cfg.openaiApiKey) {
        return { success: false, error: 'MISSING_API_KEY', provider: 'OpenAI', hint: 'Please configure OPENAI_API_KEY in Settings.' };
      }
      try {
        const res = await fetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          signal,
          headers: {
            'Authorization': `Bearer ${cfg.openaiApiKey.trim()}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            model: cfg.openaiModel || 'gpt-4o-mini',
            messages: formattedChatMessages,
            temperature: 0.2
          })
        });

        const data = await res.json();
        if (!res.ok) {
          return { success: false, error: data.error?.message || `OpenAI HTTP ${res.status}`, provider: 'OpenAI' };
        }

        const text = data.choices?.[0]?.message?.content || '';
        return parseLLMOutput(text, provider, cfg.openaiModel);
      } catch (err) {
        if (err.name === 'AbortError' || signal.aborted) {
          return { success: false, aborted: true, error: 'Execution halted by operator.' };
        }
        return { success: false, error: err.message, provider: 'OpenAI' };
      }
    }

    // 4. ANTHROPIC CLAUDE
    if (provider === 'claude' || provider === 'anthropic') {
      if (!cfg.anthropicApiKey) {
        return { success: false, error: 'MISSING_API_KEY', provider: 'Anthropic Claude', hint: 'Please configure ANTHROPIC_API_KEY in Settings.' };
      }
      try {
        const claudeMessages = [
          ...historyTurns.map(t => ({
            role: t.role === 'assistant' ? 'assistant' : 'user',
            content: t.content || ''
          })),
          { role: 'user', content: prompt }
        ];

        const res = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          signal,
          headers: {
            'x-api-key': cfg.anthropicApiKey.trim(),
            'anthropic-version': '2023-06-01',
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            model: cfg.anthropicModel || 'claude-3-5-sonnet-20241022',
            system: systemInstruction,
            messages: claudeMessages,
            max_tokens: 1024
          })
        });

        const data = await res.json();
        if (!res.ok) {
          return { success: false, error: data.error?.message || `Claude HTTP ${res.status}`, provider: 'Claude' };
        }

        const text = data.content?.[0]?.text || '';
        return parseLLMOutput(text, provider, cfg.anthropicModel);
      } catch (err) {
        if (err.name === 'AbortError' || signal.aborted) {
          return { success: false, aborted: true, error: 'Execution halted by operator.' };
        }
        return { success: false, error: err.message, provider: 'Claude' };
      }
    }

    // 5. OLLAMA / LOCAL (100% Offline / Free)
    if (provider === 'ollama') {
      const host = (cfg.ollamaEndpoint || 'http://localhost:11434').replace(/\/+$/, '');
      const model = cfg.ollamaModel || 'llama3.2';
      try {
        const res = await fetch(`${host}/api/chat`, {
          method: 'POST',
          signal,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            model: model,
            messages: formattedChatMessages,
            stream: false,
            options: { temperature: 0.2 }
          })
        });
        const data = await res.json();
        if (!res.ok) {
          return { success: false, error: data.error || `Ollama HTTP ${res.status}`, provider: 'Ollama' };
        }
        const text = data.message?.content || '';
        return parseLLMOutput(text, provider, model);
      } catch (err) {
        if (err.name === 'AbortError' || signal.aborted) {
          return { success: false, aborted: true, error: 'Execution halted by operator.' };
        }
        return {
          success: false,
          error: `Ollama connection error: ${err.message}. Ensure daemon is running on ${host}.`,
          provider: 'Ollama'
        };
      }
    }

    // 6. CUSTOM / OTHER (OpenAI-compatible)
    if (provider === 'custom') {
      const url = (cfg.customBaseUrl || 'https://openrouter.ai/api/v1').replace(/\/+$/, '');
      const model = cfg.customModel || 'deepseek/deepseek-r1';
      try {
        const headers = { 'Content-Type': 'application/json' };
        if (cfg.customApiKey) headers['Authorization'] = `Bearer ${cfg.customApiKey.trim()}`;
        const res = await fetch(`${url}/chat/completions`, {
          method: 'POST',
          signal,
          headers: headers,
          body: JSON.stringify({
            model: model,
            messages: formattedChatMessages,
            temperature: 0.2
          })
        });
        const data = await res.json();
        if (!res.ok) {
          return { success: false, error: data.error?.message || `Custom HTTP ${res.status}`, provider: 'Custom' };
        }
        const text = data.choices?.[0]?.message?.content || '';
        return parseLLMOutput(text, provider, model);
      } catch (err) {
        if (err.name === 'AbortError' || signal.aborted) {
          return { success: false, aborted: true, error: 'Execution halted by operator.' };
        }
        return { success: false, error: err.message, provider: 'Custom' };
      }
    }

    return { success: false, error: `Unknown provider: ${provider}`, provider };
  } finally {
    if (activeLLMAbortController === controller) {
      activeLLMAbortController = null;
    }
  }
}

function parseLLMOutput(text, provider, model) {
  const clean = text.trim();
  // Check if LLM emitted JSON action
  try {
    let jsonStr = clean;
    if (clean.includes('```json')) {
      const match = clean.match(/```json\s*([\s\S]*?)\s*```/);
      if (match) jsonStr = match[1];
    } else if (clean.startsWith('{') && clean.endsWith('}')) {
      jsonStr = clean;
    }

    const parsed = JSON.parse(jsonStr);
    if (parsed.action_required || parsed.tool_intent || parsed.tool_name) {
      return {
        success: true,
        actionRequired: true,
        action: parsed,
        rawText: clean,
        provider,
        model
      };
    }
  } catch (e) {
    // Regular conversation text
  }

  return {
    success: true,
    actionRequired: false,
    text: clean,
    provider,
    model
  };
}

// ---------------------------------------------------------------------------
// 5. Electron Window Lifecycle
// ---------------------------------------------------------------------------

function createTray() {
  if (tray) return;
  try {
    const iconFile = path.join(__dirname, 'assets', process.platform === 'win32' ? 'icon.ico' : 'icon.png');
    const icon = fs.existsSync(iconFile)
      ? nativeImage.createFromPath(iconFile)
      : nativeImage.createFromBuffer(
          Buffer.from(
            'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAClJREFUOE9jZKAQMFKon2HUAIbRMAgZA5y0j7pBURAOxjDgygGkOAIA4rQBD2T5k1UAAAAASUVORK5CYII=',
            'base64'
          )
        );
    tray = new Tray(icon);
    const contextMenu = Menu.buildFromTemplate([
      {
        label: 'Open Mycelium',
        click: () => {
          if (mainWindow) {
            mainWindow.show();
            mainWindow.focus();
          }
        }
      },
      { type: 'separator' },
      {
        label: 'Quit',
        click: () => {
          app.isQuitting = true;
          app.quit();
        }
      }
    ]);
    tray.setToolTip('Mycelium Agent Coordinator');
    tray.setContextMenu(contextMenu);
    tray.on('double-click', () => {
      if (mainWindow) {
        mainWindow.show();
        mainWindow.focus();
      }
    });
  } catch (e) {
    console.warn('[Tray] Failed to initialize tray:', e.message);
  }
}

function createWindow() {
  const windowIcon = path.join(__dirname, 'assets', process.platform === 'win32' ? 'icon.ico' : 'icon.png');
  mainWindow = new BrowserWindow({
    width: 1380,
    height: 880,
    minWidth: 1040,
    minHeight: 640,
    icon: windowIcon,
    frame: false,
    titleBarStyle: 'hidden',
    titleBarOverlay: {
      color: '#080a09',
      symbolColor: '#94a3b8',
      height: 38
    },
    backgroundColor: '#080a09',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });

  if (typeof mainWindow.setMenuBarVisibility === 'function') {
    mainWindow.setMenuBarVisibility(false);
  }

  const storedCfg = getStoredConfig();
  if (storedCfg.zoomFactor) {
    try {
      mainWindow.webContents.setZoomFactor(Number(storedCfg.zoomFactor) || 1.0);
    } catch (e) {}
  }

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  mainWindow.on('close', (event) => {
    const config = getStoredConfig();
    if (config.minimizeToTray && !app.isQuitting) {
      event.preventDefault();
      mainWindow.hide();
      createTray();
      return false;
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// ---------------------------------------------------------------------------
// 6. IPC Handlers
// ---------------------------------------------------------------------------

// Config store
ipcMain.handle('config:get', async () => {
  return getStoredConfig();
});

ipcMain.handle('config:save', async (_event, newConfig) => {
  return saveStoredConfig(newConfig);
});

// Native Directory Selector
ipcMain.handle('dialog:select-workspace', async () => {
  if (!mainWindow) return { canceled: true };
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Select Active Workspace Directory',
    properties: ['openDirectory', 'createDirectory']
  });
  if (result.canceled || result.filePaths.length === 0) {
    return { canceled: true };
  }
  const selectedPath = result.filePaths[0];
  saveStoredConfig({ workspacePath: selectedPath });
  sendToDaemon({ action: 'SET_WORKSPACE', workspacePath: selectedPath });
  sendToDaemon({ action: 'GET_WORKSPACE_TREE' });
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('system-ready', { workspace: selectedPath });
  }
  return { canceled: false, path: selectedPath };
});

// Window zoom factor
ipcMain.handle('window:set-zoom', async (_event, factor) => {
  const num = Number(factor) || 1.0;
  if (mainWindow && !mainWindow.isDestroyed()) {
    try {
      mainWindow.webContents.setZoomFactor(num);
    } catch (e) {}
  }
  saveStoredConfig({ zoomFactor: num });
  return { success: true, zoomFactor: num };
});

// App Login Item Settings (Launch on Startup)
ipcMain.handle('app:set-login-item', async (_event, openAtLogin) => {
  try {
    app.setLoginItemSettings({
      openAtLogin: Boolean(openAtLogin),
      path: process.execPath
    });
    saveStoredConfig({ launchOnStartup: Boolean(openAtLogin) });
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// Clear App Cache & Session Data
ipcMain.handle('app:clear-data', async () => {
  try {
    if (mainWindow && !mainWindow.isDestroyed()) {
      await mainWindow.webContents.session.clearCache();
      await mainWindow.webContents.session.clearStorageData();
    }
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// Registry health & discovery
ipcMain.handle('registry:health', async (_event, registryUrl) => {
  const url = registryUrl || getStoredConfig().registryUrl;
  return checkRegistryHealth(url);
});

ipcMain.handle('registry:discover', async (_event, { query, registryUrl }) => {
  const url = registryUrl || getStoredConfig().registryUrl;
  return discoverRegistryAgents(url, query);
});

ipcMain.handle('registry:launch', async () => {
  return launchLocalRegistryServer();
});

// Multi-provider LLM prompt executor
ipcMain.handle('llm:prompt', async (_event, { prompt, context }) => {
  return executeLLMPrompt(prompt, context);
});

// Process abort & emergency circuit break handler
ipcMain.handle('process:abort', async () => {
  let llmAborted = false;
  if (activeLLMAbortController) {
    try {
      activeLLMAbortController.abort();
    } catch (e) {}
    activeLLMAbortController = null;
    llmAborted = true;
  }
  // Send immediate SIGKILL / terminate signal to Python supervisor daemon
  sendToDaemon({ action: 'ABORT' });
  return { success: true, aborted: true, llmAborted };
});

// Live provider credential validator & real-time connection tester
ipcMain.handle('provider:test-connection', async (_event, data) => {
  return testProviderConnection(data);
});

ipcMain.handle('provider:validate', async (_event, data) => {
  return testProviderConnection(data);
});

// External browser URL launcher
ipcMain.handle('shell:open-external', async (_event, url) => {
  if (url && (url.startsWith('https://') || url.startsWith('http://'))) {
    shell.openExternal(url);
    return { success: true };
  }
  return { success: false, error: 'Invalid URL scheme' };
});

// Python coordinator daemon bridge
ipcMain.on('dispatch-intent', (_event, data) => {
  sendToDaemon({ action: 'DISPATCH_INTENT', ...data });
});

ipcMain.on('hol-decision', (_event, { quarantineId, approved }) => {
  sendToDaemon({ action: 'HOL_DECISION', quarantineId, approved });
});

ipcMain.on('get-workspace-tree', () => {
  sendToDaemon({ action: 'GET_WORKSPACE_TREE' });
});

ipcMain.on('get-mesh-nodes', () => {
  sendToDaemon({ action: 'GET_MESH_NODES' });
});

ipcMain.on('read-file', (_event, { filePath }) => {
  sendToDaemon({ action: 'READ_FILE', filePath });
});

ipcMain.on('write-file', (_event, { filePath, content }) => {
  sendToDaemon({ action: 'WRITE_FILE', filePath, content });
});

// Window controls
ipcMain.on('window-minimize', () => mainWindow?.minimize());
ipcMain.on('window-maximize', () => {
  if (mainWindow?.isMaximized()) {
    mainWindow.unmaximize();
  } else {
    mainWindow?.maximize();
  }
});
ipcMain.on('window-close', () => mainWindow?.close());

function setupApplicationMenu() {
  if (!Menu) return;
  const menuTemplate = [
    {
      label: 'Edit',
      submenu: [
        { role: 'undo' },
        { role: 'redo' },
        { type: 'separator' },
        { role: 'cut' },
        { role: 'copy' },
        { role: 'paste' },
        { role: 'selectAll' }
      ]
    },
    {
      label: 'Developer',
      submenu: [
        {
          label: 'Toggle Settings Modal',
          accelerator: 'CommandOrControl+,',
          click: () => mainWindow?.webContents.send('shortcut:toggle-settings')
        },
        {
          label: 'Toggle Workspace Explorer',
          accelerator: 'CommandOrControl+B',
          click: () => mainWindow?.webContents.send('shortcut:toggle-sidebar')
        },
        {
          label: 'Focus Slash Command Bar',
          accelerator: 'CommandOrControl+K',
          click: () => mainWindow?.webContents.send('shortcut:focus-prompt')
        },
        {
          label: 'Toggle Terminal Drawer',
          accelerator: 'CommandOrControl+`',
          click: () => mainWindow?.webContents.send('shortcut:toggle-drawer')
        },
        {
          label: 'Dismiss / Close Modal',
          accelerator: 'Escape',
          click: () => mainWindow?.webContents.send('shortcut:escape')
        },
        { type: 'separator' },
        { role: 'reload' },
        { role: 'forceReload' },
        { role: 'toggleDevTools' }
      ]
    }
  ];
  const menu = Menu.buildFromTemplate(menuTemplate);
  Menu.setApplicationMenu(menu);
}

// Lifecycle handlers
app.whenReady().then(() => {
  setupApplicationMenu();
  spawnPythonDaemon();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (pythonDaemon) {
    try {
      pythonDaemon.kill();
    } catch (e) {}
  }
  if (registryProcess) {
    try {
      registryProcess.kill();
    } catch (e) {}
  }
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('will-quit', () => {
  if (pythonDaemon) {
    try {
      pythonDaemon.kill();
    } catch (e) {}
  }
  if (registryProcess) {
    try {
      registryProcess.kill();
    } catch (e) {}
  }
});
