/**
 * US Neural - Mycelium Desktop Application
 * Preload Script (Secure IPC Context Bridge)
 * Exposes Config, Registry Health, LLM Gateway, and Coordinator APIs
 */

const { contextBridge, ipcRenderer, webFrame } = require('electron');

contextBridge.exposeInMainWorld('mycelium', {
  // Settings & Configuration Store
  getConfig: () => ipcRenderer.invoke('config:get'),
  saveConfig: (newConfig) => ipcRenderer.invoke('config:save', newConfig),

  // Appearance & Desktop Zoom
  setZoomFactor: (factor) => {
    try {
      webFrame.setZoomFactor(Number(factor) || 1.0);
    } catch (e) {}
    return ipcRenderer.invoke('window:set-zoom', factor);
  },

  // Native Workspace Directory Selector
  selectWorkspaceDirectory: () => ipcRenderer.invoke('dialog:select-workspace'),

  // Desktop Integration & Startup
  setLoginItemSettings: (openAtLogin) => ipcRenderer.invoke('app:set-login-item', openAtLogin),

  // Session & Maintenance Cache
  clearAppData: () => ipcRenderer.invoke('app:clear-data'),

  // Live Mycelium Semantic Registry
  checkRegistryHealth: (registryUrl) => ipcRenderer.invoke('registry:health', registryUrl),
  discoverRegistry: (query, registryUrl) => ipcRenderer.invoke('registry:discover', { query, registryUrl }),
  launchRegistry: () => ipcRenderer.invoke('registry:launch'),

  // Multi-Provider LLM Gateway & Validation
  executePrompt: (prompt, context) => ipcRenderer.invoke('llm:prompt', { prompt, context }),
  testProviderConnection: (params) => ipcRenderer.invoke('provider:test-connection', params),
  validateProviderKey: (params) => ipcRenderer.invoke('provider:test-connection', params),
  openExternal: (url) => ipcRenderer.invoke('shell:open-external', url),

  // Python Coordinator Command & Intent Dispatch
  dispatchIntent: (data) => ipcRenderer.send('dispatch-intent', data),
  
  // HOL (Human-On-The-Loop) Quarantine Decision
  submitHolDecision: (quarantineId, approved) => ipcRenderer.send('hol-decision', { quarantineId, approved }),

  // Workspace Operations
  getWorkspaceTree: () => ipcRenderer.send('get-workspace-tree'),
  readFile: (filePath) => ipcRenderer.send('read-file', { filePath }),
  writeFile: (filePath, content) => ipcRenderer.send('write-file', { filePath, content }),

  // Mesh Network Telemetry
  getMeshNodes: () => ipcRenderer.send('get-mesh-nodes'),

  // Window Controls
  minimizeWindow: () => ipcRenderer.send('window-minimize'),
  maximizeWindow: () => ipcRenderer.send('window-maximize'),
  closeWindow: () => ipcRenderer.send('window-close'),

  // Process & Subprocess Abort / Circuit Breaker
  abortExecution: () => ipcRenderer.invoke('process:abort'),

  // Event Listeners from Python Coordinator via Electron Main
  onSystemReady: (callback) => {
    ipcRenderer.on('system-ready', (_event, data) => callback(data));
  },
  onSemanticDiscovery: (callback) => {
    ipcRenderer.on('semantic-discovery', (_event, data) => callback(data));
  },
  onHolQuarantine: (callback) => {
    ipcRenderer.on('hol-quarantine', (_event, data) => callback(data));
  },
  onExecutionComplete: (callback) => {
    ipcRenderer.on('execution-complete', (_event, data) => callback(data));
  },
  onExecutionAborted: (callback) => {
    ipcRenderer.on('execution-aborted', (_event, data) => callback(data));
  },
  onWorkspaceTree: (callback) => {
    ipcRenderer.on('workspace-tree', (_event, data) => callback(data));
  },
  onMeshNodes: (callback) => {
    ipcRenderer.on('mesh-nodes', (_event, data) => callback(data));
  },
  onFileContent: (callback) => {
    ipcRenderer.on('file-content', (_event, data) => callback(data));
  },
  onFileWritten: (callback) => {
    ipcRenderer.on('file-written', (_event, data) => callback(data));
  },
  onBridgeError: (callback) => {
    ipcRenderer.on('bridge-error', (_event, data) => callback(data));
  },

  // Universal Developer Shortcuts Event Listener
  onShortcut: (callback) => {
    const channels = [
      'shortcut:toggle-settings',
      'shortcut:toggle-sidebar',
      'shortcut:focus-prompt',
      'shortcut:toggle-drawer',
      'shortcut:escape'
    ];
    channels.forEach((channel) => {
      ipcRenderer.on(channel, (_event, ...args) => callback(channel.replace('shortcut:', ''), ...args));
    });
  }
});
