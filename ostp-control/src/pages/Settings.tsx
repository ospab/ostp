import { useState, useEffect } from 'react';
import { 
  Settings as SettingsIcon, Globe, Key, CheckCircle, XCircle, 
  RefreshCw, Save, Sliders, Code2, AlertTriangle
} from 'lucide-react';
import { getApiSettings, saveApiSettings, api } from '../lib/api';
import { useLanguage } from '../lib/LanguageContext';
import { addAuditLog } from '../lib/audit';

export default function Settings() {
  const { t, language } = useLanguage();

  // Tabs: 'connection' | 'interactive' | 'raw'
  const [activeTab, setActiveTab] = useState<'connection' | 'interactive' | 'raw'>('interactive');

  // Connection settings state
  const [panelApiUrl, setPanelApiUrl] = useState('');
  const [panelApiToken, setPanelApiToken] = useState('');
  const [isTestingConnection, setIsTestingConnection] = useState(false);
  const [connectionTestResult, setConnectionTestResult] = useState<{ success: boolean; message: string } | null>(null);

  // Full Server Config JSON state
  const [config, setConfig] = useState<any>(null);
  const [rawJson, setRawJson] = useState('');
  const [isLoadingConfig, setIsLoadingConfig] = useState(false);
  const [configError, setConfigError] = useState<string | null>(null);
  const [saveStatus, setSaveStatus] = useState<{ success: boolean; message: string } | null>(null);

  // Initial load
  useEffect(() => {
    const { url, token } = getApiSettings();
    setPanelApiUrl(url);
    setPanelApiToken(token);
    fetchServerConfig();
  }, []);

  const fetchServerConfig = async () => {
    setIsLoadingConfig(true);
    setConfigError(null);
    try {
      const data = await api.getServerConfig();
      setConfig(data);
      setRawJson(JSON.stringify(data, null, 2));
    } catch (err: any) {
      setConfigError(language === 'ru' 
        ? 'Не удалось загрузить конфигурацию сервера. Проверьте настройки подключения.' 
        : 'Failed to load server configuration. Please check connection parameters.');
    } finally {
      setIsLoadingConfig(false);
    }
  };

  const handleTestConnection = async () => {
    setIsTestingConnection(true);
    setConnectionTestResult(null);
    const oldUrl = localStorage.getItem('ostp_api_url');
    const oldToken = localStorage.getItem('ostp_api_token');
    
    try {
      saveApiSettings(panelApiUrl, panelApiToken);
      const status = await api.getServerStatus();
      setConnectionTestResult({
        success: true,
        message: t('st_conn_success', { version: status.version, users: status.active_users }),
      });
      addAuditLog(
        `Tested connection to Management API at ${panelApiUrl} (Success)`,
        `Успешно протестировано подключение к API по адресу ${panelApiUrl}`,
        true
      );
    } catch (err: any) {
      if (oldUrl) localStorage.setItem('ostp_api_url', oldUrl);
      if (oldToken !== null) localStorage.setItem('ostp_api_token', oldToken);
      
      const errorMsgStr = err.message || err;
      setConnectionTestResult({
        success: false,
        message: t('st_conn_error', { error: errorMsgStr }),
      });
      addAuditLog(
        `Tested connection to Management API at ${panelApiUrl} (Failed: ${errorMsgStr})`,
        `Ошибка при тесте подключения к API по адресу ${panelApiUrl} (${errorMsgStr})`,
        false
      );
    } finally {
      setIsTestingConnection(false);
    }
  };

  const handleSaveConnection = () => {
    saveApiSettings(panelApiUrl, panelApiToken);
    alert(language === 'ru' ? 'Настройки подключения сохранены!' : 'Connection settings saved!');
    addAuditLog(
      `Saved API connection settings: ${panelApiUrl}`,
      `Сохранены настройки подключения к API: ${panelApiUrl}`,
      true
    );
    window.location.reload();
  };

  // Save Config to Server
  const handleSaveConfig = async (configToSave: any) => {
    setSaveStatus(null);
    try {
      await api.updateServerConfig(configToSave);
      setSaveStatus({
        success: true,
        message: t('st_save_success'),
      });
      
      addAuditLog(
        'Updated server config.json configuration',
        'Обновлена конфигурация config.json сервера',
        true
      );
      
      // Refresh current state
      setConfig(configToSave);
      setRawJson(JSON.stringify(configToSave, null, 2));
    } catch (err: any) {
      setSaveStatus({
        success: false,
        message: `${t('st_save_error')} ${err.message || err}`,
      });
      
      addAuditLog(
        `Failed to update server configuration: ${err.message || err}`,
        `Не удалось сохранить конфигурацию: ${err.message || err}`,
        false
      );
    }
  };

  const handleInteractiveSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!config) return;
    handleSaveConfig(config);
  };

  const handleRawSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const parsed = JSON.parse(rawJson);
      handleSaveConfig(parsed);
    } catch (err: any) {
      setSaveStatus({
        success: false,
        message: `${t('st_save_error')} Invalid JSON: ${err.message}`,
      });
    }
  };

  // Helper to deep modify config fields
  const updateConfigField = (path: string[], value: any) => {
    if (!config) return;
    const newConfig = { ...config };
    let current = newConfig;
    for (let i = 0; i < path.length - 1; i++) {
      if (current[path[i]] === undefined) {
        current[path[i]] = {};
      }
      current = current[path[i]];
    }
    current[path[path.length - 1]] = value;
    setConfig(newConfig);
    setRawJson(JSON.stringify(newConfig, null, 2));
  };

  return (
    <div className="relative z-10 w-full max-w-6xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold tracking-tight mb-1 flex items-center gap-3">
            <SettingsIcon className="w-8 h-8 text-primary" /> {t('st_title')}
          </h1>
          <p className="text-text-muted">{t('st_subtitle')}</p>
        </div>
        
        {config && (
          <button 
            onClick={fetchServerConfig}
            className="flex items-center gap-2 bg-white/5 hover:bg-white/10 text-white px-4 py-2.5 rounded-xl border border-white/10 text-sm transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${isLoadingConfig ? 'animate-spin text-primary' : ''}`} /> {t('st_reset')}
          </button>
        )}
      </div>

      {/* Navigation tabs */}
      <div className="flex border-b border-white/5 gap-2">
        <button
          onClick={() => setActiveTab('interactive')}
          className={`flex items-center gap-2 px-5 py-3 font-medium transition-colors border-b-2 text-sm ${
            activeTab === 'interactive' ? 'border-primary text-white' : 'border-transparent text-text-muted hover:text-white'
          }`}
        >
          <Sliders className="w-4 h-4" /> {t('st_tab_ui')}
        </button>
        <button
          onClick={() => setActiveTab('raw')}
          className={`flex items-center gap-2 px-5 py-3 font-medium transition-colors border-b-2 text-sm ${
            activeTab === 'raw' ? 'border-primary text-white' : 'border-transparent text-text-muted hover:text-white'
          }`}
        >
          <Code2 className="w-4 h-4" /> {t('st_tab_json')}
        </button>
        <button
          onClick={() => setActiveTab('connection')}
          className={`flex items-center gap-2 px-5 py-3 font-medium transition-colors border-b-2 text-sm ${
            activeTab === 'connection' ? 'border-primary text-white' : 'border-transparent text-text-muted hover:text-white'
          }`}
        >
          <Globe className="w-4 h-4" /> {t('st_tab_conn')}
        </button>
      </div>

      {/* Global save notifications */}
      {saveStatus && (
        <div className={`p-4 rounded-xl flex items-start gap-3 border animate-in fade-in duration-200 ${
          saveStatus.success ? 'bg-secondary/10 border-secondary/20 text-secondary' : 'bg-red-500/10 border-red-500/20 text-red-400'
        }`}>
          {saveStatus.success ? <CheckCircle className="w-5 h-5 shrink-0 mt-0.5" /> : <XCircle className="w-5 h-5 shrink-0 mt-0.5" />}
          <div>
            <p className="font-semibold text-sm">{saveStatus.success ? 'Success' : 'Error'}</p>
            <p className="text-xs mt-1 opacity-90 leading-relaxed font-mono">{saveStatus.message}</p>
          </div>
        </div>
      )}

      {configError && (
        <div className="bg-red-500/10 border border-red-500/20 text-red-400 p-4 rounded-xl flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 shrink-0" />
          <p className="text-sm font-semibold">{configError}</p>
        </div>
      )}

      {/* ── TAB: CONNECTION SETTINGS ── */}
      {activeTab === 'connection' && (
        <div className="glass-panel rounded-2xl p-6 space-y-6">
          <div>
            <h2 className="text-xl font-semibold mb-2">{t('st_conn_title')}</h2>
            <p className="text-sm text-text-muted">
              {t('st_conn_desc')}
            </p>
          </div>

          <div className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium flex items-center gap-2">
                <Globe className="w-4 h-4 text-primary" /> {t('st_conn_url')}
              </label>
              <input
                type="text"
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white placeholder-text-muted focus:outline-none focus:border-primary transition-colors font-mono"
                placeholder="e.g. http://localhost:9090"
                value={panelApiUrl}
                onChange={(e) => setPanelApiUrl(e.target.value)}
              />
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium flex items-center gap-2">
                <Key className="w-4 h-4 text-primary" /> {t('st_conn_token')}
              </label>
              <input
                type="password"
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white placeholder-text-muted focus:outline-none focus:border-primary transition-colors font-mono"
                placeholder={t('st_conn_token_sub')}
                value={panelApiToken}
                onChange={(e) => setPanelApiToken(e.target.value)}
              />
            </div>
          </div>

          <div className="flex gap-4 pt-4 border-t border-white/5">
            <button
              onClick={handleTestConnection}
              disabled={isTestingConnection || !panelApiUrl}
              className="flex items-center gap-2 bg-white/5 hover:bg-white/10 text-white px-5 py-2.5 rounded-xl font-medium transition-colors border border-white/10"
            >
              <RefreshCw className={`w-5 h-5 ${isTestingConnection ? 'animate-spin text-primary' : ''}`} /> {t('st_conn_test')}
            </button>
            
            <button
              onClick={handleSaveConnection}
              disabled={!panelApiUrl}
              className="flex items-center gap-2 bg-primary hover:bg-primary/90 text-white px-6 py-2.5 rounded-xl font-medium transition-colors shadow-[0_0_15px_rgba(108,114,255,0.3)]"
            >
              <Save className="w-5 h-5" /> {t('st_conn_save')}
            </button>
          </div>

          {connectionTestResult && (
            <div className={`mt-4 p-4 rounded-xl flex items-start gap-3 border ${
              connectionTestResult.success ? 'bg-secondary/10 border-secondary/20 text-secondary' : 'bg-red-500/10 border-red-500/20 text-red-400'
            }`}>
              {connectionTestResult.success ? <CheckCircle className="w-5 h-5 shrink-0 mt-0.5" /> : <XCircle className="w-5 h-5 shrink-0 mt-0.5" />}
              <div>
                <p className="font-semibold text-sm">{connectionTestResult.success ? 'Success' : 'Failed'}</p>
                <p className="text-xs mt-1 opacity-90 font-mono break-all">{connectionTestResult.message}</p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── TAB: RAW JSON EDITOR ── */}
      {activeTab === 'raw' && config && (
        <form onSubmit={handleRawSubmit} className="glass-panel rounded-2xl p-6 space-y-4">
          <div>
            <h2 className="text-xl font-semibold mb-2">{t('st_raw_title')}</h2>
            <p className="text-sm text-text-muted">
              {t('st_raw_desc')}
            </p>
          </div>

          <div className="relative">
            <textarea
              className="w-full min-h-[500px] bg-black/40 border border-white/10 rounded-xl p-4 font-mono text-sm text-white focus:outline-none focus:border-primary"
              value={rawJson}
              onChange={(e) => setRawJson(e.target.value)}
            />
          </div>

          <div className="pt-4 border-t border-white/5">
            <button
              type="submit"
              className="flex items-center gap-2 bg-primary hover:bg-primary/90 text-white px-6 py-2.5 rounded-xl font-semibold transition-colors shadow-[0_0_15px_rgba(108,114,255,0.3)]"
            >
              <Save className="w-5 h-5" /> {t('st_save_btn')}
            </button>
          </div>
        </form>
      )}

      {/* ── TAB: INTERACTIVE CONFIG EDITOR ── */}
      {activeTab === 'interactive' && config && (
        <form onSubmit={handleInteractiveSubmit} className="space-y-6">
          {/* SECTION: GENERAL */}
          <div className="glass-panel rounded-2xl p-6 space-y-4">
            <h2 className="text-lg font-bold border-b border-white/5 pb-2 text-white flex items-center gap-2">
              <Sliders className="w-5 h-5 text-primary" /> {t('st_ui_general')}
            </h2>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <label className="text-sm font-semibold text-text-muted uppercase">{t('st_ui_log')}</label>
                <select
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-primary"
                  value={config.log_level || 'info'}
                  onChange={(e) => updateConfigField(['log_level'], e.target.value)}
                >
                  <option value="debug">debug</option>
                  <option value="info">info</option>
                  <option value="warn">warn</option>
                  <option value="error">error</option>
                </select>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-semibold text-text-muted uppercase">{t('st_ui_port')}</label>
                <input
                  type="text"
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white font-mono"
                  placeholder="e.g. 0.0.0.0:50000"
                  value={typeof config.listen === 'string' ? config.listen : JSON.stringify(config.listen)}
                  onChange={(e) => {
                    let val: any = e.target.value;
                    try {
                      val = JSON.parse(e.target.value);
                    } catch {
                      // fallback as string
                    }
                    updateConfigField(['listen'], val);
                  }}
                />
              </div>
            </div>

            <div className="flex items-center gap-3 pt-2">
              <input
                type="checkbox"
                id="general-debug"
                className="w-4 h-4 accent-primary rounded bg-white/5 border-white/10"
                checked={config.debug || false}
                onChange={(e) => updateConfigField(['debug'], e.target.checked)}
              />
              <label htmlFor="general-debug" className="text-sm font-medium text-white cursor-pointer select-none">
                {t('st_ui_debug')}
              </label>
            </div>
          </div>

          {/* SECTION: MANAGEMENT API */}
          <div className="glass-panel rounded-2xl p-6 space-y-4">
            <h2 className="text-lg font-bold border-b border-white/5 pb-2 text-white flex items-center gap-2">
              <Globe className="w-5 h-5 text-secondary" /> {t('st_ui_api_title')}
            </h2>
            
            <div className="flex items-center gap-3 mb-2">
              <input
                type="checkbox"
                id="api-enabled"
                className="w-4 h-4 accent-primary rounded bg-white/5 border-white/10"
                checked={config.api?.enabled || false}
                onChange={(e) => updateConfigField(['api', 'enabled'], e.target.checked)}
              />
              <label htmlFor="api-enabled" className="text-sm font-medium text-white cursor-pointer select-none">
                {t('st_ui_api_enable')}
              </label>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <label className="text-sm font-semibold text-text-muted uppercase">{t('st_ui_api_bind')}</label>
                <input
                  type="text"
                  disabled={!config.api?.enabled}
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white font-mono disabled:opacity-50"
                  placeholder="e.g. 127.0.0.1:9090"
                  value={config.api?.bind || ''}
                  onChange={(e) => updateConfigField(['api', 'bind'], e.target.value)}
                />
              </div>

              <div className="space-y-2">
                <label className="text-sm font-semibold text-text-muted uppercase">{t('st_ui_api_token')}</label>
                <input
                  type="text"
                  disabled={!config.api?.enabled}
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white font-mono disabled:opacity-50"
                  placeholder="Leave blank to disable authorization"
                  value={config.api?.token || ''}
                  onChange={(e) => updateConfigField(['api', 'token'], e.target.value)}
                />
              </div>
            </div>
            
            {config.api?.enabled && (
              <div className="p-3 bg-yellow-500/10 border border-yellow-500/20 text-yellow-400 rounded-xl flex items-start gap-2">
                <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
                <p className="text-xs leading-relaxed font-sans">
                  <strong>{t('st_ui_api_warning')}</strong>
                </p>
              </div>
            )}
          </div>

          {/* SECTION: FALLBACK PROXY */}
          <div className="glass-panel rounded-2xl p-6 space-y-4">
            <h2 className="text-lg font-bold border-b border-white/5 pb-2 text-white flex items-center gap-2">
              <Globe className="w-5 h-5 text-blue-400" /> {t('st_ui_fb_title')}
            </h2>

            <div className="flex items-center gap-3 mb-2">
              <input
                type="checkbox"
                id="fallback-enabled"
                className="w-4 h-4 accent-primary rounded bg-white/5 border-white/10"
                checked={config.fallback?.enabled || false}
                onChange={(e) => updateConfigField(['fallback', 'enabled'], e.target.checked)}
              />
              <label htmlFor="fallback-enabled" className="text-sm font-medium text-white cursor-pointer select-none">
                {t('st_ui_fb_enable')}
              </label>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <label className="text-sm font-semibold text-text-muted uppercase">{t('st_ui_fb_port')}</label>
                <input
                  type="text"
                  disabled={!config.fallback?.enabled}
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white font-mono disabled:opacity-50"
                  placeholder="e.g. 0.0.0.0:443"
                  value={config.fallback?.listen || ''}
                  onChange={(e) => updateConfigField(['fallback', 'listen'], e.target.value)}
                />
              </div>

              <div className="space-y-2">
                <label className="text-sm font-semibold text-text-muted uppercase">{t('st_ui_fb_target')}</label>
                <input
                  type="text"
                  disabled={!config.fallback?.enabled}
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white font-mono disabled:opacity-50"
                  placeholder="e.g. 127.0.0.1:8080"
                  value={config.fallback?.target || ''}
                  onChange={(e) => updateConfigField(['fallback', 'target'], e.target.value)}
                />
              </div>
            </div>
          </div>

          {/* SECTION: REALITY MASQUERADE */}
          <div className="glass-panel rounded-2xl p-6 space-y-4">
            <h2 className="text-lg font-bold border-b border-white/5 pb-2 text-white flex items-center gap-2">
              <Globe className="w-5 h-5 text-purple-400" /> {t('st_ui_rl_title')}
            </h2>

            <div className="flex items-center gap-3 mb-2">
              <input
                type="checkbox"
                id="reality-enabled"
                className="w-4 h-4 accent-primary rounded bg-white/5 border-white/10"
                checked={config.reality?.enabled || false}
                onChange={(e) => updateConfigField(['reality', 'enabled'], e.target.checked)}
              />
              <label htmlFor="reality-enabled" className="text-sm font-medium text-white cursor-pointer select-none">
                {t('st_ui_rl_enable')}
              </label>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2 col-span-1 md:col-span-2">
                <label className="text-sm font-semibold text-text-muted uppercase">{t('st_ui_rl_dest')}</label>
                <input
                  type="text"
                  disabled={!config.reality?.enabled}
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white font-mono disabled:opacity-50"
                  placeholder="e.g. www.microsoft.com:443"
                  value={config.reality?.dest || ''}
                  onChange={(e) => updateConfigField(['reality', 'dest'], e.target.value)}
                />
              </div>

              <div className="space-y-2">
                <label className="text-sm font-semibold text-text-muted uppercase">{t('st_ui_rl_pri')}</label>
                <input
                  type="text"
                  disabled={!config.reality?.enabled}
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white font-mono disabled:opacity-50 text-xs"
                  value={config.reality?.private_key || ''}
                  onChange={(e) => updateConfigField(['reality', 'private_key'], e.target.value)}
                />
              </div>

              <div className="space-y-2">
                <label className="text-sm font-semibold text-text-muted uppercase">{t('st_ui_rl_pub')}</label>
                <input
                  type="text"
                  disabled={!config.reality?.enabled}
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white font-mono disabled:opacity-50 text-xs"
                  value={config.reality?.pbk || ''}
                  onChange={(e) => updateConfigField(['reality', 'pbk'], e.target.value)}
                />
              </div>

              <div className="space-y-2">
                <label className="text-sm font-semibold text-text-muted uppercase">{t('st_ui_rl_sid')}</label>
                <input
                  type="text"
                  disabled={!config.reality?.enabled}
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white font-mono disabled:opacity-50"
                  value={config.reality?.sid || ''}
                  onChange={(e) => updateConfigField(['reality', 'sid'], e.target.value)}
                />
              </div>

              <div className="space-y-2">
                <label className="text-sm font-semibold text-text-muted uppercase">{t('st_ui_rl_sni')}</label>
                <input
                  type="text"
                  disabled={!config.reality?.enabled}
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white font-mono disabled:opacity-50"
                  placeholder="e.g. www.microsoft.com, microsoft.com"
                  value={config.reality?.sni_list ? config.reality.sni_list.join(', ') : ''}
                  onChange={(e) => {
                    const list = e.target.value.split(',').map(s => s.trim()).filter(Boolean);
                    updateConfigField(['reality', 'sni_list'], list);
                  }}
                />
              </div>
            </div>
          </div>

          {/* SECTION: OUTBOUND ROUTING */}
          <div className="glass-panel rounded-2xl p-6 space-y-4">
            <h2 className="text-lg font-bold border-b border-white/5 pb-2 text-white flex items-center gap-2">
              <Globe className="w-5 h-5 text-red-400" /> {t('st_ui_ob_title')}
            </h2>

            <div className="flex items-center gap-3 mb-2">
              <input
                type="checkbox"
                id="outbound-enabled"
                className="w-4 h-4 accent-primary rounded bg-white/5 border-white/10"
                checked={config.outbound?.enabled || false}
                onChange={(e) => updateConfigField(['outbound', 'enabled'], e.target.checked)}
              />
              <label htmlFor="outbound-enabled" className="text-sm font-medium text-white cursor-pointer select-none">
                {t('st_ui_ob_enable')}
              </label>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="space-y-2">
                <label className="text-sm font-semibold text-text-muted uppercase">{t('st_ui_ob_proto')}</label>
                <select
                  disabled={!config.outbound?.enabled}
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-primary disabled:opacity-50"
                  value={config.outbound?.protocol || 'socks5'}
                  onChange={(e) => updateConfigField(['outbound', 'protocol'], e.target.value)}
                >
                  <option value="socks5">socks5</option>
                </select>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-semibold text-text-muted uppercase">{t('st_ui_ob_addr')}</label>
                <input
                  type="text"
                  disabled={!config.outbound?.enabled}
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white font-mono disabled:opacity-50"
                  placeholder="e.g. 127.0.0.1"
                  value={config.outbound?.address || ''}
                  onChange={(e) => updateConfigField(['outbound', 'address'], e.target.value)}
                />
              </div>

              <div className="space-y-2">
                <label className="text-sm font-semibold text-text-muted uppercase">{t('st_ui_ob_port')}</label>
                <input
                  type="number"
                  disabled={!config.outbound?.enabled}
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white font-mono disabled:opacity-50"
                  placeholder="e.g. 9050"
                  value={config.outbound?.port || ''}
                  onChange={(e) => updateConfigField(['outbound', 'port'], parseInt(e.target.value) || 0)}
                />
              </div>

              <div className="space-y-2 col-span-1 md:col-span-3">
                <label className="text-sm font-semibold text-text-muted uppercase">{t('st_ui_ob_action')}</label>
                <select
                  disabled={!config.outbound?.enabled}
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white focus:outline-none focus:border-primary disabled:opacity-50"
                  value={config.outbound?.default_action || 'direct'}
                  onChange={(e) => updateConfigField(['outbound', 'default_action'], e.target.value)}
                >
                  <option value="direct">{t('st_ui_ob_action_direct')}</option>
                  <option value="proxy">{t('st_ui_ob_action_proxy')}</option>
                </select>
              </div>
            </div>
          </div>

          {/* Form Actions */}
          <div className="flex gap-4">
            <button
              type="submit"
              className="flex items-center gap-2 bg-primary hover:bg-primary/90 text-white px-6 py-3 rounded-xl font-bold transition-colors shadow-[0_0_15px_rgba(108,114,255,0.3)]"
            >
              <Save className="w-5 h-5" /> {t('st_save_btn')}
            </button>
          </div>
        </form>
      )}
    </div>
  );
}
