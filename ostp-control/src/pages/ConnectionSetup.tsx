import React, { useState } from 'react';
import { Shield, Globe, Key, CheckCircle, XCircle, RefreshCw, ChevronRight } from 'lucide-react';
import { saveApiSettings, api } from '../lib/api';
import { useLanguage } from '../lib/LanguageContext';
import { addAuditLog } from '../lib/audit';

interface ConnectionSetupProps {
  onSetupComplete: () => void;
}

export default function ConnectionSetup({ onSetupComplete }: ConnectionSetupProps) {
  const { t, language } = useLanguage();
  
  const [apiUrl, setApiUrl] = useState('http://localhost:9090');
  const [apiToken, setApiToken] = useState('');
  const [isTesting, setIsTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);

  const handleTestAndSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!apiUrl) return;

    setIsTesting(true);
    setTestResult(null);

    const formattedUrl = apiUrl.trim().replace(/\/$/, '');
    const formattedToken = apiToken.trim();
    
    const oldUrl = localStorage.getItem('ostp_api_url');
    const oldToken = localStorage.getItem('ostp_api_token');

    try {
      saveApiSettings(formattedUrl, formattedToken);
      const status = await api.getServerStatus();
      
      setTestResult({
        success: true,
        message: language === 'ru' 
          ? `Успешно подключено! Версия сервера: v${status.version}, активных сессий: ${status.active_users}`
          : `Successfully connected! Server version: v${status.version}, active sessions: ${status.active_users}`,
      });
      
      addAuditLog(
        `Initial setup connected to API at ${formattedUrl} (Version: v${status.version})`,
        `Первоначальная настройка успешно подключена к API по адресу ${formattedUrl} (Версия: v${status.version})`,
        true
      );

      setTimeout(() => {
        onSetupComplete();
      }, 1000);
    } catch (err: any) {
      if (oldUrl) localStorage.setItem('ostp_api_url', oldUrl);
      else localStorage.removeItem('ostp_api_url');
      if (oldToken !== null) localStorage.setItem('ostp_api_token', oldToken);
      else localStorage.removeItem('ostp_api_token');

      const errorMsgStr = err.message || err;
      setTestResult({
        success: false,
        message: `${t('conn_setup_error')}${errorMsgStr}`,
      });
      
      addAuditLog(
        `Initial setup failed to connect to ${formattedUrl}: ${errorMsgStr}`,
        `Первоначальная настройка не смогла подключиться к ${formattedUrl}: ${errorMsgStr}`,
        false
      );
    } finally {
      setIsTesting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background p-4 overflow-y-auto">
      {/* Background blobs */}
      <div className="absolute top-[10%] left-[10%] w-[50%] h-[50%] rounded-full bg-primary/10 blur-[150px] pointer-events-none"></div>
      <div className="absolute bottom-[10%] right-[10%] w-[50%] h-[50%] rounded-full bg-secondary/5 blur-[150px] pointer-events-none"></div>

      <div className="relative w-full max-w-lg glass-panel rounded-3xl p-8 space-y-6 shadow-2xl border border-white/10 my-8">
        <div className="text-center space-y-2">
          <div className="inline-flex p-4 bg-primary/10 rounded-2xl mb-2 text-primary border border-primary/20">
            <Shield className="w-12 h-12" />
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight text-white">OSTP<span className="text-primary">CORE</span></h1>
          <p className="text-text-muted text-sm">{t('conn_setup_sub')}</p>
        </div>

        <div className="bg-white/5 border border-white/5 p-4 rounded-2xl space-y-2 text-white">
          <h2 className="text-sm font-semibold">{t('conn_setup_header')}</h2>
          <p className="text-xs text-text-muted leading-relaxed">
            {t('conn_setup_desc')}
          </p>
        </div>

        <form onSubmit={handleTestAndSave} className="space-y-4">
          <div className="space-y-2">
            <label className="text-xs font-semibold text-text-muted uppercase tracking-wider flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5 text-primary" /> {t('conn_setup_url_label')}
            </label>
            <input
              type="text"
              required
              className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white placeholder-text-muted focus:outline-none focus:border-primary transition-colors font-mono text-sm"
              placeholder="e.g. http://localhost:9090"
              value={apiUrl}
              onChange={(e) => setApiUrl(e.target.value)}
            />
          </div>

          <div className="space-y-2">
            <label className="text-xs font-semibold text-text-muted uppercase tracking-wider flex items-center gap-1.5">
              <Key className="w-3.5 h-3.5 text-primary" /> {t('conn_setup_token_label')}
            </label>
            <input
              type="password"
              required
              className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white placeholder-text-muted focus:outline-none focus:border-primary transition-colors font-mono text-sm"
              placeholder={t('conn_setup_token_placeholder')}
              value={apiToken}
              onChange={(e) => setApiToken(e.target.value)}
            />
          </div>

          <button
            type="submit"
            disabled={isTesting || !apiUrl || !apiToken}
            className="w-full flex items-center justify-center gap-2 bg-primary hover:bg-primary/90 disabled:opacity-50 disabled:hover:bg-primary text-white py-3.5 rounded-xl font-semibold transition-colors mt-2 shadow-[0_0_20px_rgba(108,114,255,0.4)]"
          >
            {isTesting ? (
              <RefreshCw className="w-5 h-5 animate-spin" />
            ) : (
              <>
                {t('conn_setup_btn')} <ChevronRight className="w-5 h-5" />
              </>
            )}
          </button>
        </form>

        {testResult && (
          <div className={`p-4 rounded-xl flex items-start gap-3 border animate-in fade-in slide-in-from-bottom-2 duration-200 ${
            testResult.success 
              ? 'bg-secondary/10 border-secondary/20 text-secondary' 
              : 'bg-red-500/10 border-red-500/20 text-red-400'
          }`}>
            {testResult.success ? (
              <CheckCircle className="w-5 h-5 shrink-0 mt-0.5" />
            ) : (
              <XCircle className="w-5 h-5 shrink-0 mt-0.5" />
            )}
            <div>
              <p className="font-semibold text-sm">{testResult.success ? t('conn_setup_success') : 'Connection Error'}</p>
              <p className="text-xs mt-1 opacity-90 font-mono break-all">{testResult.message}</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
