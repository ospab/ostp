import { useState, useRef } from 'react';
import { Wrench, Key, Download, Upload, RefreshCw, CheckCircle, XCircle, AlertTriangle, ShieldAlert, Copy } from 'lucide-react';
import { useLanguage } from '../lib/LanguageContext';
import { api, getApiSettings } from '../lib/api';
import { addAuditLog } from '../lib/audit';

export default function Tools() {
  const { t, language } = useLanguage();
  
  // Keygen State
  const [keys, setKeys] = useState<{ publicKey: string; privateKey: string; sid: string; isFallback?: boolean } | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [isCopied, setIsCopied] = useState(false);

  // Backup State
  const [isExporting, setIsExporting] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  const [importResult, setImportResult] = useState<{ success: boolean; message: string } | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Diagnostics State
  const [pingLatency, setPingLatency] = useState<number | null>(null);
  const [isPinging, setIsPinging] = useState(false);
  const [pingResult, setPingResult] = useState<{ success: boolean; message: string } | null>(null);

  // Reality X25519 Key Generator using Web Crypto
  const handleGenerateKeys = async () => {
    setIsGenerating(true);
    setKeys(null);
    setIsCopied(false);
    
    // Simulate slight lag for UI satisfaction
    await new Promise(resolve => setTimeout(resolve, 600));

    try {
      // Try using modern browser Web Crypto for X25519
      const keypair = await window.crypto.subtle.generateKey(
        { name: 'X25519' },
        true,
        ['deriveBits']
      );
      
      const pubBuffer = await window.crypto.subtle.exportKey('raw', keypair.publicKey);
      const priPkcs8 = await window.crypto.subtle.exportKey('pkcs8', keypair.privateKey);
      
      // Raw private key bytes are at the end of PKCS#8 ASN.1 wrapper for X25519 (last 32 bytes)
      const priBuffer = priPkcs8.slice(priPkcs8.byteLength - 32);
      
      const toBase64 = (buf: ArrayBuffer) => {
        const bytes = new Uint8Array(buf);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary)
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/, ''); // URL-safe base64 unpadded
      };
      
      const pubKey = toBase64(pubBuffer);
      const priKey = toBase64(priBuffer);
      
      // Generate random 8-byte (16-char hex) SID
      const sidBytes = new Uint8Array(8);
      window.crypto.getRandomValues(sidBytes);
      const sid = Array.from(sidBytes).map(b => b.toString(16).padStart(2, '0')).join('');
      
      setKeys({ publicKey: pubKey, privateKey: priKey, sid });
      addAuditLog(
        'Generated Reality X25519 keypair in browser',
        'Сгенерирована пара ключей Reality X25519 в браузере',
        true
      );
    } catch (err: any) {
      console.warn("Web Crypto X25519 unsupported, using pseudo-random fallback keys", err);
      
      // Fallback pseudo-random base64 keys
      const randomBase64 = (len: number) => {
        const bytes = new Uint8Array(len);
        window.crypto.getRandomValues(bytes);
        let binary = '';
        for (let i = 0; i < len; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary)
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/, '');
      };

      const sidBytes = new Uint8Array(8);
      window.crypto.getRandomValues(sidBytes);
      const sid = Array.from(sidBytes).map(b => b.toString(16).padStart(2, '0')).join('');
      
      setKeys({
        publicKey: randomBase64(32),
        privateKey: randomBase64(32),
        sid,
        isFallback: true
      });
      addAuditLog(
        'Generated fallback Reality keypair (pseudo-random)',
        'Сгенерированы резервные ключи Reality (псевдослучайные)',
        true
      );
    } finally {
      setIsGenerating(false);
    }
  };

  const handleCopyKeys = () => {
    if (!keys) return;
    const text = `private_key: ${keys.privateKey}\npbk: ${keys.publicKey}\nsid: ${keys.sid}`;
    navigator.clipboard.writeText(text);
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2000);
  };

  // Export config.json
  const handleExportConfig = async () => {
    setIsExporting(true);
    try {
      const configData = await api.getServerConfig();
      const jsonString = `data:text/json;charset=utf-8,${encodeURIComponent(JSON.stringify(configData, null, 2))}`;
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute('href', jsonString);
      downloadAnchor.setAttribute('download', 'ostp_config_backup.json');
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
      
      addAuditLog('Exported server configuration backup', 'Экспортирована резервная копия конфигурации сервера', true);
    } catch (err: any) {
      alert(`Export failed: ${err.message || err}`);
      addAuditLog('Failed to export configuration backup', 'Ошибка экспорта резервной копии конфигурации', false);
    } finally {
      setIsExporting(false);
    }
  };

  // Import config.json
  const handleImportFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsImporting(true);
    setImportResult(null);
    
    const reader = new FileReader();
    reader.onload = async (event) => {
      try {
        const text = event.target?.result as string;
        const parsedConfig = JSON.parse(text);
        
        if (parsedConfig.mode !== 'server') {
          throw new Error(language === 'ru' ? 'Файл не является валидной серверной конфигурацией OSTP' : 'File is not a valid OSTP server configuration');
        }

        await api.updateServerConfig(parsedConfig);
        setImportResult({
          success: true,
          message: t('tl_backup_import_success')
        });
        addAuditLog('Restored server configuration from backup file', 'Конфигурация сервера успешно восстановлена из бэкапа', true);
      } catch (err: any) {
        setImportResult({
          success: false,
          message: `${t('tl_backup_import_error')} ${err.message || err}`
        });
        addAuditLog('Failed to restore server configuration from backup file', 'Не удалось восстановить конфигурацию из файла бэкапа', false);
      } finally {
        setIsImporting(false);
        if (fileInputRef.current) fileInputRef.current.value = '';
      }
    };
    reader.readAsText(file);
  };

  // Diagnostics: latency test (ping)
  const handlePingTest = async () => {
    setIsPinging(true);
    setPingResult(null);
    setPingLatency(null);

    const startTime = performance.now();
    try {
      await api.getServerStatus();
      const endTime = performance.now();
      const latency = Math.round(endTime - startTime);
      setPingLatency(latency);
      setPingResult({
        success: true,
        message: language === 'ru' ? `Успешный ответ. Задержка сети: ${latency} мс` : `Successful response. Network latency: ${latency} ms`
      });
    } catch (err: any) {
      setPingResult({
        success: false,
        message: language === 'ru' ? `Хост недоступен или не отвечает: ${err.message || err}` : `Host unreachable or error response: ${err.message || err}`
      });
    } finally {
      setIsPinging(false);
    }
  };

  return (
    <div className="relative z-10 w-full max-w-6xl mx-auto space-y-6 animate-in fade-in duration-300">
      {/* Title */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight mb-1 flex items-center gap-3">
          <Wrench className="w-8 h-8 text-primary" /> {t('tl_title')}
        </h1>
        <p className="text-text-muted">{t('tl_subtitle')}</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Reality Keypair Generator */}
        <div className="glass-panel rounded-2xl p-6 space-y-4 flex flex-col justify-between">
          <div>
            <h2 className="text-xl font-semibold mb-2 flex items-center gap-2">
              <Key className="w-5 h-5 text-primary" /> {t('tl_keygen_title')}
            </h2>
            <p className="text-sm text-text-muted leading-relaxed mb-4">
              {t('tl_keygen_desc')}
            </p>
            
            {keys && (
              <div className="space-y-3 bg-black/30 border border-white/5 p-4 rounded-xl font-mono text-xs">
                {keys.isFallback && (
                  <div className="flex items-start gap-2 text-yellow-400 bg-yellow-500/10 p-2.5 rounded-lg mb-2">
                    <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                    <span>
                      {language === 'ru' 
                        ? 'Браузер не поддерживает криптографию Curve25519 (X25519). Ключи сгенерированы в тестовом режиме. Рекомендуется использовать CLI ядра: ostp --generate-key.' 
                        : 'Web Crypto API does not support Curve25519 (X25519) in this browser. Generated pseudo-random keys. For production, run: ostp --generate-key.'}
                    </span>
                  </div>
                )}
                <div>
                  <span className="text-text-muted">private_key: </span>
                  <span className="text-secondary select-all">{keys.privateKey}</span>
                </div>
                <div>
                  <span className="text-text-muted">pbk (public_key): </span>
                  <span className="text-primary select-all">{keys.publicKey}</span>
                </div>
                <div>
                  <span className="text-text-muted">sid (session ID): </span>
                  <span className="text-white select-all">{keys.sid}</span>
                </div>
              </div>
            )}
          </div>

          <div className="flex gap-3 pt-4 border-t border-white/5">
            <button
              onClick={handleGenerateKeys}
              disabled={isGenerating}
              className="flex items-center gap-2 bg-primary hover:bg-primary/90 text-white px-5 py-2.5 rounded-xl font-semibold transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${isGenerating ? 'animate-spin' : ''}`} /> {t('tl_keygen_btn')}
            </button>
            {keys && (
              <button
                onClick={handleCopyKeys}
                className="flex items-center gap-2 bg-white/5 hover:bg-white/10 text-white px-5 py-2.5 rounded-xl border border-white/10 text-sm transition-colors"
              >
                <Copy className="w-4 h-4" /> {isCopied ? t('cl_copied') : t('tl_keygen_copy')}
              </button>
            )}
          </div>
        </div>

        {/* Backup & Restore Configuration */}
        <div className="glass-panel rounded-2xl p-6 space-y-4 flex flex-col justify-between">
          <div>
            <h2 className="text-xl font-semibold mb-2 flex items-center gap-2">
              <Download className="w-5 h-5 text-secondary" /> {t('tl_backup_title')}
            </h2>
            <p className="text-sm text-text-muted leading-relaxed mb-4">
              {t('tl_backup_desc')}
            </p>

            {importResult && (
              <div className={`p-4 rounded-xl flex items-start gap-2.5 border ${
                importResult.success ? 'bg-secondary/10 border-secondary/20 text-secondary' : 'bg-red-500/10 border-red-500/20 text-red-400'
              }`}>
                {importResult.success ? <CheckCircle className="w-5 h-5 shrink-0 mt-0.5" /> : <XCircle className="w-5 h-5 shrink-0 mt-0.5" />}
                <p className="text-xs font-mono">{importResult.message}</p>
              </div>
            )}
          </div>

          <div className="space-y-4 pt-4 border-t border-white/5">
            <button
              onClick={handleExportConfig}
              disabled={isExporting}
              className="w-full flex items-center justify-center gap-2 bg-white/5 hover:bg-white/10 text-white border border-white/10 py-3 rounded-xl font-semibold transition-colors"
            >
              <Download className="w-5 h-5" /> {t('tl_backup_export')}
            </button>

            <div 
              onClick={() => fileInputRef.current?.click()}
              className="border-2 border-dashed border-white/10 hover:border-primary/50 bg-white/[0.01] hover:bg-white/[0.03] rounded-xl p-4 text-center cursor-pointer transition-all"
            >
              <Upload className="w-6 h-6 mx-auto mb-2 text-text-muted" />
              <span className="text-xs text-text-muted font-medium">{t('tl_backup_import_zone')}</span>
              <input 
                type="file" 
                ref={fileInputRef} 
                className="hidden" 
                accept=".json"
                onChange={handleImportFileChange}
                disabled={isImporting}
              />
            </div>
          </div>
        </div>

        {/* API Connection Diagnostics */}
        <div className="glass-panel rounded-2xl p-6 lg:col-span-2 space-y-4">
          <h2 className="text-xl font-semibold mb-2 flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-blue-400" /> {t('tl_diag_title')}
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 items-center">
            <div className="space-y-2 bg-black/20 p-4 rounded-xl border border-white/5 text-sm font-mono">
              <div>
                <span className="text-text-muted">API Connection: </span>
                <span className="text-white">{getApiSettings().url}</span>
              </div>
              <div>
                <span className="text-text-muted">Auth Status: </span>
                <span className={getApiSettings().token ? 'text-secondary' : 'text-yellow-400'}>
                  {getApiSettings().token ? 'Authorized Token (Active)' : 'No Token Configuration'}
                </span>
              </div>
              {pingLatency !== null && (
                <div>
                  <span className="text-text-muted">Ping RTT: </span>
                  <span className="text-secondary font-bold">{pingLatency} ms</span>
                </div>
              )}
            </div>

            <div className="space-y-3">
              <button
                onClick={handlePingTest}
                disabled={isPinging}
                className="w-full flex items-center justify-center gap-2 bg-white/5 hover:bg-white/10 text-white border border-white/10 py-3 rounded-xl font-semibold transition-colors"
              >
                <RefreshCw className={`w-4 h-4 ${isPinging ? 'animate-spin' : ''}`} /> {t('tl_diag_ping')}
              </button>

              {pingResult && (
                <div className={`p-4 rounded-xl flex items-start gap-2.5 border ${
                  pingResult.success ? 'bg-secondary/10 border-secondary/20 text-secondary' : 'bg-red-500/10 border-red-500/20 text-red-400'
                }`}>
                  {pingResult.success ? <CheckCircle className="w-5 h-5 shrink-0 mt-0.5" /> : <XCircle className="w-5 h-5 shrink-0 mt-0.5" />}
                  <p className="text-xs font-mono">{pingResult.message}</p>
                </div>
              )}
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
