import { useState, useEffect } from 'react';
import { History, Trash2, CheckCircle2, XCircle } from 'lucide-react';
import { useLanguage } from '../lib/LanguageContext';
import { getAuditLogs, clearAuditLogs } from '../lib/audit';
import type { AuditLogEntry } from '../lib/audit';

export default function AuditLogs() {
  const { t, language } = useLanguage();
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);

  const loadLogs = () => {
    setLogs(getAuditLogs());
  };

  useEffect(() => {
    loadLogs();
    
    // Listen for log updates
    window.addEventListener('ostp_audit_log_added', loadLogs);
    return () => {
      window.removeEventListener('ostp_audit_log_added', loadLogs);
    };
  }, []);

  const handleClear = () => {
    if (confirm(language === 'ru' ? 'Очистить журнал действий?' : 'Clear audit log history?')) {
      clearAuditLogs();
    }
  };

  return (
    <div className="relative z-10 w-full max-w-5xl mx-auto space-y-6 animate-in fade-in duration-300">
      {/* Page Title */}
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold tracking-tight mb-1 flex items-center gap-3">
            <History className="w-8 h-8 text-primary" /> {t('au_title')}
          </h1>
          <p className="text-text-muted">{t('au_subtitle')}</p>
        </div>
        {logs.length > 0 && (
          <button 
            onClick={handleClear}
            className="flex items-center gap-2 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 px-4 py-2.5 rounded-xl text-sm font-semibold transition-colors"
          >
            <Trash2 className="w-4 h-4" /> {t('au_clear')}
          </button>
        )}
      </div>

      {/* Logs Table */}
      <div className="glass-panel rounded-2xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-white/5 bg-white/[0.02]">
                <th className="px-6 py-4 font-medium text-text-muted w-32">{t('au_time')}</th>
                <th className="px-6 py-4 font-medium text-text-muted">{t('au_event')}</th>
                <th className="px-6 py-4 font-medium text-text-muted w-32 text-right">{t('au_status')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {logs.map((log) => (
                <tr key={log.id} className="hover:bg-white/[0.02] transition-colors font-sans">
                  <td className="px-6 py-4 text-sm text-text-muted font-mono">{log.time}</td>
                  <td className="px-6 py-4 text-sm font-medium text-white">
                    {language === 'ru' ? log.eventRu : log.eventEn}
                  </td>
                  <td className="px-6 py-4 text-right">
                    {log.success ? (
                      <span className="inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-full bg-secondary/15 text-secondary border border-secondary/20">
                        <CheckCircle2 className="w-3.5 h-3.5" /> Success
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-full bg-red-500/15 text-red-400 border border-red-500/20">
                        <XCircle className="w-3.5 h-3.5" /> Failed
                      </span>
                    )}
                  </td>
                </tr>
              ))}

              {logs.length === 0 && (
                <tr>
                  <td colSpan={3} className="px-6 py-16 text-center text-text-muted">
                    <History className="w-12 h-12 mx-auto mb-4 opacity-20" />
                    <p className="text-sm font-medium">{t('au_empty')}</p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
