
import type { FormEvent } from 'react';
import { X } from 'lucide-react';
import { useLanguage } from '../../lib/LanguageContext';

export interface AddClientModalProps {
  show: boolean;
  onClose: () => void;
  onSubmit: (e: FormEvent) => void;
  clientName: string;
  setClientName: (v: string) => void;
  clientLimit: string;
  setClientLimit: (v: string) => void;
  clientLimitUnit: string;
  setClientLimitUnit: (v: string) => void;
  clientCustomKey: string;
  setClientCustomKey: (v: string) => void;
}

export function AddClientModal({
  show,
  onClose,
  onSubmit,
  clientName,
  setClientName,
  clientLimit,
  setClientLimit,
  clientLimitUnit,
  setClientLimitUnit,
  clientCustomKey,
  setClientCustomKey
}: AddClientModalProps) {
  const { t } = useLanguage();

  if (!show) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="glass-panel w-full max-w-md rounded-2xl p-6 space-y-4 relative animate-in fade-in zoom-in-95 duration-200">
        <button 
          onClick={onClose}
          className="absolute top-4 right-4 p-1 rounded-lg hover:bg-white/10 text-text-muted hover:text-white transition-colors"
        >
          <X className="w-5 h-5" />
        </button>
        <h2 className="text-xl font-bold text-white">{t('cl_add_title')}</h2>
        
        <form onSubmit={onSubmit} className="space-y-4">
          <div className="space-y-1">
            <label className="text-xs font-semibold text-text-muted uppercase">{t('cl_form_name')}</label>
            <input
              type="text"
              className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white placeholder-text-muted focus:outline-none focus:border-primary transition-colors"
              placeholder="e.g. My Phone, Home Laptop"
              value={clientName}
              onChange={(e) => setClientName(e.target.value)}
            />
          </div>

          <div className="space-y-1">
            <label className="text-xs font-semibold text-text-muted uppercase">{t('cl_form_limit')}</label>
            <div className="flex gap-2">
              <input
                type="number"
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white placeholder-text-muted focus:outline-none focus:border-primary transition-colors font-mono"
                placeholder={t('cl_form_limit_sub')}
                value={clientLimit}
                onChange={(e) => setClientLimit(e.target.value)}
              />
              <select
                className="bg-surface-light border border-white/10 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-primary"
                value={clientLimitUnit}
                onChange={(e) => setClientLimitUnit(e.target.value)}
              >
                <option value="MB">MB</option>
                <option value="GB">GB</option>
                <option value="TB">TB</option>
              </select>
            </div>
          </div>

          <div className="space-y-1">
            <label className="text-xs font-semibold text-text-muted uppercase">{t('cl_form_custom')}</label>
            <input
              type="text"
              className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white placeholder-text-muted focus:outline-none focus:border-primary transition-colors font-mono"
              placeholder={t('cl_form_custom_sub')}
              value={clientCustomKey}
              onChange={(e) => setClientCustomKey(e.target.value)}
            />
          </div>

          <button
            type="submit"
            className="w-full bg-primary hover:bg-primary/90 text-white py-2.5 rounded-xl font-medium transition-colors mt-2 shadow-[0_0_15px_rgba(108,114,255,0.3)]"
          >
            {t('cl_add')}
          </button>
        </form>
      </div>
    </div>
  );
}
