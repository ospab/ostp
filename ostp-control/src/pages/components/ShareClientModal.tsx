import type { RefObject } from 'react';
import { X, RefreshCw, Copy, Download } from 'lucide-react';
import { useLanguage } from '../../lib/LanguageContext';
import type { UserStatsSnapshot } from '../../lib/api';

export interface ShareClientModalProps {
  show: boolean;
  onClose: () => void;
  sharingUser: UserStatsSnapshot | null;
  shareLink: string;
  isFetchingLink: boolean;
  qrCanvasRef: RefObject<HTMLCanvasElement | null>;
  copyToClipboard: (text: string) => void;
  downloadQr: () => void;
}

export function ShareClientModal({
  show,
  onClose,
  sharingUser,
  shareLink,
  isFetchingLink,
  qrCanvasRef,
  copyToClipboard,
  downloadQr
}: ShareClientModalProps) {
  const { t } = useLanguage();

  if (!show || !sharingUser) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="glass-panel w-full max-w-lg rounded-2xl relative animate-in fade-in zoom-in-95 duration-200 flex flex-col" style={{ maxHeight: '90vh' }}>
        {/* Sticky header */}
        <div className="flex items-start justify-between p-6 pb-4 shrink-0">
          <div>
            <h2 className="text-xl font-bold text-white">{t('cl_share_title')}</h2>
            <p className="text-sm text-text-muted mt-0.5">{t('cl_share_sub')}</p>
          </div>
          <button 
            onClick={onClose}
            className="ml-4 shrink-0 p-1.5 rounded-lg hover:bg-white/10 text-text-muted hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable body */}
        <div className="overflow-y-auto px-6 pb-6 space-y-4">
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-text-muted uppercase">{t('cl_name')}</label>
            <div className="text-white font-medium">{sharingUser.name || t('cl_unnamed')}</div>
          </div>

          <div className="space-y-2">
            <label className="text-xs font-semibold text-text-muted uppercase">{t('cl_share_link')}</label>
            {isFetchingLink ? (
              <div className="bg-white/5 border border-white/10 rounded-xl p-4 flex items-center justify-center">
                <RefreshCw className="w-6 h-6 animate-spin text-primary mr-2" />
                <span className="text-sm text-text-muted">Generating link...</span>
              </div>
            ) : (
              <div className="flex gap-2">
                <input
                  type="text"
                  readOnly
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white font-mono text-xs select-all focus:outline-none"
                  value={shareLink}
                />
                <button
                  onClick={() => copyToClipboard(shareLink)}
                  className="p-2.5 bg-primary hover:bg-primary/90 text-white rounded-xl transition-colors shrink-0"
                  title="Copy Link"
                >
                  <Copy className="w-5 h-5" />
                </button>
              </div>
            )}
          </div>

          {/* QR Code — compact, side layout */}
          {!isFetchingLink && shareLink && (
            <div className="flex items-center gap-4 p-3 rounded-xl border border-white/10" style={{ background: 'linear-gradient(135deg, rgba(108,114,255,0.10) 0%, rgba(34,211,165,0.07) 100%)' }}>
              <div className="shrink-0" style={{ background: 'rgba(0,0,0,0.3)', borderRadius: '0.5rem', padding: '8px' }}>
                <canvas ref={qrCanvasRef} style={{ display: 'block', borderRadius: '4px' }} />
              </div>
              <div className="flex flex-col gap-2 min-w-0">
                <p className="text-xs text-text-muted leading-snug">{t('cl_share_scan')}</p>
                <button
                  onClick={downloadQr}
                  className="flex items-center gap-2 px-3 py-1.5 bg-white/5 hover:bg-white/10 border border-white/10 text-white text-xs rounded-lg transition-colors w-fit"
                >
                  <Download className="w-3.5 h-3.5" />
                  {t('cl_share_download_qr')}
                </button>
              </div>
            </div>
          )}

        </div>
      </div>
    </div>
  );
}
