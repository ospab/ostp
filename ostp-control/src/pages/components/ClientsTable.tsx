
import { Users, Key, Share2, RefreshCw, Edit2, Trash2 } from 'lucide-react';
import { useLanguage } from '../../lib/LanguageContext';
import type { UserStatsSnapshot } from '../../lib/api';

export interface ClientsTableProps {
  users: UserStatsSnapshot[];
  isLoading: boolean;
  formatBytes: (bytes: number) => string;
  handleOpenShare: (user: UserStatsSnapshot) => void;
  handleResetStats: (key: string) => void;
  openEditModal: (user: UserStatsSnapshot) => void;
  handleDeleteClient: (key: string) => void;
}

export function ClientsTable({
  users,
  isLoading,
  formatBytes,
  handleOpenShare,
  handleResetStats,
  openEditModal,
  handleDeleteClient
}: ClientsTableProps) {
  const { t } = useLanguage();

  return (
    <div className="glass-panel rounded-2xl overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-white/5 bg-white/[0.02]">
              <th className="px-6 py-4 font-medium text-text-muted">{t('cl_status')}</th>
              <th className="px-6 py-4 font-medium text-text-muted">{t('cl_name')}</th>
              <th className="px-6 py-4 font-medium text-text-muted">{t('cl_key')}</th>
              <th className="px-6 py-4 font-medium text-text-muted">{t('cl_usage')}</th>
              <th className="px-6 py-4 font-medium text-text-muted">{t('cl_limit')}</th>
              <th className="px-6 py-4 font-medium text-text-muted text-right">{t('cl_actions')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {users.map((user) => (
              <tr key={user.access_key} className="hover:bg-white/[0.02] transition-colors group">
                <td className="px-6 py-4">
                  {user.online ? (
                    <div className="flex items-center gap-2 text-secondary">
                      <span className="w-2 h-2 rounded-full bg-secondary shadow-[0_0_8px_#22D3A5]"></span>
                      <span className="text-sm font-medium">{t('cl_active')}</span>
                    </div>
                  ) : (
                    <div className="flex flex-col gap-1">
                      <div className="flex items-center gap-2 text-text-muted">
                        <span className="w-2 h-2 rounded-full bg-text-muted"></span>
                        <span className="text-sm">{t('cl_offline')}</span>
                      </div>
                      {user.last_seen ? (
                        <div className="text-[10px] text-text-muted/60 pl-4 whitespace-nowrap">
                          {new Date(user.last_seen * 1000).toLocaleString(undefined, { 
                            month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' 
                          })}
                        </div>
                      ) : null}
                    </div>
                  )}
                </td>
                <td className="px-6 py-4 font-medium text-white">
                  {user.name || (
                    <span className="text-text-muted italic">{t('cl_unnamed')}</span>
                  )}
                </td>
                <td className="px-6 py-4">
                  <div className="flex items-center gap-2 text-text-muted font-mono text-sm">
                    <Key className="w-4 h-4 shrink-0 text-primary/70" />
                    <span title={user.access_key}>
                      {user.access_key.length > 20 ? `${user.access_key.substring(0, 16)}...` : user.access_key}
                    </span>
                  </div>
                </td>
                <td className="px-6 py-4">
                  <div className="flex flex-col gap-0.5">
                    <div className="flex items-center gap-2 text-sm text-white">
                      <span className="text-xs text-text-muted w-8">Up:</span>
                      <span className="text-red-400 font-mono">{formatBytes(user.bytes_up || 0)}</span>
                    </div>
                    <div className="flex items-center gap-2 text-sm text-white">
                      <span className="text-xs text-text-muted w-8">Down:</span>
                      <span className="text-secondary font-mono">{formatBytes(user.bytes_down || 0)}</span>
                    </div>
                    <div className="flex items-center gap-2 text-xs text-text-muted mt-0.5">
                      <span>Sessions:</span>
                      <span className="font-mono text-white">{user.connections}</span>
                    </div>
                  </div>
                </td>
                <td className="px-6 py-4">
                  <div className="text-sm font-mono text-text-muted">
                    {user.limit_bytes ? (
                      <span className={(user.bytes_up || 0) + (user.bytes_down || 0) >= user.limit_bytes ? 'text-red-400 font-bold' : 'text-white'}>
                        {formatBytes(user.limit_bytes)}
                      </span>
                    ) : (
                      t('cl_unlimited')
                    )}
                  </div>
                </td>
                <td className="px-6 py-4 text-right">
                  <div className="flex items-center justify-end gap-1 sm:opacity-0 group-hover:opacity-100 transition-opacity">
                    <button 
                      onClick={() => handleOpenShare(user)}
                      className="p-2 hover:bg-white/10 rounded-lg text-text-muted hover:text-white transition-colors"
                      title="Get Share Connection Link"
                    >
                      <Share2 className="w-4 h-4" />
                    </button>
                    <button 
                      onClick={() => handleResetStats(user.access_key)}
                      className="p-2 hover:bg-white/10 rounded-lg text-text-muted hover:text-yellow-400 transition-colors"
                      title="Reset Traffic Counters"
                    >
                      <RefreshCw className="w-4 h-4" />
                    </button>
                    <button 
                      onClick={() => openEditModal(user)}
                      className="p-2 hover:bg-white/10 rounded-lg text-text-muted hover:text-white transition-colors"
                      title="Edit Client Description/Limit"
                    >
                      <Edit2 className="w-4 h-4" />
                    </button>
                    <button 
                      onClick={() => handleDeleteClient(user.access_key)}
                      className="p-2 hover:bg-red-500/20 rounded-lg text-text-muted hover:text-red-400 transition-colors"
                      title="Delete Client"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            
            {users.length === 0 && !isLoading && (
              <tr>
                <td colSpan={6} className="px-6 py-12 text-center text-text-muted">
                  <Users className="w-12 h-12 mx-auto mb-4 opacity-20" />
                  <p>No clients found matching query.</p>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
