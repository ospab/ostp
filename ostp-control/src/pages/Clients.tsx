import { useState, useEffect, useRef } from 'react';
import { Users, Plus, Key, Trash2, Edit2, Copy, Search, RefreshCw, X, Share2, ShieldAlert, Download } from 'lucide-react';
import QRCode from 'qrcode';
import { api } from '../lib/api';
import type { UserStatsSnapshot } from '../lib/api';
import { useLanguage } from '../lib/LanguageContext';
import { addAuditLog } from '../lib/audit';

export default function Clients() {
  const { t } = useLanguage();

  const [users, setUsers] = useState<UserStatsSnapshot[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  
  // Modals state
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showShareModal, setShowShareModal] = useState(false);
  
  // Form fields
  const [clientName, setClientName] = useState('');
  const [clientLimit, setClientLimit] = useState('');
  const [clientLimitUnit, setClientLimitUnit] = useState('GB');
  const [clientCustomKey, setClientCustomKey] = useState('');
  
  // Editing user state
  const [editingUser, setEditingUser] = useState<UserStatsSnapshot | null>(null);
  const [editName, setEditName] = useState('');
  const [editLimit, setEditLimit] = useState('');
  const [editLimitUnit, setEditLimitUnit] = useState('GB');

  // Sharing user state
  const [sharingUser, setSharingUser] = useState<UserStatsSnapshot | null>(null);
  const [shareLink, setShareLink] = useState('');
  const [isFetchingLink, setIsFetchingLink] = useState(false);
  const qrCanvasRef = useRef<HTMLCanvasElement>(null);

  const fetchUsers = async (showLoading = false) => {
    if (showLoading) setIsLoading(true);
    try {
      const data = await api.listUsers();
      setUsers(data || []);
      setErrorMsg(null);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to fetch clients');
    } finally {
      if (showLoading) setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers(true);
    const interval = setInterval(() => {
      fetchUsers(false);
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleAddClient = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    
    let limitBytes: number | null = null;
    if (clientLimit && !isNaN(Number(clientLimit))) {
      const mult = clientLimitUnit === 'MB' ? 1024 * 1024 : clientLimitUnit === 'GB' ? 1024 * 1024 * 1024 : 1024 * 1024 * 1024 * 1024;
      limitBytes = Number(clientLimit) * mult;
    }

    const nameToCreate = clientName.trim() || null;
    const customKey = clientCustomKey.trim() || undefined;

    try {
      const createdKey = await api.createUser(nameToCreate, limitBytes, customKey);
      setShowAddModal(false);
      setClientName('');
      setClientLimit('');
      setClientCustomKey('');
      fetchUsers(false);
      
      addAuditLog(
        `Created client "${nameToCreate || 'Unnamed'}" with key "${createdKey.substring(0, 8)}..."`,
        `Создан клиент "${nameToCreate || 'Без имени'}" с ключом "${createdKey.substring(0, 8)}..."`,
        true
      );
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to create client');
      addAuditLog(
        `Failed to create client: ${err.message || err}`,
        `Не удалось создать клиента: ${err.message || err}`,
        false
      );
    }
  };

  const handleEditClient = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingUser) return;
    setErrorMsg(null);

    let limitBytes: number | null = null;
    if (editLimit && !isNaN(Number(editLimit))) {
      const mult = editLimitUnit === 'MB' ? 1024 * 1024 : editLimitUnit === 'GB' ? 1024 * 1024 * 1024 : editLimitUnit === 'TB' ? 1024 * 1024 * 1024 * 1024 : 1;
      limitBytes = Number(editLimit) * mult;
    }

    const nameToEdit = editName.trim() || null;

    try {
      await api.updateUser(editingUser.access_key, nameToEdit, limitBytes);
      setShowEditModal(false);
      setEditingUser(null);
      fetchUsers(false);
      
      addAuditLog(
        `Updated client settings for key "${editingUser.access_key.substring(0, 8)}..." (Name: ${nameToEdit || 'None'}, Limit: ${limitBytes ? limitBytes + ' bytes' : 'Unlimited'})`,
        `Обновлен клиент "${editingUser.access_key.substring(0, 8)}..." (Имя: ${nameToEdit || 'Нет'}, Лимит: ${limitBytes ? limitBytes + ' байт' : 'Безлимит'})`,
        true
      );
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to update client');
      addAuditLog(
        `Failed to edit client: ${err.message || err}`,
        `Не удалось изменить настройки клиента: ${err.message || err}`,
        false
      );
    }
  };

  const handleDeleteClient = async (key: string) => {
    if (!confirm(t('cl_confirm_delete'))) return;
    setErrorMsg(null);
    try {
      await api.deleteUser(key);
      fetchUsers(false);
      
      addAuditLog(
        `Deleted client access key "${key.substring(0, 8)}..."`,
        `Удален ключ доступа клиента "${key.substring(0, 8)}..."`,
        true
      );
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to delete client');
      addAuditLog(
        `Failed to delete client "${key.substring(0, 8)}...": ${err.message || err}`,
        `Не удалось удалить клиента "${key.substring(0, 8)}...": ${err.message || err}`,
        false
      );
    }
  };

  const handleResetStats = async (key: string) => {
    if (!confirm(t('cl_confirm_reset'))) return;
    setErrorMsg(null);
    try {
      await api.resetUserStats(key);
      fetchUsers(false);
      
      addAuditLog(
        `Reset traffic counters for key "${key.substring(0, 8)}..."`,
        `Сброшена статистика трафика для ключа "${key.substring(0, 8)}..."`,
        true
      );
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to reset client stats');
      addAuditLog(
        `Failed to reset traffic counters: ${err.message || err}`,
        `Не удалось сбросить счетчики трафика: ${err.message || err}`,
        false
      );
    }
  };

  const handleOpenShare = async (user: UserStatsSnapshot) => {
    setSharingUser(user);
    setShareLink('');
    setIsFetchingLink(true);
    setShowShareModal(true);
    try {
      const link = await api.getSubscriptionLink(user.access_key);
      setShareLink(link);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to fetch subscription share link');
      setShowShareModal(false);
    } finally {
      setIsFetchingLink(false);
    }
  };

  // Render QR code whenever shareLink changes
  useEffect(() => {
    if (shareLink && qrCanvasRef.current) {
      QRCode.toCanvas(qrCanvasRef.current, shareLink, {
        width: 180,
        margin: 1,
        color: {
          dark: '#ffffff',
          light: '#00000000',
        },
      });
    }
  }, [shareLink]);

  const downloadQr = () => {
    const canvas = qrCanvasRef.current;
    if (!canvas) return;
    const link = document.createElement('a');
    link.download = `ostp-${sharingUser?.name || 'client'}.png`;
    link.href = canvas.toDataURL('image/png');
    link.click();
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    alert(t('cl_copied'));
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const parseBytesToInput = (bytes: number | null) => {
    if (!bytes) return { value: '', unit: 'GB' };
    const tb = 1024 * 1024 * 1024 * 1024;
    const gb = 1024 * 1024 * 1024;
    if (bytes >= tb) return { value: (bytes / tb).toString(), unit: 'TB' };
    return { value: (bytes / gb).toString(), unit: 'GB' };
  };

  const openEditModal = (user: UserStatsSnapshot) => {
    setEditingUser(user);
    setEditName(user.name || '');
    const { value, unit } = parseBytesToInput(user.limit_bytes);
    setEditLimit(value);
    setEditLimitUnit(unit);
    setShowEditModal(true);
  };

  const filteredUsers = users.filter(user => {
    const q = searchQuery.toLowerCase();
    const nameMatch = (user.name || '').toLowerCase().includes(q);
    const keyMatch = user.access_key.toLowerCase().includes(q);
    return nameMatch || keyMatch;
  });

  return (
    <div className="relative z-10 w-full max-w-7xl mx-auto space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight mb-1 flex items-center gap-3">
            <Users className="w-8 h-8 text-primary" /> {t('cl_title')}
          </h1>
          <p className="text-text-muted">{t('cl_subtitle')}</p>
        </div>
        <div className="flex gap-2">
          <button 
            onClick={() => fetchUsers(true)}
            className="p-2.5 bg-white/5 hover:bg-white/10 text-white rounded-xl font-medium transition-colors border border-white/10"
            title="Refresh"
          >
            <RefreshCw className={`w-5 h-5 ${isLoading ? 'animate-spin text-primary' : ''}`} />
          </button>
          <button 
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 bg-primary hover:bg-primary/90 text-white px-4 py-2.5 rounded-xl font-medium transition-colors shadow-[0_0_15px_rgba(108,114,255,0.3)]"
          >
            <Plus className="w-5 h-5" />
            {t('cl_add')}
          </button>
        </div>
      </div>

      {/* Global Error Banner */}
      {errorMsg && (
        <div className="bg-red-500/10 border border-red-500/20 text-red-400 p-4 rounded-xl flex items-center gap-3">
          <ShieldAlert className="w-5 h-5 shrink-0" />
          <p className="text-sm font-mono">{errorMsg}</p>
        </div>
      )}

      {/* Search and Quick Filters */}
      <div className="flex items-center bg-white/5 border border-white/10 rounded-2xl px-4 py-3 max-w-md">
        <Search className="w-5 h-5 text-text-muted mr-3" />
        <input
          type="text"
          className="bg-transparent border-none outline-none text-white w-full placeholder-text-muted"
          placeholder={t('cl_search')}
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
        />
      </div>

      {/* Clients Table */}
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
              {filteredUsers.map((user) => (
                <tr key={user.access_key} className="hover:bg-white/[0.02] transition-colors group">
                  <td className="px-6 py-4">
                    {user.online ? (
                      <div className="flex items-center gap-2 text-secondary">
                        <span className="w-2 h-2 rounded-full bg-secondary shadow-[0_0_8px_#22D3A5]"></span>
                        <span className="text-sm font-medium">{t('cl_active')}</span>
                      </div>
                    ) : (
                      <div className="flex items-center gap-2 text-text-muted">
                        <span className="w-2 h-2 rounded-full bg-text-muted"></span>
                        <span className="text-sm">{t('cl_offline')}</span>
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
              
              {filteredUsers.length === 0 && !isLoading && (
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

      {/* Add Client Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="glass-panel w-full max-w-md rounded-2xl p-6 space-y-4 relative animate-in fade-in zoom-in-95 duration-200">
            <button 
              onClick={() => setShowAddModal(false)}
              className="absolute top-4 right-4 p-1 rounded-lg hover:bg-white/10 text-text-muted hover:text-white transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
            <h2 className="text-xl font-bold text-white">{t('cl_add_title')}</h2>
            
            <form onSubmit={handleAddClient} className="space-y-4">
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
      )}

      {/* Edit Client Modal */}
      {showEditModal && editingUser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="glass-panel w-full max-w-md rounded-2xl p-6 space-y-4 relative animate-in fade-in zoom-in-95 duration-200">
            <button 
              onClick={() => {
                setShowEditModal(false);
                setEditingUser(null);
              }}
              className="absolute top-4 right-4 p-1 rounded-lg hover:bg-white/10 text-text-muted hover:text-white transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
            <h2 className="text-xl font-bold text-white">{t('cl_edit_title')}</h2>
            
            <form onSubmit={handleEditClient} className="space-y-4">
              <div className="space-y-1">
                <label className="text-xs font-semibold text-text-muted uppercase">{t('cl_form_name')}</label>
                <input
                  type="text"
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white placeholder-text-muted focus:outline-none focus:border-primary transition-colors"
                  placeholder="e.g. My Phone, Home Laptop"
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-semibold text-text-muted uppercase">{t('cl_form_limit')}</label>
                <div className="flex gap-2">
                  <input
                    type="number"
                    className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white placeholder-text-muted focus:outline-none focus:border-primary transition-colors font-mono"
                    placeholder={t('cl_form_limit_sub')}
                    value={editLimit}
                    onChange={(e) => setEditLimit(e.target.value)}
                  />
                  <select
                    className="bg-surface-light border border-white/10 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-primary"
                    value={editLimitUnit}
                    onChange={(e) => setEditLimitUnit(e.target.value)}
                  >
                    <option value="MB">MB</option>
                    <option value="GB">GB</option>
                    <option value="TB">TB</option>
                  </select>
                </div>
              </div>

              <div className="text-xs text-text-muted font-mono truncate">
                Access Key: {editingUser.access_key}
              </div>

              <button
                type="submit"
                className="w-full bg-primary hover:bg-primary/90 text-white py-2.5 rounded-xl font-medium transition-colors mt-2 shadow-[0_0_15px_rgba(108,114,255,0.3)]"
              >
                {t('cl_form_save')}
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Share Connection Modal */}
      {showShareModal && sharingUser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="glass-panel w-full max-w-lg rounded-2xl relative animate-in fade-in zoom-in-95 duration-200 flex flex-col" style={{ maxHeight: '90vh' }}>
            {/* Sticky header */}
            <div className="flex items-start justify-between p-6 pb-4 shrink-0">
              <div>
                <h2 className="text-xl font-bold text-white">{t('cl_share_title')}</h2>
                <p className="text-sm text-text-muted mt-0.5">{t('cl_share_sub')}</p>
              </div>
              <button 
                onClick={() => {
                  setShowShareModal(false);
                  setSharingUser(null);
                }}
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
      )}
    </div>
  );
}
