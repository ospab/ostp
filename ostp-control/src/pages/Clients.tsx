import { useState, useEffect, useRef } from 'react';
import QRCode from 'qrcode';
import { Users, Plus, Search, RefreshCw, ShieldAlert, Zap } from 'lucide-react';
import { api } from '../lib/api';
import type { UserStatsSnapshot } from '../lib/api';
import { useLanguage } from '../lib/LanguageContext';
import { addAuditLog } from '../lib/audit';
import { AddClientModal } from './components/AddClientModal';
import { EditClientModal } from './components/EditClientModal';
import { ShareClientModal } from './components/ShareClientModal';
import { ClientsTable } from './components/ClientsTable';
import { BulkKeysModal } from './components/BulkKeysModal';

export default function Clients() {
  const { t } = useLanguage();

  const [users, setUsers] = useState<UserStatsSnapshot[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  
  // Modals state
  const [showAddModal, setShowAddModal] = useState(false);
  const [showBulkModal, setShowBulkModal] = useState(false);
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

  const handleBulkGenerate = async (count: number, limitBytes: number | null): Promise<string[]> => {
    try {
      const keys = await api.bulkCreateUsers(count, limitBytes);
      fetchUsers(false);
      addAuditLog(
        `Bulk generated ${count} keys`,
        `Сгенерирован пакет из ${count} ключей`,
        true
      );
      return keys;
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to bulk generate keys');
      addAuditLog(
        `Failed to bulk generate keys: ${err.message || err}`,
        `Не удалось сгенерировать ключи: ${err.message || err}`,
        false
      );
      throw err;
    }
  };

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
            onClick={() => setShowBulkModal(true)}
            className="flex items-center gap-2 bg-secondary hover:bg-secondary/90 text-black px-4 py-2.5 rounded-xl font-medium transition-colors shadow-[0_0_15px_rgba(34,211,165,0.3)]"
          >
            <Zap className="w-5 h-5" />
            <span className="hidden sm:inline">Bulk Gen</span>
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
      <ClientsTable
        users={filteredUsers}
        isLoading={isLoading}
        formatBytes={formatBytes}
        handleOpenShare={handleOpenShare}
        handleResetStats={handleResetStats}
        openEditModal={openEditModal}
        handleDeleteClient={handleDeleteClient}
      />

      {/* Add Client Modal */}
      <AddClientModal
        show={showAddModal}
        onClose={() => setShowAddModal(false)}
        onSubmit={handleAddClient}
        clientName={clientName}
        setClientName={setClientName}
        clientLimit={clientLimit}
        setClientLimit={setClientLimit}
        clientLimitUnit={clientLimitUnit}
        setClientLimitUnit={setClientLimitUnit}
        clientCustomKey={clientCustomKey}
        setClientCustomKey={setClientCustomKey}
      />

      {/* Edit Client Modal */}
      <EditClientModal
        show={showEditModal}
        onClose={() => {
          setShowEditModal(false);
          setEditingUser(null);
        }}
        onSubmit={handleEditClient}
        editingUser={editingUser}
        editName={editName}
        setEditName={setEditName}
        editLimit={editLimit}
        setEditLimit={setEditLimit}
        editLimitUnit={editLimitUnit}
        setEditLimitUnit={setEditLimitUnit}
      />

      {/* Share Connection Modal */}
      {showShareModal && sharingUser && (
        <ShareClientModal
          user={sharingUser}
          shareLink={shareLink}
          isFetchingLink={isFetchingLink}
          qrCanvasRef={qrCanvasRef}
          onClose={() => setShowShareModal(false)}
          downloadQr={downloadQr}
          copyToClipboard={copyToClipboard}
        />
      )}

      {showBulkModal && (
        <BulkKeysModal
          onClose={() => setShowBulkModal(false)}
          onGenerate={handleBulkGenerate}
        />
      )}
    </div>
  );
}
