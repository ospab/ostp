import { useState, useEffect } from 'react';
import { Globe, Plus, Trash2, Save, RefreshCw, AlertCircle, CheckCircle, XCircle } from 'lucide-react';
import { api } from '../lib/api';
import type { DnsConfig, DnsQueryLog } from '../lib/api';
import { useLanguage } from '../lib/LanguageContext';

export default function Dns() {
  const { t } = useLanguage();
  
  const [config, setConfig] = useState<DnsConfig | null>(null);
  const [queries, setQueries] = useState<DnsQueryLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Forms state
  const [newDomain, setNewDomain] = useState('');
  const [newIp, setNewIp] = useState('');
  const [newUrl, setNewUrl] = useState('');

  const fetchConfig = async () => {
    try {
      const data = await api.getDnsConfig();
      setConfig(data);
    } catch (err: any) {
      setError(err.message);
    }
  };

  const fetchQueries = async () => {
    try {
      const data = await api.getDnsQueries();
      setQueries(data.reverse()); // Show newest first
    } catch (err: any) {
      console.error('Failed to load DNS queries', err);
    }
  };

  const loadData = async () => {
    setLoading(true);
    await fetchConfig();
    await fetchQueries();
    setLoading(false);
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(fetchQueries, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleSave = async () => {
    if (!config) return;
    setSaving(true);
    setError(null);
    try {
      await api.updateDnsConfig(config);
      // Wait a moment for backend to potentially fetch blocklists
      setTimeout(loadData, 1000);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  };

  const handleRefreshBlocklists = async () => {
    setRefreshing(true);
    try {
      await api.refreshDnsBlocklists();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setRefreshing(false);
    }
  };

  const addCustomDomain = () => {
    if (!newDomain || !newIp || !config) return;
    setConfig({
      ...config,
      custom_domains: {
        ...config.custom_domains,
        [newDomain.toLowerCase()]: newIp
      }
    });
    setNewDomain('');
    setNewIp('');
  };

  const removeCustomDomain = (domain: string) => {
    if (!config) return;
    const newDomains = { ...config.custom_domains };
    delete newDomains[domain];
    setConfig({ ...config, custom_domains: newDomains });
  };

  const addAdblockUrl = () => {
    if (!newUrl || !config) return;
    setConfig({
      ...config,
      adblock_urls: [...config.adblock_urls, newUrl]
    });
    setNewUrl('');
  };

  const removeAdblockUrl = (index: number) => {
    if (!config) return;
    const newUrls = [...config.adblock_urls];
    newUrls.splice(index, 1);
    setConfig({ ...config, adblock_urls: newUrls });
  };

  if (loading && !config) {
    return (
      <div className="flex h-full items-center justify-center">
        <RefreshCw className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <div className="flex items-center gap-3 mb-8">
        <div className="p-3 bg-primary/10 rounded-xl">
          <Globe className="w-8 h-8 text-primary" />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-white tracking-tight">{t('dns_title')}</h1>
          <p className="text-text-muted mt-1">{t('dns_subtitle')}</p>
        </div>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/20 text-red-400 p-4 rounded-xl flex items-center gap-3">
          <AlertCircle className="w-5 h-5 flex-shrink-0" />
          <p>{error}</p>
        </div>
      )}

      {config && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Main Settings Panel */}
          <div className="space-y-6">
            <div className="glass p-6 rounded-2xl border border-white/5 space-y-6">
              <label className="flex items-center justify-between p-4 bg-surface rounded-xl border border-white/5 cursor-pointer hover:bg-white/5 transition-colors">
                <div className="space-y-1">
                  <div className="text-white font-medium">{t('dns_enable')}</div>
                </div>
                <div className="relative">
                  <input
                    type="checkbox"
                    className="sr-only"
                    checked={config.enabled}
                    onChange={(e) => setConfig({ ...config, enabled: e.target.checked })}
                  />
                  <div className={`block w-14 h-8 rounded-full transition-colors ${config.enabled ? 'bg-primary' : 'bg-surface-light border border-white/10'}`}></div>
                  <div className={`dot absolute left-1 top-1 bg-white w-6 h-6 rounded-full transition-transform ${config.enabled ? 'transform translate-x-6' : ''}`}></div>
                </div>
              </label>

              <div className="space-y-2">
                <label className="block text-sm font-medium text-text-muted">{t('dns_upstream')}</label>
                <input
                  type="text"
                  value={config.doh_upstream}
                  onChange={(e) => setConfig({ ...config, doh_upstream: e.target.value })}
                  className="w-full bg-surface border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all"
                  placeholder="https://cloudflare-dns.com/dns-query"
                />
                <p className="text-xs text-text-muted mt-1">{t('dns_upstream_sub')}</p>
              </div>

              <div className="pt-4 border-t border-white/5 flex gap-3">
                <button
                  onClick={handleSave}
                  disabled={saving}
                  className="flex-1 flex items-center justify-center gap-2 bg-primary hover:bg-primary-hover text-background font-bold py-3 px-4 rounded-xl transition-all shadow-[0_0_20px_rgba(34,211,165,0.2)] disabled:opacity-50"
                >
                  {saving ? <RefreshCw className="w-5 h-5 animate-spin" /> : <Save className="w-5 h-5" />}
                  {t('dns_save')}
                </button>
              </div>
            </div>

            {/* Custom Domains */}
            <div className="glass p-6 rounded-2xl border border-white/5 space-y-4">
              <h3 className="text-lg font-bold text-white">{t('dns_custom_domains')}</h3>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={newDomain}
                  onChange={(e) => setNewDomain(e.target.value)}
                  placeholder="example.local"
                  className="flex-1 bg-surface border border-white/10 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-primary"
                  onKeyDown={(e) => e.key === 'Enter' && addCustomDomain()}
                />
                <input
                  type="text"
                  value={newIp}
                  onChange={(e) => setNewIp(e.target.value)}
                  placeholder="192.168.1.10"
                  className="flex-1 bg-surface border border-white/10 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-primary"
                  onKeyDown={(e) => e.key === 'Enter' && addCustomDomain()}
                />
                <button onClick={addCustomDomain} className="bg-primary/20 hover:bg-primary/30 text-primary p-2 rounded-lg transition-colors">
                  <Plus className="w-5 h-5" />
                </button>
              </div>
              <div className="space-y-2 mt-4 max-h-48 overflow-y-auto pr-2">
                {Object.entries(config.custom_domains).map(([domain, ip]) => (
                  <div key={domain} className="flex items-center justify-between bg-surface p-3 rounded-lg border border-white/5">
                    <div>
                      <div className="text-white font-medium text-sm">{domain}</div>
                      <div className="text-text-muted text-xs font-mono mt-0.5">{ip}</div>
                    </div>
                    <button onClick={() => removeCustomDomain(domain)} className="text-red-400 hover:text-red-300 p-1">
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                ))}
                {Object.keys(config.custom_domains).length === 0 && (
                  <div className="text-center text-text-muted text-sm py-4">Нет записей</div>
                )}
              </div>
            </div>
          </div>

          {/* AdBlock Lists & Queries */}
          <div className="space-y-6">
            <div className="glass p-6 rounded-2xl border border-white/5 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-bold text-white">{t('dns_adblock_lists')}</h3>
                <button
                  onClick={handleRefreshBlocklists}
                  disabled={refreshing}
                  className="text-xs flex items-center gap-1.5 bg-white/5 hover:bg-white/10 text-white py-1.5 px-3 rounded-lg transition-colors"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
                  {t('dns_refresh')}
                </button>
              </div>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={newUrl}
                  onChange={(e) => setNewUrl(e.target.value)}
                  placeholder="https://..."
                  className="flex-1 bg-surface border border-white/10 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-primary"
                  onKeyDown={(e) => e.key === 'Enter' && addAdblockUrl()}
                />
                <button onClick={addAdblockUrl} className="bg-primary/20 hover:bg-primary/30 text-primary p-2 rounded-lg transition-colors">
                  <Plus className="w-5 h-5" />
                </button>
              </div>
              <div className="space-y-2 mt-4 max-h-48 overflow-y-auto pr-2">
                {config.adblock_urls.map((url, i) => (
                  <div key={i} className="flex items-center justify-between bg-surface p-3 rounded-lg border border-white/5">
                    <div className="text-white text-sm truncate pr-4" title={url}>{url}</div>
                    <button onClick={() => removeAdblockUrl(i)} className="text-red-400 hover:text-red-300 p-1 flex-shrink-0">
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                ))}
                {config.adblock_urls.length === 0 && (
                  <div className="text-center text-text-muted text-sm py-4">Нет списков</div>
                )}
              </div>
            </div>

            <div className="glass p-6 rounded-2xl border border-white/5 flex flex-col h-[400px]">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-bold text-white">{t('dns_query_log')}</h3>
                <div className="flex gap-3 text-xs text-text-muted">
                  <div className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-primary"></span> {t('dns_q_allowed')}</div>
                  <div className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-500"></span> {t('dns_q_blocked')}</div>
                </div>
              </div>
              <div className="flex-1 overflow-auto -mx-4 px-4">
                <table className="w-full text-left text-sm whitespace-nowrap">
                  <thead className="text-text-muted sticky top-0 bg-[#0f111a] z-10">
                    <tr>
                      <th className="pb-3 font-medium px-2">{t('dns_q_time')}</th>
                      <th className="pb-3 font-medium px-2">{t('dns_q_domain')}</th>
                      <th className="pb-3 font-medium px-2">{t('dns_q_client')}</th>
                      <th className="pb-3 font-medium px-2 w-10"></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {queries.map((q, i) => (
                      <tr key={i} className="hover:bg-white/5 transition-colors">
                        <td className="py-2.5 px-2 text-text-muted">
                          {new Date(q.timestamp * 1000).toLocaleTimeString()}
                        </td>
                        <td className="py-2.5 px-2 text-white max-w-[150px] truncate" title={q.domain}>
                          {q.domain}
                        </td>
                        <td className="py-2.5 px-2 text-text-muted font-mono text-xs">
                          {q.client_ip}
                        </td>
                        <td className="py-2.5 px-2 text-right">
                          {q.blocked ? (
                            <XCircle className="w-4 h-4 text-red-500 inline" />
                          ) : (
                            <CheckCircle className="w-4 h-4 text-primary/50 inline" />
                          )}
                        </td>
                      </tr>
                    ))}
                    {queries.length === 0 && (
                      <tr>
                        <td colSpan={4} className="py-8 text-center text-text-muted">
                          Журнал пуст
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
