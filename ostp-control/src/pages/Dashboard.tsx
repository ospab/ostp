import { useState, useEffect } from 'react';
import { Activity, Cpu, ArrowUpRight, ArrowDownRight, Users, Server, ShieldAlert } from 'lucide-react';
import { api } from '../lib/api';
import type { ServerStatus, UserStatsSnapshot } from '../lib/api';
import { useLanguage } from '../lib/LanguageContext';

export default function Dashboard() {
  const { t } = useLanguage();
  
  const [status, setStatus] = useState<ServerStatus | null>(null);
  const [config, setConfig] = useState<any>(null);
  const [users, setUsers] = useState<UserStatsSnapshot[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [apiPing, setApiPing] = useState<number | null>(null);

  const fetchDashboardData = async (showLoading = false) => {
    if (showLoading) setIsLoading(true);
    const startPing = performance.now();
    try {
      // Fetch status, users and server configuration in parallel
      const [statusData, usersData, configData] = await Promise.all([
        api.getServerStatus(),
        api.listUsers(),
        api.getServerConfig().catch(() => null) // Allow failing gracefully if config read fails
      ]);
      
      const endPing = performance.now();
      setApiPing(Math.round(endPing - startPing));
      
      setStatus(statusData);
      setUsers(usersData || []);
      if (configData) setConfig(configData);
      setErrorMsg(null);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to fetch server statistics');
    } finally {
      if (showLoading) setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData(true);
    const interval = setInterval(() => {
      fetchDashboardData(false);
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  // Aggregators
  const totalTxBytes = users.reduce((acc, user) => acc + (user.bytes_up || 0), 0);
  const totalRxBytes = users.reduce((acc, user) => acc + (user.bytes_down || 0), 0);
  const totalTraffic = totalTxBytes + totalRxBytes;
  const totalConnections = users.reduce((acc, user) => acc + (user.connections || 0), 0);
  
  // Real active users check
  const activeUsersCount = users.filter(user => user.online && user.connections > 0).length;
  const totalUsersCount = status?.total_users ?? users.length;
  const avgTrafficPerUser = users.length > 0 ? Math.round(totalTraffic / users.length) : 0;

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="relative z-10 w-full max-w-7xl mx-auto space-y-6 animate-in fade-in duration-300">
      {/* Page Title */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight mb-1 flex items-center gap-3">
          <Activity className="w-8 h-8 text-primary animate-pulse" /> {t('db_title')}
        </h1>
        <p className="text-text-muted">{t('db_subtitle')}</p>
      </div>

      {/* Global Error Banner */}
      {errorMsg && (
        <div className="bg-red-500/10 border border-red-500/20 text-red-400 p-4 rounded-xl flex items-center gap-3">
          <ShieldAlert className="w-5 h-5 shrink-0" />
          <p className="text-sm font-mono">{errorMsg}</p>
        </div>
      )}

      {/* Stats Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard 
          icon={<Users className="text-primary w-6 h-6" />}
          label={t('db_active_users')}
          value={isLoading ? '...' : `${activeUsersCount} / ${totalUsersCount}`}
          subValue={t('db_active_users_sub')}
        />
        <StatCard 
          icon={<Activity className="text-secondary w-6 h-6" />}
          label={t('db_connections')}
          value={isLoading ? '...' : totalConnections.toLocaleString()}
          subValue={t('db_connections_sub')}
        />
        <StatCard 
          icon={<ArrowUpRight className="text-red-400 w-6 h-6" />}
          label={t('db_uploaded')}
          value={isLoading ? '...' : formatBytes(totalTxBytes)}
          subValue={t('db_uploaded_sub')}
        />
        <StatCard 
          icon={<ArrowDownRight className="text-secondary w-6 h-6" />}
          label={t('db_downloaded')}
          value={isLoading ? '...' : formatBytes(totalRxBytes)}
          subValue={t('db_downloaded_sub')}
        />
      </div>

      {/* System Status & Details */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mt-6">
        
        {/* Core Properties Card */}
        <div className="lg:col-span-2 glass-panel rounded-2xl p-6 min-h-[300px] flex flex-col justify-between">
          <div>
            <h2 className="text-xl font-semibold mb-2 flex items-center gap-2">
              <Server className="w-5 h-5 text-primary" /> {t('db_properties')}
            </h2>
            <p className="text-sm text-text-muted mb-6">{t('db_properties_sub')}</p>
          </div>
          
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
            <InfoItem 
              label={t('db_core_version')} 
              value={status?.version ? `v${status.version}` : 'v0.2.30'} 
            />
            <InfoItem 
              label={t('db_listen_addr')} 
              value={config?.listen ? (typeof config.listen === 'string' ? config.listen : config.listen.join(', ')) : 'Offline'} 
            />
            <InfoItem 
              label={t('db_api_bind')} 
              value={config?.api?.enabled ? config.api.bind : 'Disabled'} 
            />
            <InfoItem 
              label={t('db_reality_status')} 
              value={config?.reality?.enabled ? 'Active' : 'Disabled'} 
              highlight={config?.reality?.enabled}
            />
            {config?.reality?.enabled && (
              <InfoItem 
                label={t('db_reality_dest')} 
                value={config.reality.dest} 
              />
            )}
            <InfoItem 
              label={t('db_fallback_status')} 
              value={config?.fallback?.enabled ? `Active` : 'Disabled'} 
              highlight={config?.fallback?.enabled}
            />
            {config?.fallback?.enabled && (
              <InfoItem 
                label={t('db_fallback_target')} 
                value={config.fallback.target} 
              />
            )}
            <InfoItem 
              label={t('db_outbound_proxy')} 
              value={config?.outbound?.enabled ? `${config.outbound.protocol}://${config.outbound.address}:${config.outbound.port}` : 'Direct'} 
            />
            {apiPing !== null && (
              <InfoItem 
                label={t('db_api_latency')} 
                value={`${apiPing} ms`} 
              />
            )}
          </div>
        </div>

        {/* Load & Capacity Utilization Card */}
        <div className="glass-panel rounded-2xl p-6 flex flex-col justify-between">
          <div>
            <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
              <Cpu className="w-5 h-5 text-primary" /> {t('db_load_title')}
            </h2>
          </div>
          <div className="space-y-6">
            <ProgressItem 
              label={t('db_load_users')} 
              percentage={totalUsersCount > 0 ? Math.round((activeUsersCount / totalUsersCount) * 100) : 0} 
              color="bg-primary" 
            />
            <ProgressItem 
              label={t('db_load_connections')} 
              percentage={Math.min(Math.round((totalConnections / 512) * 100), 100)} 
              color="bg-secondary" 
            />
            
            <div className="pt-4 border-t border-white/5 space-y-2 mt-auto">
              <div className="flex justify-between text-xs text-text-muted">
                <span>{t('db_total_traffic')}:</span>
                <span className="font-mono text-white font-medium">{formatBytes(totalTraffic)}</span>
              </div>
              <div className="flex justify-between text-xs text-text-muted">
                <span>{t('db_traffic_per_user')}:</span>
                <span className="font-mono text-white font-medium">{formatBytes(avgTrafficPerUser)}</span>
              </div>
              <div className="flex justify-between text-xs text-text-muted pt-2 border-t border-white/5">
                <span>Core Daemon State:</span>
                <span className="font-mono text-secondary font-bold flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-secondary animate-pulse inline-block"></span>
                  RUNNING
                </span>
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}

function StatCard({ icon, label, value, subValue }: { icon: React.ReactNode, label: string, value: string, subValue: string }) {
  return (
    <div className="glass-panel rounded-2xl p-6 group hover:border-primary/30 transition-colors duration-300">
      <div className="flex items-start justify-between mb-4">
        <div className="p-3 bg-white/5 rounded-xl group-hover:bg-primary/10 transition-colors">{icon}</div>
      </div>
      <div>
        <p className="text-text-muted text-sm font-medium">{label}</p>
        <h3 className="text-3xl font-bold mt-1 font-mono tracking-tight text-white">{value}</h3>
        <p className="text-xs text-text-muted mt-2">{subValue}</p>
      </div>
    </div>
  );
}

function InfoItem({ label, value, highlight }: { label: string; value: string; highlight?: boolean }) {
  return (
    <div className="space-y-1">
      <div className="text-xs text-text-muted font-medium">{label}</div>
      <div className={`font-mono text-sm font-medium break-all ${highlight ? 'text-secondary font-bold' : 'text-white'}`}>
        {value}
      </div>
    </div>
  );
}

function ProgressItem({ label, percentage, color }: { label: string, percentage: number, color: string }) {
  return (
    <div>
      <div className="flex justify-between mb-2">
        <span className="text-sm font-medium text-white">{label}</span>
        <span className="text-sm font-mono text-text-muted">{percentage}%</span>
      </div>
      <div className="h-2 w-full bg-white/5 rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full transition-all duration-1000`} style={{ width: `${percentage}%` }}></div>
      </div>
    </div>
  );
}
