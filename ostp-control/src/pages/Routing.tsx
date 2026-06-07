import { useState, useEffect } from 'react';
import { Route, Plus, Trash2, Save, Activity, ShieldAlert, ShieldCheck, HelpCircle } from 'lucide-react';
import { api } from '../lib/api';
import type { OutboundRule, OutboundAction } from '../lib/api';
import { addAuditLog } from '../lib/audit';

export default function Routing() {
  const [rules, setRules] = useState<OutboundRule[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const fetchRules = async () => {
    setIsLoading(true);
    try {
      const data = await api.getRouterRules();
      setRules(data || []);
      setErrorMsg(null);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to fetch routing rules');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleSave = async () => {
    setIsSaving(true);
    setErrorMsg(null);
    setSuccessMsg(null);
    try {
      await api.updateRouterRules(rules);
      setSuccessMsg('Routing rules saved successfully');
      addAuditLog('Updated outbound routing rules', 'Обновлены правила маршрутизации исходящего трафика', true);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to save rules');
      addAuditLog(`Failed to update rules: ${err.message || err}`, `Не удалось обновить правила: ${err.message || err}`, false);
    } finally {
      setIsSaving(false);
    }
  };

  const addRule = () => {
    setRules([...rules, { action: 'proxy', domain_suffix: [], ip_cidr: [] }]);
  };

  const removeRule = (index: number) => {
    const newRules = [...rules];
    newRules.splice(index, 1);
    setRules(newRules);
  };

  const updateRuleAction = (index: number, action: OutboundAction) => {
    const newRules = [...rules];
    newRules[index].action = action;
    setRules(newRules);
  };

  const updateRuleDomains = (index: number, domainsStr: string) => {
    const newRules = [...rules];
    newRules[index].domain_suffix = domainsStr.split(',').map(d => d.trim()).filter(Boolean);
    setRules(newRules);
  };

  const updateRuleIps = (index: number, ipsStr: string) => {
    const newRules = [...rules];
    newRules[index].ip_cidr = ipsStr.split(',').map(i => i.trim()).filter(Boolean);
    setRules(newRules);
  };

  return (
    <div className="relative z-10 w-full max-w-5xl mx-auto space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight mb-1 flex items-center gap-3">
            <Route className="w-8 h-8 text-primary" /> Outbound Routing
          </h1>
          <p className="text-text-muted">Manage how outbound traffic is routed for connected clients.</p>
        </div>
        <div className="flex gap-2">
          <button 
            onClick={addRule}
            className="flex items-center gap-2 bg-white/10 hover:bg-white/20 text-white px-4 py-2.5 rounded-xl font-medium transition-colors border border-white/5"
          >
            <Plus className="w-5 h-5" />
            Add Rule
          </button>
          <button 
            onClick={handleSave}
            disabled={isSaving || isLoading}
            className="flex items-center gap-2 bg-primary hover:bg-primary/90 text-white px-6 py-2.5 rounded-xl font-medium transition-colors shadow-[0_0_15px_rgba(108,114,255,0.3)] disabled:opacity-50"
          >
            {isSaving ? <Activity className="w-5 h-5 animate-spin" /> : <Save className="w-5 h-5" />}
            Save Changes
          </button>
        </div>
      </div>

      {errorMsg && (
        <div className="bg-red-500/10 border border-red-500/20 text-red-400 p-4 rounded-xl flex items-center gap-3 animate-in fade-in duration-300">
          <ShieldAlert className="w-5 h-5 shrink-0" />
          <p>{errorMsg}</p>
        </div>
      )}

      {successMsg && (
        <div className="bg-secondary/10 border border-secondary/20 text-secondary p-4 rounded-xl flex items-center gap-3 animate-in fade-in duration-300">
          <ShieldCheck className="w-5 h-5 shrink-0" />
          <p>{successMsg}</p>
        </div>
      )}

      <div className="glass-panel p-6 rounded-2xl">
        <div className="flex items-center gap-2 mb-6 text-text-muted text-sm">
          <HelpCircle className="w-4 h-4 text-primary" />
          <p>Rules are evaluated from top to bottom. The first matching rule determines the action.</p>
        </div>

        {isLoading ? (
          <div className="py-12 flex justify-center">
            <Activity className="w-8 h-8 text-primary animate-spin" />
          </div>
        ) : rules.length === 0 ? (
          <div className="text-center py-12 text-text-muted border border-dashed border-white/10 rounded-xl">
            <Route className="w-12 h-12 mx-auto mb-4 opacity-20" />
            <p>No routing rules defined. All traffic follows the default action.</p>
            <button onClick={addRule} className="mt-4 text-primary hover:text-primary/80 transition-colors">Create your first rule</button>
          </div>
        ) : (
          <div className="space-y-4">
            {rules.map((rule, index) => (
              <div key={index} className="bg-black/20 border border-white/5 rounded-xl p-4 flex flex-col sm:flex-row gap-4 items-start sm:items-center">
                
                <div className="flex items-center justify-center bg-white/5 rounded-lg w-8 h-8 text-text-muted font-mono shrink-0">
                  {index + 1}
                </div>

                <div className="flex-1 grid grid-cols-1 sm:grid-cols-2 gap-4 w-full">
                  <div>
                    <label className="block text-xs font-medium text-text-muted mb-1">Domain Suffixes (comma separated)</label>
                    <input
                      type="text"
                      value={rule.domain_suffix?.join(', ') || ''}
                      onChange={e => updateRuleDomains(index, e.target.value)}
                      placeholder="e.g. google.com, netflix.com"
                      className="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-primary/50 transition-colors"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-text-muted mb-1">IP CIDRs (comma separated)</label>
                    <input
                      type="text"
                      value={rule.ip_cidr?.join(', ') || ''}
                      onChange={e => updateRuleIps(index, e.target.value)}
                      placeholder="e.g. 192.168.1.0/24, 10.0.0.1/32"
                      className="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-primary/50 transition-colors"
                    />
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <div>
                    <label className="block text-xs font-medium text-text-muted mb-1">Action</label>
                    <select
                      value={rule.action}
                      onChange={e => updateRuleAction(index, e.target.value as OutboundAction)}
                      className="bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-primary/50 transition-colors appearance-none cursor-pointer"
                    >
                      <option value="proxy">Proxy</option>
                      <option value="direct">Direct</option>
                      <option value="block">Block</option>
                    </select>
                  </div>
                  <button 
                    onClick={() => removeRule(index)}
                    className="p-2 text-text-muted hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors mt-5"
                    title="Remove Rule"
                  >
                    <Trash2 className="w-5 h-5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
