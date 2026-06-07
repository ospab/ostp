import React, { useState } from 'react';
import { X, Copy, CheckCircle2, Zap } from 'lucide-react';

interface BulkKeysModalProps {
  onClose: () => void;
  onGenerate: (count: number, limitBytes: number | null) => Promise<string[]>;
}

export function BulkKeysModal({ onClose, onGenerate }: BulkKeysModalProps) {

  const [count, setCount] = useState<number>(10);
  const [limitGB, setLimitGB] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [generatedKeys, setGeneratedKeys] = useState<string[]>([]);
  const [copied, setCopied] = useState(false);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const limitBytes = limitGB ? parseInt(limitGB) * 1024 * 1024 * 1024 : null;
      const keys = await onGenerate(count, limitBytes);
      setGeneratedKeys(keys);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(generatedKeys.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-background-light border border-white/10 rounded-2xl w-full max-w-md shadow-2xl overflow-hidden">
        <div className="p-6 border-b border-white/5 flex items-center justify-between">
          <h2 className="text-xl font-semibold text-white flex items-center gap-2">
            <Zap className="w-5 h-5 text-primary" />
            Bulk Generate Keys
          </h2>
          <button onClick={onClose} className="p-2 hover:bg-white/5 rounded-lg transition-colors text-text-muted hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>

        {generatedKeys.length === 0 ? (
          <form onSubmit={handleGenerate} className="p-6 space-y-6">
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-text-muted mb-2">Number of Keys to Generate</label>
                <input
                  type="number"
                  min="1"
                  max="1000"
                  required
                  value={count}
                  onChange={e => setCount(parseInt(e.target.value))}
                  className="w-full bg-black/20 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-primary/50 transition-colors"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-text-muted mb-2">Traffic Limit per Key (GB, optional)</label>
                <input
                  type="number"
                  min="1"
                  value={limitGB}
                  onChange={e => setLimitGB(e.target.value)}
                  placeholder="Unlimited"
                  className="w-full bg-black/20 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-primary/50 transition-colors placeholder:text-white/20"
                />
              </div>
            </div>

            <div className="flex gap-3 pt-2">
              <button
                type="button"
                onClick={onClose}
                className="flex-1 px-4 py-3 rounded-xl font-medium text-white hover:bg-white/5 transition-colors border border-white/10"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={loading}
                className="flex-1 px-4 py-3 bg-primary hover:bg-primary/90 text-white rounded-xl font-medium transition-colors flex items-center justify-center disabled:opacity-50"
              >
                {loading ? 'Generating...' : 'Generate'}
              </button>
            </div>
          </form>
        ) : (
          <div className="p-6 space-y-6">
            <p className="text-secondary font-medium flex items-center gap-2">
              <CheckCircle2 className="w-5 h-5" /> Successfully generated {generatedKeys.length} keys
            </p>
            
            <div className="bg-black/40 rounded-xl p-4 border border-white/5 relative group">
              <textarea 
                readOnly 
                value={generatedKeys.join('\n')} 
                className="w-full h-48 bg-transparent text-sm font-mono text-white/80 resize-none outline-none"
              />
              <button 
                onClick={handleCopy}
                className="absolute top-2 right-2 p-2 bg-white/10 hover:bg-white/20 rounded-lg backdrop-blur-md text-white transition-colors flex items-center gap-2"
              >
                {copied ? <CheckCircle2 className="w-4 h-4 text-secondary" /> : <Copy className="w-4 h-4" />}
                <span className="text-xs font-medium">{copied ? 'Copied' : 'Copy All'}</span>
              </button>
            </div>

            <button
              onClick={onClose}
              className="w-full px-4 py-3 bg-white/10 hover:bg-white/20 text-white rounded-xl font-medium transition-colors"
            >
              Close
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
