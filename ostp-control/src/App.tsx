import { HashRouter as Router, Routes, Route, Link, Navigate, useLocation } from 'react-router-dom';
import { Activity, Users, Settings, Shield, MoreVertical, RefreshCw, BookOpen, Wrench, History, Globe, LogOut } from 'lucide-react';
import { useState, useEffect } from 'react';
import type { ReactNode } from 'react';

// Components
import Dashboard from './pages/Dashboard';
import Clients from './pages/Clients';
import SettingsPage from './pages/Settings';
import Wiki from './pages/Wiki';
import Tools from './pages/Tools';
import AuditLogs from './pages/AuditLogs';
import Login from './pages/Login';
import Dns from './pages/Dns';

// State and Context
import { api } from './lib/api';
import { LanguageProvider, useLanguage } from './lib/LanguageContext';

function AuthGuard({ children }: { children: ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null);
  const location = useLocation();

  useEffect(() => {
    const checkAuth = async () => {
      try {
        await api.getServerStatus();
        setIsAuthenticated(true);
      } catch {
        setIsAuthenticated(false);
      }
    };
    checkAuth();
  }, [location.pathname]);

  if (isAuthenticated === null) {
    return (
      <div className="flex h-screen w-screen bg-background items-center justify-center text-white font-sans">
        <RefreshCw className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
}

function MainLayout() {
  const { t, language, setLanguage } = useLanguage();
  const [isSidebarOpen, setSidebarOpen] = useState(true);

  return (
    <div className="flex h-screen bg-background text-text overflow-hidden">
        {/* Sidebar */}
        <aside className={`bg-surface-light border-r border-white/5 transition-all duration-300 ${isSidebarOpen ? 'w-64' : 'w-20'} flex flex-col`}>
          <div className="h-16 flex items-center justify-center border-b border-white/5">
            <Shield className="w-8 h-8 text-primary animate-pulse" />
            {isSidebarOpen && <span className="ml-3 font-bold text-xl tracking-wider text-white">OSTP<span className="text-primary">CORE</span></span>}
          </div>
          
          <nav className="flex-1 py-6 flex flex-col gap-2 px-3">
            <Link to="/" className="flex items-center gap-3 px-3 py-3 rounded-xl hover:bg-white/5 transition-colors text-text-muted hover:text-white">
              <Activity className="w-5 h-5 text-primary" />
              {isSidebarOpen && <span>{t('sidebar_dashboard')}</span>}
            </Link>
            <Link to="/clients" className="flex items-center gap-3 px-3 py-3 rounded-xl hover:bg-white/5 transition-colors text-text-muted hover:text-white">
              <Users className="w-5 h-5 text-secondary" />
              {isSidebarOpen && <span>{t('sidebar_clients')}</span>}
            </Link>
            <Link to="/tools" className="flex items-center gap-3 px-3 py-3 rounded-xl hover:bg-white/5 transition-colors text-text-muted hover:text-white">
              <Wrench className="w-5 h-5 text-purple-400" />
              {isSidebarOpen && <span>{t('sidebar_tools')}</span>}
            </Link>
            <Link to="/wiki" className="flex items-center gap-3 px-3 py-3 rounded-xl hover:bg-white/5 transition-colors text-text-muted hover:text-white">
              <BookOpen className="w-5 h-5 text-blue-400" />
              {isSidebarOpen && <span>{t('sidebar_wiki')}</span>}
            </Link>
            <Link to="/dns" className="flex items-center gap-3 px-3 py-3 rounded-xl hover:bg-white/5 transition-colors text-text-muted hover:text-white">
              <Globe className="w-5 h-5 text-emerald-400" />
              {isSidebarOpen && <span>{t('sidebar_dns')}</span>}
            </Link>
            <Link to="/logs" className="flex items-center gap-3 px-3 py-3 rounded-xl hover:bg-white/5 transition-colors text-text-muted hover:text-white">
              <History className="w-5 h-5 text-yellow-400" />
              {isSidebarOpen && <span>{t('sidebar_history')}</span>}
            </Link>
            <div className="mt-auto">
              <Link to="/settings" className="flex items-center gap-3 px-3 py-3 rounded-xl hover:bg-white/5 transition-colors text-text-muted hover:text-white">
                <Settings className="w-5 h-5 text-text-muted" />
                {isSidebarOpen && <span>{t('sidebar_settings')}</span>}
              </Link>
            </div>
          </nav>
        </aside>

        {/* Main Content */}
        <main className="flex-1 flex flex-col relative overflow-hidden">
          {/* Header */}
          <header className="h-16 glass z-10 flex items-center justify-between px-6 border-b border-white/5">
            <div className="flex items-center gap-3">
              <button 
                onClick={() => setSidebarOpen(!isSidebarOpen)}
                className="p-2 rounded-lg hover:bg-white/5 text-text-muted transition-colors cursor-pointer"
              >
                <MoreVertical className="w-5 h-5" />
              </button>
              
              <button
                onClick={() => {
                  import('./lib/api').then(({ clearApiAuth }) => clearApiAuth());
                  window.location.reload();
                }}
                className="text-xs text-text-muted hover:text-red-400 bg-white/5 hover:bg-red-500/10 border border-white/10 rounded-lg px-2.5 py-1.5 transition-colors cursor-pointer flex items-center gap-1.5"
              >
                <LogOut className="w-3.5 h-3.5" />
                {t('header_reset_conn') || 'Logout'}
              </button>
            </div>
            
            <div className="flex items-center gap-4">
              {/* Language Switcher */}
              <button
                onClick={() => setLanguage(language === 'ru' ? 'en' : 'ru')}
                className="flex items-center gap-1.5 text-xs text-white bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg px-3 py-1.5 transition-all font-semibold cursor-pointer shadow-[0_0_10px_rgba(255,255,255,0.02)]"
              >
                <Globe className="w-3.5 h-3.5 text-primary" />
                {language === 'ru' ? 'RU' : 'EN'}
              </button>

              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-secondary shadow-[0_0_10px_#22D3A5]"></div>
                <span className="text-sm text-text-muted">{t('header_core_online')}</span>
              </div>
            </div>
          </header>

          {/* Page Content */}
          <div className="flex-1 overflow-auto p-6 relative">
            {/* Background decorative blobs */}
            <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] rounded-full bg-primary/20 blur-[120px] pointer-events-none"></div>
            <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] rounded-full bg-secondary/10 blur-[120px] pointer-events-none"></div>
            
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/clients" element={<Clients />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="/wiki" element={<Wiki />} />
              <Route path="/tools" element={<Tools />} />
              <Route path="/dns" element={<Dns />} />
              <Route path="/logs" element={<AuditLogs />} />
            </Routes>
          </div>
        </main>
    </div>
  );
}

function AppContent() {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login onLoginSuccess={() => window.location.href = '#/'} />} />
        <Route
          path="/*"
          element={
            <AuthGuard>
              <MainLayout />
            </AuthGuard>
          }
        />
      </Routes>
    </Router>
  );
}

export default function App() {
  return (
    <LanguageProvider>
      <AppContent />
    </LanguageProvider>
  );
}
