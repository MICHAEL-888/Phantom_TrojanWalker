import { Routes, Route, Link, useLocation } from 'react-router-dom';
import { Home as HomeIcon, Clock } from 'lucide-react';
import Home from './pages/Home';
import History from './pages/History';
import TaskDetail from './pages/TaskDetail';
import { useScrollNavbar } from './hooks/useScrollNavbar';

// Refactor note: shared nav-link class string to avoid duplication between
// Home and History links.
const _navLinkBase =
  'flex items-center px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 cursor-pointer';
const _navLinkActive = 'bg-slate-700 text-white shadow-md';
const _navLinkInactive = 'text-slate-400 hover:text-slate-200 hover:bg-slate-800';

function NavLink({ to, icon, label, isActive }) {
  return (
    <Link
      to={to}
      className={`${_navLinkBase} ${isActive ? _navLinkActive : _navLinkInactive}`}
    >
      {icon}
      <span className="ml-2">{label}</span>
    </Link>
  );
}

function App() {
  const location = useLocation();
  const { isScrolled, isVisible } = useScrollNavbar();

  const isActive = (path) => location.pathname === path;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-50 font-sans selection:bg-cyan-500/30">
      <nav
        className={`fixed left-0 right-0 z-50 bg-slate-900/90 backdrop-blur-md border-b border-slate-800 shadow-2xl flex items-center justify-between transition-all duration-300 ${
          isVisible ? 'translate-y-0' : '-translate-y-full'
        } ${isScrolled ? 'py-2' : 'py-4'}`}
      >
        <div className="max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <span className="text-xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-emerald-400 to-cyan-500">
              Phantom TrojanWalker
            </span>
          </div>

          <div className="flex items-center space-x-1 bg-slate-800/50 p-1 rounded-xl border border-slate-700/50">
            <NavLink to="/" icon={<HomeIcon className="w-4 h-4" />} label="Home" isActive={isActive('/')} />
            <NavLink to="/history" icon={<Clock className="w-4 h-4" />} label="History" isActive={isActive('/history')} />
          </div>
        </div>
      </nav>

      <main className="pt-28 pb-12 px-4 sm:px-6 lg:px-8">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/history" element={<History />} />
          <Route path="/task/:taskId" element={<TaskDetail />} />
        </Routes>
      </main>
    </div>
  );
}

export default App;
