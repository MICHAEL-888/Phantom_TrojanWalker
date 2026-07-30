import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Clock, FileText, AlertCircle, CheckCircle, Loader2, Search } from 'lucide-react';
import { getHistory, getResultByHash } from '../lib/api';
import { getStatusBadgeClass, formatDate } from '../lib/utils';

// Refactor note: helpers (getStatusIcon, getStatusBadgeClass, formatDate)
// hoisted to module scope — previously defined inside the component and
// recreated on every render. getStatusBadgeClass and formatDate now come
// from lib/utils.js. Fixed non-existent Tailwind classes w-58/w-30 → w-60/w-32.
// Removed unused React import. Trimmed the 50-line JSDoc block.

function getStatusIcon(status) {
  switch (status) {
    case 'completed':
      return <CheckCircle className="w-5 h-5 text-emerald-400" />;
    case 'failed':
      return <AlertCircle className="w-5 h-5 text-red-400" />;
    case 'pending':
    case 'processing':
      return <Loader2 className="w-5 h-5 text-cyan-400 animate-spin" />;
    default:
      return <Clock className="w-5 h-5 text-slate-400" />;
  }
}

export default function History() {
  const [history, setHistory] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchHash, setSearchHash] = useState('');
  const [isSearching, setIsSearching] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const res = await getHistory(50);
        setHistory(res.data);
      } catch (err) {
        console.error(err);
        setError('Failed to load history.');
      } finally {
        setIsLoading(false);
      }
    };
    fetchHistory();
  }, []);

  const searchByHash = async () => {
    if (!searchHash) return;
    setIsSearching(true);
    setError(null);
    try {
      const res = await getResultByHash(searchHash);
      navigate(`/task/${res.data.task_id}`);
    } catch (err) {
      setError('Analysis not found for this hash.');
      setIsSearching(false);
    }
  };

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-64">
        <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-900/20 p-8 rounded-xl border border-red-800 text-center">
        <AlertCircle className="w-12 h-12 mx-auto text-red-500 mb-4" />
        <h3 className="text-2xl font-bold text-red-400">Error</h3>
        <p className="text-red-200 mt-2">{error}</p>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto">
      <header className="mb-8 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center">
            <Clock className="mr-3 text-cyan-400" /> Analysis History
          </h1>
          <p className="text-slate-400 mt-2">Recent malware analysis tasks</p>
        </div>

        <div className="flex items-center space-x-2 bg-slate-800 p-2 rounded-xl border border-slate-700 shadow-lg w-full md:w-96">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              type="text"
              placeholder="Enter SHA256 Hash"
              className="w-full bg-slate-900 border border-slate-600 rounded-lg py-2 pl-10 pr-4 text-sm text-slate-100 focus:outline-none focus:border-cyan-500 transition-colors"
              value={searchHash}
              onChange={(e) => setSearchHash(e.target.value)}
            />
          </div>
          <button
            onClick={searchByHash}
            disabled={!searchHash || isSearching}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white text-sm font-bold rounded-lg transition-all disabled:opacity-50 cursor-pointer whitespace-nowrap"
          >
            {isSearching ? 'Searching...' : 'Search'}
          </button>
        </div>
      </header>

      <div className="bg-slate-800 rounded-xl border border-slate-700 shadow-xl overflow-hidden">
        {history.length === 0 ? (
          <div className="p-8 text-center text-slate-400">
            No analysis history found.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse table-fixed">
              <thead>
                <tr className="bg-slate-900/50 border-b border-slate-700 text-slate-300 text-sm uppercase tracking-wider">
                  <th className="p-4 font-medium w-32">Status</th>
                  <th className="p-4 font-medium w-1/3">Filename</th>
                  <th className="p-4 font-medium w-1/3">SHA256</th>
                  <th className="p-4 font-medium w-60">Date</th>
                  <th className="p-4 font-medium w-32">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {history.map((task) => (
                  <tr
                    key={task.task_id}
                    className="hover:bg-slate-700/30 transition-colors group"
                  >
                    <td className="p-4">
                      <div
                        className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${getStatusBadgeClass(task.status)}`}
                      >
                        {getStatusIcon(task.status)}
                        <span className="ml-1.5 capitalize">{task.status}</span>
                      </div>
                    </td>
                    <td className="p-4">
                      <div className="flex items-center text-slate-200 font-medium truncate">
                        <FileText className="w-4 h-4 mr-2 text-slate-400 flex-shrink-0" />
                        <span className="truncate" title={task.filename || 'Unknown'}>
                          {task.filename || 'Unknown'}
                        </span>
                      </div>
                    </td>
                    <td className="p-4">
                      <div className="text-slate-400 font-mono text-sm truncate" title={task.sha256}>
                        {task.sha256}
                      </div>
                    </td>
                    <td className="p-4 text-slate-400 text-sm">
                      {formatDate(task.created_at)}
                    </td>
                    <td className="p-4 text-right">
                      <button
                        onClick={() => navigate(`/task/${task.task_id}`)}
                        className="inline-flex items-center px-3 py-1.5 bg-slate-700 hover:bg-cyan-600 text-white text-sm font-medium rounded transition-colors cursor-pointer"
                      >
                        View Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
