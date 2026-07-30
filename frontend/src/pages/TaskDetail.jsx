import { useEffect, useState, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { AlertCircle, Loader2, ArrowLeft } from 'lucide-react';
import ReportView from '../components/ReportView';
import { getTaskStatus } from '../lib/api';

const STATUS = {
  idle: 'idle',
  pending: 'pending',
  processing: 'processing',
  completed: 'completed',
  failed: 'failed',
};
const POLL_INTERVAL_MS = 30000;

function isInProgress(status) {
  return status === STATUS.pending || status === STATUS.processing;
}

// Refactor note: removed unused React import (automatic JSX runtime).
// Polling now uses AbortController to cancel in-flight requests on unmount.
// The setStatus-as-read hack is replaced by a statusRef that mirrors state.
export default function TaskDetail() {
  const { taskId } = useParams();
  const navigate = useNavigate();
  const [status, setStatus] = useState(STATUS.idle);
  const [report, setReport] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const statusRef = useRef(STATUS.idle);

  const applyTaskState = (taskData) => {
    if (!taskData) return;
    setStatus(taskData.status);
    statusRef.current = taskData.status;

    if (taskData.status === STATUS.completed) {
      setReport(taskData);
      return;
    }
    if (taskData.status === STATUS.failed) {
      setErrorMessage(taskData.error || 'Analysis failed.');
    }
  };

  const fetchStatus = async (id, signal) => {
    try {
      const res = await getTaskStatus(id, { signal });
      applyTaskState(res.data);
    } catch (err) {
      if (err.name === 'CanceledError') return;
      console.error(err);
      if (err.response?.status === 404) {
        setErrorMessage('Task not found.');
        setStatus(STATUS.failed);
        statusRef.current = STATUS.failed;
      }
    }
  };

  useEffect(() => {
    if (!taskId) return;

    const controller = new AbortController();

    // Initial fetch
    fetchStatus(taskId, controller.signal);

    const interval = setInterval(() => {
      // Refactor note: read current status from ref instead of the
      // setStatus(callback) hack that caused extra render cycles.
      if (isInProgress(statusRef.current) || statusRef.current === STATUS.idle) {
        fetchStatus(taskId, controller.signal);
      } else {
        clearInterval(interval);
      }
    }, POLL_INTERVAL_MS);

    return () => {
      controller.abort();
      clearInterval(interval);
    };
  }, [taskId]);

  return (
    <div className="max-w-7xl mx-auto">
      <button
        onClick={() => navigate(-1)}
        className="mb-6 flex items-center text-slate-400 hover:text-emerald-400 transition-colors cursor-pointer"
      >
        <ArrowLeft className="w-4 h-4 mr-2" /> Back
      </button>

      {status !== STATUS.idle && (
        <div className="animate-in fade-in duration-500">
          {isInProgress(status) ? (
            <div className="bg-slate-800 p-8 rounded-xl border border-slate-700 text-center">
              <Loader2 className="animate-spin w-12 h-12 mx-auto text-cyan-400 mb-4" />
              <h3 className="text-2xl font-bold text-white">Analysis in Progress...</h3>
              <p className="text-slate-400 mt-2">
                AI Agents are auditing the binary. This may take a few minutes.
                <br />
                Current State: <span className="text-cyan-400 uppercase">{status}</span>
              </p>
            </div>
          ) : null}

          {status === STATUS.failed && (
            <div className="bg-red-900/20 p-8 rounded-xl border border-red-800 text-center">
              <AlertCircle className="w-12 h-12 mx-auto text-red-500 mb-4" />
              <h3 className="text-2xl font-bold text-red-400">Analysis Failed</h3>
              <p className="text-red-200 mt-2">{errorMessage}</p>
            </div>
          )}

          {status === STATUS.completed && report && (
            <ReportView report={report} />
          )}
        </div>
      )}
    </div>
  );
}
