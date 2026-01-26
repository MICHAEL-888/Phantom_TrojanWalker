import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Upload, Search, Loader2, FileWarning, CheckCircle, AlertCircle } from 'lucide-react';
import ReportView from './components/ReportView';

// IMPORTANT: To ensure the browser never talks to backend directly,
// the frontend always calls a same-origin relative API path.
// In dev, Vite's proxy handles forwarding. In production, the frontend container
// runs a small Node gateway that proxies /api/* to the backend.
const API_BASE = "/api";

async function sha256HexFromFile(file) {
  if (!globalThis.crypto?.subtle) {
    throw new Error('WebCrypto unavailable (needs secure context/HTTPS)');
  }
  const buffer = await file.arrayBuffer();
  const digest = await globalThis.crypto.subtle.digest('SHA-256', buffer);
  const bytes = new Uint8Array(digest);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function App() {
  const [file, setFile] = useState(null);
  const [taskId, setTaskId] = useState(null);
  const [status, setStatus] = useState("idle"); // idle, uploading, pending, processing, completed, failed
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [searchHash, setSearchHash] = useState("");

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  const uploadFile = async () => {
    if (!file) return;
    setStatus("uploading");
    setReport(null);
    setError(null);

    let sha256 = null;
    try {
      sha256 = await sha256HexFromFile(file);
      // Pre-dedupe: if task exists for this sha256, reuse it and avoid uploading.
      const existing = await axios.get(`${API_BASE}/result/${sha256}`);
      setTaskId(existing.data.task_id);
      setStatus(existing.data.status);
      if (existing.data.status === 'completed') {
        setReport(existing.data);
      } else if (existing.data.status === 'failed') {
        setError(existing.data.error || 'Analysis failed.');
      }
      return;
    } catch (err) {
      // 404 means no existing task -> proceed to upload.
      // Any other error (e.g. WebCrypto not available) also falls back to upload.
      if (err?.response?.status && err.response.status !== 404) {
        console.warn('Pre-dedupe lookup failed, falling back to upload:', err);
      }
      if (!sha256 && !globalThis.crypto?.subtle) {
        console.warn('WebCrypto unavailable; uploading without client-side sha256');
      }
    }

    const formData = new FormData();
    formData.append("file", file);
    if (sha256) {
      formData.append('sha256', sha256);
    }

    try {
      const res = await axios.post(`${API_BASE}/analyze`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setTaskId(res.data.task_id);
      setStatus(res.data.status); 
      
      if (res.data.status === 'completed') {
        fetchStatus(res.data.task_id);
      }
    } catch (err) {
      console.error(err);
      setError("Upload failed.");
      setStatus("failed");
    }
  };

  const fetchStatus = async (tid) => {
    try {
      const res = await axios.get(`${API_BASE}/tasks/${tid}`);
      setStatus(res.data.status);
      if (res.data.status === "completed") {
        setReport(res.data);
      } else if (res.data.status === "failed") {
        setError(res.data.error || "Analysis failed.");
      }
    } catch (err) {
      console.error(err);
    }
  };

  const searchByHash = async () => {
    if (!searchHash) return;
    try {
      setStatus("processing");
      const res = await axios.get(`${API_BASE}/result/${searchHash}`);
      setTaskId(res.data.task_id);
      setStatus(res.data.status);
      if (res.data.status === "completed") {
        setReport(res.data);
      }
    } catch (err) {
      setError("Analysis not found for this hash.");
      setStatus("failed");
    }
  };

  // Polling
  useEffect(() => {
    let interval;
    if (taskId && (status === "pending" || status === "processing")) {
      interval = setInterval(() => {
        fetchStatus(taskId);
      }, 2000);
    }
    return () => clearInterval(interval);
  }, [taskId, status]);

  return (
    <div className="min-h-screen p-8 max-w-7xl mx-auto">
      <header className="mb-12 text-center">
        <h1 className="text-5xl font-extrabold mb-4 bg-clip-text text-transparent bg-gradient-to-r from-emerald-400 to-cyan-500">
          Phantom TrojanWalker
        </h1>
        <p className="text-xl text-slate-400">Next-Gen AI Malware Analysis Framework</p>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
        {/* Upload Card */}
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-xl lg:col-span-2">
          <h2 className="text-2xl font-bold mb-6 flex items-center">
            <Upload className="mr-2 text-emerald-400" /> Upload Binary
          </h2>
          <div className="border-2 border-dashed border-slate-600 rounded-lg p-12 text-center hover:border-emerald-500 transition-colors cursor-pointer relative">
            <input 
              type="file" 
              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
              onChange={handleFileChange}
            />
            {file ? (
              <div className="text-emerald-400 font-semibold">{file.name}</div>
            ) : (
              <div className="text-slate-400">
                <p>Drag & drop or click to select</p>
                <p className="text-sm mt-2 opacity-60">Supports PE, ELF, Mach-O</p>
              </div>
            )}
          </div>
          <button 
            onClick={uploadFile}
            disabled={!file || status === 'uploading'}
            className="mt-4 w-full bg-emerald-600 hover:bg-emerald-700 text-white font-bold py-3 rounded-lg transition-all disabled:opacity-50"
          >
            {status === 'uploading' ? 'Uploading...' : 'Start Analysis'}
          </button>
        </div>

        {/* Search Card */}
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-xl">
          <h2 className="text-2xl font-bold mb-6 flex items-center">
            <Search className="mr-2 text-cyan-400" /> Search History
          </h2>
          <div className="space-y-4">
             <input 
              type="text" 
              placeholder="Enter SHA256 Hash"
              className="w-full bg-slate-900 border border-slate-600 rounded p-3 text-slate-100 focus:outline-none focus:border-cyan-500"
              value={searchHash}
              onChange={(e) => setSearchHash(e.target.value)}
            />
            <button 
              onClick={searchByHash}
              className="w-full bg-cyan-600 hover:bg-cyan-700 text-white font-bold py-3 rounded-lg transition-all"
            >
              Search
            </button>
          </div>
        </div>
      </div>

      {/* Status & Results */}
      {status !== 'idle' && (
        <div className="animate-in fade-in duration-500">
           {status === 'pending' || status === 'processing' ? (
             <div className="bg-slate-800 p-8 rounded-xl border border-slate-700 text-center">
               <Loader2 className="animate-spin w-12 h-12 mx-auto text-cyan-400 mb-4" />
               <h3 className="text-2xl font-bold text-white">Analysis in Progress...</h3>
               <p className="text-slate-400 mt-2">
                 AI Agents are auditing the binary. This may take a few minutes.
                 <br/>
                 Current State: <span className="text-cyan-400 uppercase">{status}</span>
               </p>
             </div>
           ) : null}

           {status === 'failed' && (
             <div className="bg-red-900/20 p-8 rounded-xl border border-red-800 text-center">
               <AlertCircle className="w-12 h-12 mx-auto text-red-500 mb-4" />
               <h3 className="text-2xl font-bold text-red-400">Analysis Failed</h3>
               <p className="text-red-200 mt-2">{error}</p>
             </div>
           )}

           {status === 'completed' && report && (
             <ReportView report={report} />
           )}
        </div>
      )}
    </div>
  );
}

export default App;
