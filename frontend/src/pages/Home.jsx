import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Search, Upload } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

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

function buildUploadFormData(selectedFile, sha256) {
  const formData = new FormData();
  formData.append("file", selectedFile);
  if (sha256) {
    formData.append('sha256', sha256);
  }
  return formData;
}

function eventHasFiles(event) {
  return Array.from(event?.dataTransfer?.types || []).includes('Files');
}

export default function Home() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [isDraggingFile, setIsDraggingFile] = useState(false);
  const [searchHash, setSearchHash] = useState("");
  const [isUploading, setIsUploading] = useState(false);
  const [isSearching, setIsSearching] = useState(false);
  const [errorMessage, setErrorMessage] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    const preventWindowFileDrop = (event) => {
      if (!eventHasFiles(event)) {
        return;
      }
      event.preventDefault();
    };

    window.addEventListener('dragover', preventWindowFileDrop);
    window.addEventListener('drop', preventWindowFileDrop);

    return () => {
      window.removeEventListener('dragover', preventWindowFileDrop);
      window.removeEventListener('drop', preventWindowFileDrop);
    };
  }, []);

  const handleFileSelection = (nextFile) => {
    setSelectedFile(nextFile);
    setErrorMessage(null);
  };

  const handleFileChange = (event) => {
    const nextFile = event.target.files?.[0] || null;
    handleFileSelection(nextFile);
    setIsDraggingFile(false);
  };

  const handleDragEnter = (event) => {
    if (!eventHasFiles(event)) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    setIsDraggingFile(true);
  };

  const handleDragOver = (event) => {
    if (!eventHasFiles(event)) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    event.dataTransfer.dropEffect = 'copy';
    setIsDraggingFile(true);
  };

  const handleDragLeave = (event) => {
    if (!eventHasFiles(event)) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    if (!event.currentTarget.contains(event.relatedTarget)) {
      setIsDraggingFile(false);
    }
  };

  const handleDrop = (event) => {
    if (!eventHasFiles(event)) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    const nextFile = event.dataTransfer.files?.[0] || null;
    handleFileSelection(nextFile);
    setIsDraggingFile(false);
  };

  const uploadFile = async () => {
    if (!selectedFile) return;
    setIsUploading(true);
    setErrorMessage(null);

    let sha256 = null;
    try {
      sha256 = await sha256HexFromFile(selectedFile);
      const existing = await axios.get(`${API_BASE}/result/${sha256}`);
      const existingStatus = existing?.data?.status;
      if (existingStatus && existingStatus !== "failed") {
        navigate(`/task/${existing.data.task_id}`);
        return;
      }
    } catch (err) {
      if (err?.response?.status && err.response.status !== 404) {
        console.warn('Pre-dedupe lookup failed, falling back to upload:', err);
      }
      if (!sha256 && !globalThis.crypto?.subtle) {
        console.warn('WebCrypto unavailable; uploading without client-side sha256');
      }
    }

    const formData = buildUploadFormData(selectedFile, sha256);

    try {
      const res = await axios.post(`${API_BASE}/analyze`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      navigate(`/task/${res.data.task_id}`);
    } catch (err) {
      console.error(err);
      setErrorMessage("Upload failed.");
      setIsUploading(false);
    }
  };

  const searchByHash = async () => {
    if (!searchHash) return;
    setIsSearching(true);
    setErrorMessage(null);
    try {
      const res = await axios.get(`${API_BASE}/result/${searchHash}`);
      navigate(`/task/${res.data.task_id}`);
    } catch (err) {
      setErrorMessage("Analysis not found for this hash.");
      setIsSearching(false);
    }
  };

  return (
    <div className="max-w-7xl mx-auto">
      <header className="mb-12 text-center">
        <h1 className="text-5xl font-extrabold mb-4 bg-clip-text text-transparent bg-gradient-to-r from-emerald-400 to-cyan-500">
          Phantom TrojanWalker
        </h1>
        <p className="text-xl text-slate-400">Next-Gen AI Malware Analysis Framework</p>
      </header>

      {errorMessage && (
        <div className="mb-8 bg-red-900/20 p-4 rounded-xl border border-red-800 text-center text-red-400">
          {errorMessage}
        </div>
      )}

      <div className="max-w-7xl mx-auto mb-8">
        {/* Upload Card */}
        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-xl">
          <h2 className="text-2xl font-bold mb-6 flex items-center">
            <Upload className="mr-2 text-emerald-400" /> Upload Binary
          </h2>
          <input
            id="binary-upload-input"
            type="file"
            className="hidden"
            onChange={handleFileChange}
          />
          <label
            htmlFor="binary-upload-input"
            onDragEnter={handleDragEnter}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            className={`block border-2 border-dashed rounded-lg p-12 text-center transition-colors cursor-pointer ${
              isDraggingFile
                ? 'border-emerald-400 bg-emerald-500/10'
                : 'border-slate-600 hover:border-emerald-500'
            }`}
          >
            {selectedFile ? (
              <div className="text-emerald-400 font-semibold">{selectedFile.name}</div>
            ) : (
              <div className="text-slate-400">
                <p>Drag & drop or click to select</p>
                <p className="text-sm mt-2 opacity-60">Supports PE, ELF, Mach-O</p>
              </div>
            )}
          </label>
          <button 
            onClick={uploadFile}
            disabled={!selectedFile || isUploading}
            className="mt-4 w-full bg-emerald-600 hover:bg-emerald-700 text-white font-bold py-3 rounded-lg transition-all disabled:opacity-50 cursor-pointer"
          >
            {isUploading ? 'Uploading...' : 'Start Analysis'}
          </button>
        </div>
      </div>
    </div>
  );
}
