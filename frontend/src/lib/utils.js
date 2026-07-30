// Refactor note: data-shaping helpers and badge theming previously duplicated
// or inlined across ReportView.jsx and History.jsx. Centralized here for reuse.

export const normalizeList = (items) => (Array.isArray(items) ? items.filter(Boolean) : []);

export const getRiskBadgeClass = (riskLevel) => {
  if (riskLevel === 'critical' || riskLevel === 'high') return 'bg-red-900 text-red-100';
  if (riskLevel === 'medium' || riskLevel === 'low') return 'bg-orange-700 text-orange-100';
  if (riskLevel === 'safe') return 'bg-green-900 text-green-100';
  return 'bg-slate-700 text-slate-200';
};

export const getSeverityBadgeClass = (severity) => {
  if (severity === 'critical') return 'bg-red-800 text-red-100';
  if (severity === 'high') return 'bg-orange-800 text-orange-100';
  if (severity === 'medium') return 'bg-yellow-800 text-yellow-100';
  return 'bg-slate-700 text-slate-200';
};

export const getStatusBadgeClass = (status) => {
  switch (status) {
    case 'completed':
      return 'bg-emerald-900/30 text-emerald-400 border-emerald-800';
    case 'failed':
      return 'bg-red-900/30 text-red-400 border-red-800';
    case 'pending':
    case 'processing':
      return 'bg-cyan-900/30 text-cyan-400 border-cyan-800';
    default:
      return 'bg-slate-800 text-slate-400 border-slate-700';
  }
};

const _IOC_KEYS = [
  'domains', 'ips', 'urls', 'file_paths',
  'registry_keys', 'mutexes', 'process_names', 'service_names',
];

export const hasAnyIocs = (iocs) => {
  if (!iocs) return false;
  return _IOC_KEYS.some((k) => Array.isArray(iocs[k]) && iocs[k].length > 0);
};

export const formatDate = (dateString) => {
  if (!dateString) return 'N/A';
  return new Intl.DateTimeFormat('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(new Date(dateString));
};

export const sha256HexFromFile = async (file) => {
  if (!globalThis.crypto?.subtle) {
    throw new Error('WebCrypto unavailable (needs secure context/HTTPS)');
  }
  const buffer = await file.arrayBuffer();
  const digest = await globalThis.crypto.subtle.digest('SHA-256', buffer);
  const bytes = new Uint8Array(digest);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
};

export const buildUploadFormData = (selectedFile, sha256) => {
  const formData = new FormData();
  formData.append('file', selectedFile);
  if (sha256) {
    formData.append('sha256', sha256);
  }
  return formData;
};

export const eventHasFiles = (event) =>
  Array.from(event?.dataTransfer?.types || []).includes('Files');
