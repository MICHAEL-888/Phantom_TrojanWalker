import axios from 'axios';

// Refactor note: API_BASE was duplicated across Home.jsx, TaskDetail.jsx,
// and History.jsx. Centralized here so all pages share one source of truth.
export const API_BASE = '/api';

export const getTaskStatus = (taskId, { includeHeavy = false } = {}) =>
  axios.get(`${API_BASE}/tasks/${taskId}`, { params: { include_heavy: includeHeavy } });

export const getResultByHash = (sha256, { includeHeavy = false } = {}) =>
  axios.get(`${API_BASE}/result/${sha256}`, { params: { include_heavy: includeHeavy } });

export const uploadAnalyze = (formData) =>
  axios.post(`${API_BASE}/analyze`, formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });

export const getHistory = (limit = 50) =>
  axios.get(`${API_BASE}/history`, { params: { limit } });
