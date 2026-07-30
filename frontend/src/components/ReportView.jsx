import { useState } from 'react';
import ReactMarkdown from 'react-markdown';
import {
  normalizeList,
  getRiskBadgeClass,
  getSeverityBadgeClass,
  hasAnyIocs,
} from '../lib/utils';

// Refactor note: data-shaping helpers moved to lib/utils.js. Removed unused
// React import (automatic JSX runtime). Inline render helpers kept in-component
// since they depend on component state (collapsible toggles).

const ReportView = ({ report }) => {
  const [maliciousOpen, setMaliciousOpen] = useState(false);
  const [ttpsOpen, setTtpsOpen] = useState(false);
  const [iocsOpen, setIocsOpen] = useState(false);

  // Refactor: keep hooks unconditional to satisfy React rules.
  if (!report) return null;

  const metadata = report.metadata;
  const malwareReport = report.malware_report;
  const extractedIocCount = Object.values(malwareReport?.extracted_iocs || {}).reduce(
    (count, items) => count + (Array.isArray(items) ? items.length : 0),
    0
  );

  const renderChevronButton = (open, onClick, expandedLabel, collapsedLabel) => (
    <button
      onClick={onClick}
      aria-expanded={open}
      aria-label={open ? expandedLabel : collapsedLabel}
      className="text-slate-200 bg-slate-800/60 hover:bg-slate-800 px-2 py-1 rounded flex items-center justify-center"
    >
      <svg
        className={`w-4 h-4 transform transition-transform ${open ? 'rotate-90' : ''}`}
        viewBox="0 0 20 20"
        fill="currentColor"
        xmlns="http://www.w3.org/2000/svg"
      >
        <path fillRule="evenodd" clipRule="evenodd" d="M6.293 4.293a1 1 0 011.414 0L13.414 10l-5.707 5.707a1 1 0 01-1.414-1.414L10.586 10 6.293 5.707a1 1 0 010-1.414z" />
      </svg>
    </button>
  );

  const renderIocGroup = (title, items) => {
    const safeItems = normalizeList(items);
    if (safeItems.length === 0) return null;
    return (
      <div className="bg-slate-800 p-3 rounded border border-slate-700">
        <div className="flex items-center justify-between mb-2">
          <div className="text-sm font-bold text-slate-100">{title}</div>
          <div className="text-xs text-slate-400">{safeItems.length}</div>
        </div>
        <div className="flex flex-wrap gap-2">
          {safeItems.map((v, idx) => (
            <span key={`${title}-${idx}`} className="font-mono text-[11px] px-2 py-1 rounded bg-slate-700/60 text-slate-100 break-all">
              {String(v)}
            </span>
          ))}
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-4 text-left">
      {/* 1. Basic Information */}
      <div className="bg-slate-800 p-6 rounded-lg shadow-lg border border-slate-700">
        <h2 className="text-2xl font-bold mb-4 text-emerald-400">File Basic Info</h2>
        {metadata && metadata.bin ? (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 text-sm">
            <div className="bg-slate-700 p-3 rounded col-span-2">
              <span className="block text-slate-400 text-xs">Filename</span>
              <span className="font-mono text-emerald-300 break-all">{report.filename || 'Unknown'}</span>
            </div>
            <div className="bg-slate-700 p-3 rounded">
              <span className="block text-slate-400 text-xs">Architecture</span>
              <span className="font-mono text-cyan-300">{metadata.bin.arch || 'N/A'}</span>
            </div>
            <div className="bg-slate-700 p-3 rounded">
              <span className="block text-slate-400 text-xs">Bits</span>
              <span className="font-mono text-purple-300">{metadata.bin.bits || 'N/A'}</span>
            </div>
            <div className="bg-slate-700 p-3 rounded">
              <span className="block text-slate-400 text-xs">Subsystem</span>
              <span className="font-mono text-yellow-300">{metadata.bin.subsys || 'N/A'}</span>
            </div>
            <div className="bg-slate-700 p-3 rounded">
              <span className="block text-slate-400 text-xs">Signed</span>
              <span className="font-mono text-blue-300">{metadata.bin.signed ? 'Yes' : 'No'}</span>
            </div>
            <div className="bg-slate-700 p-3 rounded">
              <span className="block text-slate-400 text-xs">Compiled At</span>
              <span className="font-mono text-slate-200">{metadata.bin.compiled || 'N/A'}</span>
            </div>
            <div className="bg-slate-700 p-3 rounded">
              <span className="block text-slate-400 text-xs">Size</span>
              <span className="font-mono text-slate-200">{metadata.core?.humansz || metadata.core?.size}</span>
            </div>
            <div className="bg-slate-700 p-3 rounded col-span-2 lg:col-span-4">
              <span className="block text-slate-400 text-xs">SHA256</span>
              <span className="font-mono text-slate-200 break-all text-[10px] sm:text-xs">{report.sha256 || metadata.core?.sha256 || 'N/A'}</span>
            </div>
          </div>
        ) : (
          <p className="text-slate-400">No metadata available.</p>
        )}
      </div>

      {/* 2. Analysis Summary (Malware Report) */}
      <div className="bg-slate-800 p-6 rounded-lg shadow-lg border border-slate-700">
        <h2 className="text-2xl font-bold mb-4 text-emerald-400">Analysis Summary</h2>
        {malwareReport ? (
          <div className="space-y-4">
            <div className="flex space-x-4 mb-4">
              <span className={`px-3 py-1 rounded text-sm font-bold uppercase ${getRiskBadgeClass(malwareReport.risk_level)}`}>
                Risk: {malwareReport.risk_level}
              </span>
              <span className="px-3 py-1 rounded text-sm font-bold bg-slate-700 text-slate-200">
                Type: {malwareReport.threat_type}
              </span>
            </div>

            <div className="bg-slate-700/50 p-4 rounded border-l-4 border-cyan-500 mb-4">
              <h3 className="font-bold text-lg text-white mb-1">Variant Identity</h3>
              <p className="font-mono text-cyan-300">{malwareReport.malware_name}</p>
            </div>

            <div className="bg-slate-700/50 p-4 rounded border-l-4 border-blue-500 mb-4">
              <h3 className="font-bold text-lg text-white mb-1">Attack Chain Analysis</h3>
              <p className="text-slate-300 leading-relaxed">{malwareReport.attack_chain}</p>
            </div>

            <div className="bg-slate-700/50 p-4 rounded border-l-4 border-indigo-500 mb-4">
              <h3 className="font-bold text-lg text-white mb-1">Detailed Reason</h3>
              <div className="prose prose-invert prose-sm max-w-none">
                <ReactMarkdown>{malwareReport.reason}</ReactMarkdown>
              </div>
            </div>

            {/* 2.1 Key TTPs (ATT&CK) */}
            {Array.isArray(malwareReport.key_ttps) && malwareReport.key_ttps.length > 0 && (
              <div className="bg-slate-700/50 p-4 rounded border-l-4 border-fuchsia-500">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <h3 className="font-bold text-lg text-white">Key TTPs (ATT&amp;CK)</h3>
                    <span className="text-xs text-slate-300 bg-slate-800/60 border border-slate-700 px-2 py-0.5 rounded">
                      {malwareReport.key_ttps.length}
                    </span>
                  </div>
                  {renderChevronButton(
                    ttpsOpen,
                    () => setTtpsOpen(!ttpsOpen),
                    'Collapse key TTPs',
                    'Expand key TTPs'
                  )}
                </div>

                {ttpsOpen && (
                  <div className="space-y-3">
                    {malwareReport.key_ttps.map((ttp, idx) => {
                      const techniqueId = ttp?.technique_id || '';
                      const techniqueName = ttp?.technique_name || 'Unknown technique';
                      const tactics = normalizeList(ttp?.tactics);
                      const evidenceRefs = Array.isArray(ttp?.evidence_refs) ? ttp.evidence_refs : [];

                      return (
                        <div key={`ttp-${idx}`} className="bg-slate-800 p-4 rounded border border-slate-700">
                          <div className="flex flex-wrap items-start justify-between gap-2">
                            <div className="min-w-0">
                              <div className="text-sm text-slate-400">Technique</div>
                              <div className="text-slate-100 font-semibold break-words">
                                <span className="font-mono text-cyan-300">{techniqueId || 'N/A'}</span>
                                <span className="text-slate-200">{' — '}{techniqueName}</span>
                              </div>
                              {tactics.length > 0 && (
                                <div className="mt-2 flex flex-wrap gap-2">
                                  {tactics.map((t, i) => (
                                    <span key={`tactic-${idx}-${i}`} className="px-2 py-0.5 rounded text-xs font-semibold bg-slate-700 text-slate-100 border border-slate-600">
                                      {t}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>
                          </div>

                          {evidenceRefs.length > 0 && (
                            <div className="mt-3">
                              <div className="text-sm text-slate-400 mb-1">Evidence (by function)</div>
                              <div className="space-y-2">
                                {evidenceRefs.slice(0, 6).map((ref, ridx) => (
                                  <div key={`ev-${idx}-${ridx}`} className="bg-slate-900/40 border border-slate-700 rounded p-2">
                                    <div className="text-xs text-slate-300">
                                      <span className="text-slate-400">Function: </span>
                                      <span className="font-mono text-emerald-300 break-all">{ref?.function_name || 'N/A'}</span>
                                    </div>
                                    {ref?.evidence && (
                                      <div className="text-xs text-slate-200 mt-1 leading-relaxed break-words">
                                        {String(ref.evidence)}
                                      </div>
                                    )}
                                  </div>
                                ))}
                                {evidenceRefs.length > 6 && (
                                  <div className="text-xs text-slate-400">
                                    Showing 6/{evidenceRefs.length} evidence items.
                                  </div>
                                )}
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* 2.2 Extracted IOCs */}
            {malwareReport.extracted_iocs && (
              <div className="bg-slate-700/50 p-4 rounded border-l-4 border-sky-500">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <h3 className="font-bold text-lg text-white">Extracted IOCs</h3>
                    <span className="text-xs text-slate-300 bg-slate-800/60 border border-slate-700 px-2 py-0.5 rounded">
                      {extractedIocCount}
                    </span>
                  </div>
                  {renderChevronButton(
                    iocsOpen,
                    () => setIocsOpen(!iocsOpen),
                    'Collapse extracted IOCs',
                    'Expand extracted IOCs'
                  )}
                </div>

                {iocsOpen && (
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                    {renderIocGroup('Domains', malwareReport.extracted_iocs.domains)}
                    {renderIocGroup('IPs', malwareReport.extracted_iocs.ips)}
                    {renderIocGroup('URLs', malwareReport.extracted_iocs.urls)}
                    {renderIocGroup('File Paths', malwareReport.extracted_iocs.file_paths)}
                    {renderIocGroup('Registry Keys', malwareReport.extracted_iocs.registry_keys)}
                    {renderIocGroup('Mutexes', malwareReport.extracted_iocs.mutexes)}
                    {renderIocGroup('Process Names', malwareReport.extracted_iocs.process_names)}
                    {renderIocGroup('Service Names', malwareReport.extracted_iocs.service_names)}
                    {!hasAnyIocs(malwareReport.extracted_iocs) && (
                      <div className="lg:col-span-2 text-slate-400 text-sm italic">
                        No IOCs extracted.
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {malwareReport.malicious_functions && malwareReport.malicious_functions.length > 0 && (
              <div className="bg-slate-700/50 p-4 rounded border-l-4 border-rose-500">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <h3 className="font-bold text-lg text-white">Malicious Functions</h3>
                    <span className="text-xs text-slate-300 bg-slate-800/60 border border-slate-700 px-2 py-0.5 rounded">
                      {malwareReport.malicious_functions.length}
                    </span>
                  </div>
                  {renderChevronButton(
                    maliciousOpen,
                    () => setMaliciousOpen(!maliciousOpen),
                    'Collapse malicious functions',
                    'Expand malicious functions'
                  )}
                </div>

                {maliciousOpen && (
                  <div className="space-y-3">
                    {malwareReport.malicious_functions.map((fn, idx) => (
                      <div key={`${fn.name}-${idx}`} className="bg-slate-800 p-3 rounded border border-slate-700 flex items-start justify-between">
                        <div className="min-w-0">
                          <div className="text-sm text-slate-400">{fn.name}</div>
                          <div className="text-sm text-slate-200 mt-1">{fn.reason}</div>
                        </div>
                        <div className="ml-4 flex-shrink-0">
                          <span className={`px-3 py-1 rounded text-xs font-bold uppercase ${getSeverityBadgeClass(fn.severity)}`}>
                            {fn.severity}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        ) : (
          <p className="text-slate-400 italic">No malware analysis report generated yet.</p>
        )}
      </div>
    </div>
  );
};

export default ReportView;
