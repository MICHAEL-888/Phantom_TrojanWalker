import React from 'react';
import ReactMarkdown from 'react-markdown';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

const ReportView = ({ report }) => {
  if (!report) return null;

  return (
    <div className="space-y-4 text-left">
      {/* 1. Basic Information */}
      <div className="bg-slate-800 p-6 rounded-lg shadow-lg border border-slate-700">
        <h2 className="text-2xl font-bold mb-4 text-emerald-400">File Basic Info</h2>
        {report.metadata && report.metadata.bin ? (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 text-sm">
             <div className="bg-slate-700 p-3 rounded col-span-2">
               <span className="block text-slate-400 text-xs">Filename</span>
               <span className="font-mono text-emerald-300 break-all">{report.filename || 'Unknown'}</span>
             </div>
             <div className="bg-slate-700 p-3 rounded">
               <span className="block text-slate-400 text-xs">Architecture</span>
               <span className="font-mono text-cyan-300">{report.metadata.bin.arch || 'N/A'}</span>
             </div>
             <div className="bg-slate-700 p-3 rounded">
               <span className="block text-slate-400 text-xs">Bits</span>
               <span className="font-mono text-purple-300">{report.metadata.bin.bits || 'N/A'}</span>
             </div>
             <div className="bg-slate-700 p-3 rounded">
               <span className="block text-slate-400 text-xs">Subsystem</span>
               <span className="font-mono text-yellow-300">{report.metadata.bin.subsys || 'N/A'}</span>
             </div>
             <div className="bg-slate-700 p-3 rounded">
               <span className="block text-slate-400 text-xs">Signed</span>
               <span className="font-mono text-blue-300">{report.metadata.bin.signed ? 'Yes' : 'No'}</span>
             </div>
             <div className="bg-slate-700 p-3 rounded">
               <span className="block text-slate-400 text-xs">Compiled At</span>
               <span className="font-mono text-slate-200">{report.metadata.bin.compiled || 'N/A'}</span>
             </div>
             <div className="bg-slate-700 p-3 rounded">
               <span className="block text-slate-400 text-xs">Size</span>
               <span className="font-mono text-slate-200">{report.metadata.core?.humansz || report.metadata.core?.size}</span>
             </div>
             <div className="bg-slate-700 p-3 rounded col-span-2 lg:col-span-4">
               <span className="block text-slate-400 text-xs">SHA256</span>
               <span className="font-mono text-slate-200 break-all text-[10px] sm:text-xs">{report.sha256 || report.metadata.core?.sha256 || 'N/A'}</span>
             </div>
          </div>
        ) : (
          <p className="text-slate-400">No metadata available.</p>
        )}
      </div>

      {/* 2. Analysis Summary (Malware Report) */}
      <div className="bg-slate-800 p-6 rounded-lg shadow-lg border border-slate-700">
        <h2 className="text-2xl font-bold mb-4 text-emerald-400">Analysis Summary</h2>
        {report.malware_report ? (
           <div className="space-y-4">
               <div className="flex space-x-4 mb-4">
                 <span className={`px-3 py-1 rounded text-sm font-bold uppercase ${
                   report.malware_report.risk_level === 'critical' || report.malware_report.risk_level === 'high' 
                   ? 'bg-red-900 text-red-100' 
                   : report.malware_report.risk_level === 'medium' || report.malware_report.risk_level === 'low'
                   ? 'bg-orange-700 text-orange-100'
                   : report.malware_report.risk_level === 'safe'
                   ? 'bg-green-900 text-green-100'
                   : 'bg-slate-700 text-slate-200'
                 }`}>
                   Risk: {report.malware_report.risk_level}
                 </span>
                 <span className="px-3 py-1 rounded text-sm font-bold bg-slate-700 text-slate-200">
                   Type: {report.malware_report.threat_type}
                 </span>
               </div>
               
               <div className="bg-slate-700/50 p-4 rounded border-l-4 border-cyan-500 mb-4">
                 <h3 className="font-bold text-lg text-white mb-1">Variant Identity</h3>
                 <p className="font-mono text-cyan-300">{report.malware_report.malware_name}</p>
               </div>
               
               <div className="bg-slate-700/50 p-4 rounded border-l-4 border-blue-500 mb-4">
                  <h3 className="font-bold text-lg text-white mb-1">Attack Chain Analysis</h3>
                  <p className="text-slate-300 leading-relaxed">{report.malware_report.attack_chain}</p>
               </div>
               
               <div className="bg-slate-700/50 p-4 rounded border-l-4 border-indigo-500 mb-4">
                  <h3 className="font-bold text-lg text-white mb-1">Detailed Reason</h3>
                  <div className="prose prose-invert prose-sm max-w-none">
                    <ReactMarkdown>{report.malware_report.reason}</ReactMarkdown>
                  </div>
               </div>
           </div>
        ) : (
          <p className="text-slate-400 italic">No malware analysis report generated yet.</p>
        )}
      </div>
    </div>
  );
};

export default ReportView;
