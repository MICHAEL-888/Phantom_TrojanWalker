import React from 'react';
import ReactMarkdown from 'react-markdown';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

const ReportView = ({ report }) => {
  if (!report) return null;

  return (
    <div className="space-y-4">
      <div className="bg-slate-800 p-6 rounded-lg shadow-lg border border-slate-700">
        <h2 className="text-2xl font-bold mb-4 text-emerald-400">Analysis Summary</h2>
        <div className="prose prose-invert max-w-none">
          <ReactMarkdown
            components={{
              code({node, inline, className, children, ...props}) {
                const match = /language-(\w+)/.exec(className || '')
                return !inline && match ? (
                  <SyntaxHighlighter
                    {...props}
                    children={String(children).replace(/\n$/, '')}
                    style={vscDarkPlus}
                    language={match[1]}
                    PreTag="div"
                  />
                ) : (
                  <code {...props} className={className}>
                    {children}
                  </code>
                )
              }
            }}
          >
            {report.summary || "No summary available."}
          </ReactMarkdown>
        </div>
      </div>

      <div className="bg-slate-800 p-6 rounded-lg shadow-lg border border-slate-700">
        <h2 className="text-2xl font-bold mb-4 text-emerald-400">Function Details</h2>
        {report.functions && report.functions.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {report.functions.map((func, idx) => (
              <div key={idx} className="bg-slate-700 p-4 rounded border border-slate-600">
                <h3 className="text-lg font-semibold text-blue-300">{func.name}</h3>
                <div className="text-sm text-slate-300 mt-2">
                   <ReactMarkdown>{func.analysis}</ReactMarkdown>
                </div>
              </div>
            ))}
          </div>
        ) : (
            <p>No function details available.</p>
        )}
      </div>
    </div>
  );
};

export default ReportView;
