'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';

const API_BASE = 'http://localhost:8000';

// Severity badge styles - bold colors matching HTML report
const severityBadge: Record<string, string> = {
  CRITICAL: 'bg-red-500 text-white border-red-600',
  HIGH: 'bg-orange-500 text-white border-orange-600',
  MEDIUM: 'bg-yellow-500 text-black border-yellow-600',
  LOW: 'bg-blue-500 text-white border-blue-600',
};

interface ScanStatus {
  scan_id: string;
  status: string;
  message: string;
  progress: number;
  results?: ScanResults;
}

interface ScanResults {
  target: string;
  scanned_at: string;
  summary: {
    hosts_count: number;
    services_count: number;
    total_cves: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
  };
  vulnerabilities: VulnReport[];
  ai_analysis?: AIAnalysis;
  recommendations?: string[];
}

interface VulnReport {
  ip_address: string;
  total_cves: number;
  vulnerable_services: VulnService[];
}

interface VulnService {
  port: number;
  service_name: string;
  product: string;
  cves: CVE[];
}

interface CVE {
  cve_id: string;
  description: string;
  severity: string;
  base_score: number;
  in_kev?: boolean;
}

interface AIAnalysis {
  threat_level: string;
  overall_risk_score: number;
  ai_threat_summary?: string;
  ai_executive_summary?: string;
  ai_attack_scenarios?: string[];
  ai_remediation_steps?: string[];
}

export default function Dashboard() {
  const [target, setTarget] = useState('');
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);
  const [error, setError] = useState('');
  const [isScanning, setIsScanning] = useState(false);

  // Poll for scan status
  useEffect(() => {
    if (!scanId || !isScanning) return;

    const interval = setInterval(async () => {
      try {
        const res = await fetch(`${API_BASE}/api/live/live/${scanId}`);
        if (res.ok) {
          const status: ScanStatus = await res.json();
          setScanStatus(status);

          if (status.status === 'complete' || status.status === 'failed') {
            setIsScanning(false);
          }
        }
      } catch (err) {
        console.error('Status poll error:', err);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [scanId, isScanning]);

  const startScan = async () => {
    if (!target.trim()) {
      setError('Please enter a target IP or hostname');
      return;
    }

    setError('');
    setIsScanning(true);
    setScanStatus(null);

    try {
      const res = await fetch(`${API_BASE}/api/live/live`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target.trim(), max_cves: 20, skip_ai: false }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Scan failed to start');
      }

      const status: ScanStatus = await res.json();
      setScanId(status.scan_id);
      setScanStatus(status);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start scan');
      setIsScanning(false);
    }
  };

  const resetScan = () => {
    setScanId(null);
    setScanStatus(null);
    setError('');
    setIsScanning(false);
  };

  const downloadReport = (format: string) => {
    if (!scanId) return;
    window.open(`${API_BASE}/api/reports/download/${scanId}/${format}`, '_blank');
  };

  // Get all CVEs from results
  const allCVEs: CVE[] = scanStatus?.results?.vulnerabilities?.flatMap(
    v => v.vulnerable_services?.flatMap(s => s.cves || []) || []
  ) || [];

  const results = scanStatus?.results;
  const ai = results?.ai_analysis;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      {/* Header */}
      <header className="border-b border-slate-700 bg-slate-900/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-lg flex items-center justify-center">
              <span className="text-xl">🛡️</span>
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">AI Network Analyzer</h1>
              <p className="text-xs text-slate-400">Live Vulnerability Scanner</p>
            </div>
          </div>

          <nav className="flex items-center gap-4">
            <Link href="/" className="px-3 py-2 text-white bg-cyan-600 rounded-lg text-sm font-medium">
              Scanner
            </Link>
            <Link href="/history" className="px-3 py-2 text-slate-300 hover:text-white hover:bg-slate-700 rounded-lg text-sm">
              History
            </Link>
            {(scanId || scanStatus) && (
              <button
                onClick={resetScan}
                className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-colors text-sm"
              >
                New Scan
              </button>
            )}
          </nav>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-8">
        {/* Error Display */}
        {error && (
          <div className="mb-6 p-4 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400">
            ⚠️ {error}
          </div>
        )}

        {/* Scan Input */}
        {!scanId && !isScanning && (
          <div className="max-w-2xl mx-auto">
            <div className="text-center mb-8">
              <h2 className="text-3xl font-bold text-white mb-2">Start a Security Scan</h2>
              <p className="text-slate-400">Enter a target IP or hostname to scan for vulnerabilities</p>
            </div>

            <div className="bg-slate-800/50 rounded-2xl p-8 border border-slate-700">
              <div className="flex gap-4">
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="e.g., 192.168.1.1 or scanme.nmap.org"
                  className="flex-1 px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                  onKeyDown={(e) => e.key === 'Enter' && startScan()}
                />
                <button
                  onClick={startScan}
                  className="px-8 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold rounded-lg transition-all transform hover:scale-105"
                >
                  🔍 Scan
                </button>
              </div>

              <div className="mt-6 text-sm text-slate-400">
                <p className="font-medium text-slate-300 mb-2">What this will do:</p>
                <ul className="space-y-1 ml-4">
                  <li>• Run nmap service detection on the target</li>
                  <li>• Query NVD database for known vulnerabilities (CVEs)</li>
                  <li>• Perform AI-powered threat analysis</li>
                  <li>• Generate downloadable reports</li>
                </ul>
              </div>
            </div>
          </div>
        )}

        {/* Scanning Progress */}
        {isScanning && scanStatus && (
          <div className="max-w-2xl mx-auto text-center">
            <div className="bg-slate-800/50 rounded-2xl p-8 border border-slate-700">
              <div className="w-20 h-20 mx-auto mb-6 relative">
                <div className="absolute inset-0 border-4 border-slate-700 rounded-full"></div>
                <div
                  className="absolute inset-0 border-4 border-cyan-500 rounded-full animate-spin"
                  style={{ borderTopColor: 'transparent', animationDuration: '1.5s' }}
                ></div>
                <div className="absolute inset-0 flex items-center justify-center text-2xl font-bold text-white">
                  {scanStatus.progress}%
                </div>
              </div>

              <h3 className="text-xl font-bold text-white mb-2">
                {scanStatus.status === 'scanning' && '🔍 Detecting Services...'}
                {scanStatus.status === 'vuln_check' && '🔒 Checking CVEs...'}
                {scanStatus.status === 'analyzing' && '🤖 AI Analysis...'}
                {scanStatus.status === 'pending' && '⏳ Starting scan...'}
              </h3>
              <p className="text-slate-400">{scanStatus.message}</p>

              <div className="mt-6 w-full bg-slate-700 rounded-full h-2">
                <div
                  className="bg-gradient-to-r from-cyan-500 to-blue-600 h-2 rounded-full transition-all duration-500"
                  style={{ width: `${scanStatus.progress}%` }}
                ></div>
              </div>
            </div>
          </div>
        )}

        {/* Results */}
        {scanStatus?.status === 'complete' && results && (
          <div className="space-y-6">
            {/* Download Buttons */}
            <div className="flex items-center justify-between">
              <h2 className="text-2xl font-bold text-white">
                Scan Results: {results.target}
              </h2>
              <div className="flex gap-2">
                <button
                  onClick={() => downloadReport('json')}
                  className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg text-sm flex items-center gap-2"
                >
                  📥 JSON
                </button>
                <button
                  onClick={() => downloadReport('html')}
                  className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg text-sm flex items-center gap-2"
                >
                  📄 HTML
                </button>
                <button
                  onClick={() => downloadReport('pdf')}
                  className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg text-sm flex items-center gap-2"
                >
                  📑 PDF
                </button>
              </div>
            </div>

            {/* Summary Cards */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <StatCard label="Total CVEs" value={results.summary.total_cves} color="text-white" />
              <StatCard label="Critical" value={results.summary.critical_count} color="text-red-500" />
              <StatCard label="High" value={results.summary.high_count} color="text-orange-500" />
              <StatCard label="Medium" value={results.summary.medium_count} color="text-yellow-500" />
              <StatCard label="Low" value={results.summary.low_count} color="text-blue-500" />
            </div>

            {/* AI Analysis */}
            {ai && (
              <div className="bg-gradient-to-r from-purple-900/30 to-blue-900/30 rounded-xl border border-purple-500/30 p-6">
                <div className="flex items-center gap-2 mb-4">
                  <span className="text-2xl">🤖</span>
                  <h2 className="text-xl font-bold text-white">AI Threat Analysis</h2>
                  <span className={`ml-auto px-3 py-1 rounded-full text-sm font-medium ${ai.threat_level === 'CRITICAL' ? 'bg-red-500 text-white' :
                    ai.threat_level === 'HIGH' ? 'bg-orange-500 text-white' :
                      ai.threat_level === 'MEDIUM' ? 'bg-yellow-500 text-black' :
                        'bg-green-500 text-white'
                    }`}>
                    {ai.threat_level} RISK ({ai.overall_risk_score?.toFixed(0)}/100)
                  </span>
                </div>

                {ai.ai_threat_summary && (
                  <div className="mb-4 p-4 bg-slate-800/50 rounded-lg">
                    <h3 className="text-sm font-medium text-slate-400 mb-2">Threat Summary</h3>
                    <p className="text-slate-200" dangerouslySetInnerHTML={{
                      __html: ai.ai_threat_summary.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
                    }}></p>
                  </div>
                )}

                {ai.ai_executive_summary && (
                  <div className="mb-4 p-4 bg-cyan-900/30 border border-cyan-500/20 rounded-lg">
                    <h3 className="text-sm font-medium text-cyan-400 mb-2">📋 Executive Summary</h3>
                    <p className="text-slate-200" dangerouslySetInnerHTML={{
                      __html: ai.ai_executive_summary.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
                    }}></p>
                  </div>
                )}

                {ai.ai_attack_scenarios && ai.ai_attack_scenarios.length > 0 && (
                  <div className="mb-4">
                    <h3 className="text-sm font-medium text-slate-400 mb-2">⚔️ Attack Scenarios</h3>
                    <ul className="space-y-2">
                      {ai.ai_attack_scenarios.slice(0, 5).map((scenario, i) => (
                        <li key={i} className="p-3 bg-red-900/20 border border-red-500/20 rounded-lg text-sm text-slate-300"
                          dangerouslySetInnerHTML={{ __html: scenario.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>') }}>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {ai.ai_remediation_steps && ai.ai_remediation_steps.length > 0 && (
                  <div>
                    <h3 className="text-sm font-medium text-slate-400 mb-2">🔧 Remediation Steps</h3>
                    <ul className="space-y-1">
                      {ai.ai_remediation_steps.slice(0, 7).map((step, i) => (
                        <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                          <span className="text-green-500 mt-0.5">✓</span>
                          <span dangerouslySetInnerHTML={{ __html: step.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>') }}></span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}

            {/* Recommendations Section */}
            {results.recommendations && results.recommendations.length > 0 && (
              <div className="bg-gradient-to-r from-green-900/30 to-emerald-900/30 rounded-xl border border-green-500/30 p-6">
                <div className="flex items-center gap-2 mb-4">
                  <span className="text-2xl">💡</span>
                  <h2 className="text-xl font-bold text-white">Recommendations</h2>
                </div>
                <ul className="space-y-2">
                  {results.recommendations.map((rec, i) => (
                    <li key={i} className="flex items-start gap-3 p-3 bg-slate-800/50 rounded-lg text-slate-300"
                      dangerouslySetInnerHTML={{ __html: rec.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>') }}>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* CVE Table */}
            {allCVEs.length > 0 && (
              <div className="bg-slate-800/50 rounded-xl border border-slate-700 overflow-hidden">
                <div className="px-6 py-4 border-b border-slate-700">
                  <h2 className="text-xl font-bold text-white">🔍 Vulnerabilities ({allCVEs.length})</h2>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead className="bg-slate-900/50">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase">CVE ID</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase">Severity</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase">Score</th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase">Description</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-700">
                      {allCVEs.slice(0, 50).map((cve, i) => (
                        <tr key={i} className="hover:bg-slate-700/30">
                          <td className="px-6 py-4">
                            <a
                              href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-cyan-400 hover:text-cyan-300 font-medium"
                            >
                              {cve.cve_id}
                            </a>
                            {cve.in_kev && (
                              <span className="ml-2 px-2 py-0.5 bg-red-500 text-white text-xs rounded-full">🔥 KEV</span>
                            )}
                          </td>
                          <td className="px-6 py-4">
                            <span className={`px-2 py-1 rounded-md text-xs font-medium border ${severityBadge[cve.severity] || severityBadge['LOW']}`}>
                              {cve.severity || 'N/A'}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-slate-300">{cve.base_score?.toFixed(1) || 'N/A'}</td>
                          <td className="px-6 py-4 text-slate-400 text-sm max-w-md truncate">
                            {cve.description?.slice(0, 100)}...
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Failed Scan */}
        {scanStatus?.status === 'failed' && (
          <div className="max-w-2xl mx-auto text-center">
            <div className="bg-red-500/10 rounded-2xl p-8 border border-red-500/30">
              <div className="text-6xl mb-4">❌</div>
              <h3 className="text-xl font-bold text-white mb-2">Scan Failed</h3>
              <p className="text-slate-400">{scanStatus.message}</p>
              <button onClick={resetScan} className="mt-6 px-6 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg">
                Try Again
              </button>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="bg-slate-800/50 rounded-xl border border-slate-700 p-4 text-center">
      <div className={`text-3xl font-bold ${color}`}>{value}</div>
      <div className="text-sm text-slate-400">{label}</div>
    </div>
  );
}
