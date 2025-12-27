'use client';

import { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://51.20.8.177';

interface ScanSummary {
    scan_id: string;
    status: string;
    message: string;
    progress: number;
}

export default function HistoryPage() {
    const [scans, setScans] = useState<ScanSummary[]>([]);
    const [loading, setLoading] = useState(true);

    const fetchScans = async () => {
        try {
            const res = await fetch(`${API_BASE}/api/live/live`);
            if (res.ok) {
                const data = await res.json();
                setScans(data.scans || []);
            }
        } catch (err) {
            console.error('Failed to fetch scans:', err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchScans();
    }, []);

    const onRefresh = useCallback(() => {
        setLoading(true);
        fetchScans();
    }, []);

    const getStatusColor = (status: string) => {
        switch (status) {
            case 'complete': return '#22c55e';
            case 'failed': return '#ef4444';
            case 'scanning':
            case 'vuln_check':
            case 'analyzing': return '#06b6d4';
            default: return '#6b7280';
        }
    };

    const downloadReport = (scanId: string, format: string) => {
        window.open(`${API_BASE}/api/reports/download/${scanId}/${format}`, '_blank');
    };

    const deleteScan = async (scanId: string) => {
        if (!confirm('Delete this scan? This cannot be undone.')) return;

        try {
            const res = await fetch(`${API_BASE}/api/live/live/${scanId}`, {
                method: 'DELETE'
            });
            if (res.ok) {
                setScans(scans.filter(s => s.scan_id !== scanId));
            }
        } catch (err) {
            console.error('Failed to delete scan:', err);
        }
    };

    const deleteAllScans = async () => {
        if (!confirm('Delete ALL scans? This cannot be undone.')) return;

        try {
            const res = await fetch(`${API_BASE}/api/live/live`, {
                method: 'DELETE'
            });
            if (res.ok) {
                setScans([]);
            }
        } catch (err) {
            console.error('Failed to delete scans:', err);
        }
    };

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
                            <h1 className="text-xl font-bold text-white">Network Vulnerability scanner tool with integrated Ai Driven Threat intelligence</h1>
                            <p className="text-xs text-slate-400">Scan History</p>
                        </div>
                    </div>

                    <nav className="flex items-center gap-4">
                        <Link href="/" className="px-3 py-2 text-slate-300 hover:text-white hover:bg-slate-700 rounded-lg text-sm">
                            Scanner
                        </Link>
                        <Link href="/history" className="px-3 py-2 text-white bg-cyan-600 rounded-lg text-sm font-medium">
                            History
                        </Link>
                    </nav>
                </div>
            </header>

            <main className="max-w-7xl mx-auto px-4 py-8">
                <div className="mb-6 flex items-center justify-between">
                    <h2 className="text-2xl font-bold text-white">📋 Scan History</h2>
                    <div className="flex items-center gap-2">
                        {scans.length > 0 && (
                            <button
                                onClick={deleteAllScans}
                                className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg text-sm"
                            >
                                🗑️ Delete All
                            </button>
                        )}
                        <button
                            onClick={onRefresh}
                            disabled={loading}
                            className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg text-sm disabled:opacity-50"
                        >
                            🔄 Refresh
                        </button>
                    </div>
                </div>

                {loading ? (
                    <div className="text-center py-16">
                        <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto"></div>
                        <p className="text-slate-400 mt-4">Loading scans...</p>
                    </div>
                ) : scans.length === 0 ? (
                    <div className="text-center py-16">
                        <div className="text-6xl mb-4">📭</div>
                        <p className="text-slate-400">No scans yet. Start a new scan from the Scanner page.</p>
                        <Link href="/" className="mt-4 inline-block px-6 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg">
                            Start Scanning
                        </Link>
                    </div>
                ) : (
                    <div className="space-y-4">
                        {scans.map((scan) => (
                            <div
                                key={scan.scan_id}
                                className="bg-slate-800/50 rounded-xl border border-slate-700 p-4"
                            >
                                <div className="flex items-center justify-between">
                                    <div className="flex items-center gap-4">
                                        <div
                                            className="w-3 h-3 rounded-full"
                                            style={{ backgroundColor: getStatusColor(scan.status) }}
                                        ></div>
                                        <div>
                                            <p className="text-white font-medium font-mono text-sm">{scan.scan_id}</p>
                                            <p className="text-slate-400 text-sm">{scan.message}</p>
                                        </div>
                                    </div>

                                    <div className="flex items-center gap-4">
                                        <span className={`px-3 py-1 rounded-full text-xs font-medium`}
                                            style={{
                                                backgroundColor: getStatusColor(scan.status) + '20',
                                                color: getStatusColor(scan.status)
                                            }}>
                                            {scan.status.toUpperCase()}
                                        </span>

                                        {scan.status === 'complete' && (
                                            <div className="flex items-center gap-2">
                                                {/* View Details Button */}
                                                <Link
                                                    href={`/scan/${scan.scan_id}`}
                                                    className="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-sm font-medium"
                                                >
                                                    View Details
                                                </Link>

                                                {/* Download Buttons */}
                                                <button
                                                    onClick={() => downloadReport(scan.scan_id, 'json')}
                                                    className="px-3 py-1 bg-slate-700 hover:bg-slate-600 text-white rounded text-sm"
                                                >
                                                    JSON
                                                </button>
                                                <button
                                                    onClick={() => downloadReport(scan.scan_id, 'html')}
                                                    className="px-3 py-1 bg-slate-700 hover:bg-slate-600 text-white rounded text-sm"
                                                >
                                                    HTML
                                                </button>
                                                <button
                                                    onClick={() => downloadReport(scan.scan_id, 'pdf')}
                                                    className="px-3 py-1 bg-slate-700 hover:bg-slate-600 text-white rounded text-sm"
                                                >
                                                    PDF
                                                </button>
                                                <button
                                                    onClick={() => deleteScan(scan.scan_id)}
                                                    className="px-3 py-1 bg-red-600 hover:bg-red-500 text-white rounded text-sm"
                                                    title="Delete scan"
                                                >
                                                    🗑️
                                                </button>
                                            </div>
                                        )}

                                        {scan.status !== 'complete' && scan.status !== 'failed' && (
                                            <div className="flex items-center gap-2 text-sm text-slate-400">
                                                <div className="w-4 h-4 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin"></div>
                                                {scan.progress}%
                                            </div>
                                        )}
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </main>
        </div>
    );
}
