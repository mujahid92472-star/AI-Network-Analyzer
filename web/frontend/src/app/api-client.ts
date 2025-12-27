/**
 * API Client for AI Network Analyzer Backend
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://51.20.8.177';

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
}

export interface ScanUploadResponse {
  success: boolean;
  message: string;
  hosts_count: number;
  services_count: number;
  scan_id: string;
}

export interface VulnScanRequest {
  scan_id: string;
  max_cves_per_service?: number;
}

export interface VulnScanResponse {
  success: boolean;
  message: string;
  total_cves: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  results: VulnResult[];
}

export interface VulnResult {
  ip_address: string;
  hostname?: string;
  total_cves: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  vulnerable_services: VulnService[];
}

export interface VulnService {
  port: number;
  protocol: string;
  service_name: string;
  product: string;
  version: string;
  cve_count: number;
  cves: CVE[];
}

export interface CVE {
  cve_id: string;
  description: string;
  severity: string;
  base_score: number;
  in_kev?: boolean;
}

export interface AnalysisRequest {
  scan_id: string;
  use_ai?: boolean;
}

export interface AnalysisResponse {
  success: boolean;
  threat_level: string;
  risk_score: number;
  total_vulnerabilities: number;
  threat_summary?: string;
  executive_summary?: string;
  attack_scenarios: string[];
  remediation_steps: string[];
}

class APIClient {
  private baseUrl: string;

  constructor(baseUrl: string = API_BASE) {
    this.baseUrl = baseUrl;
  }

  async health(): Promise<HealthResponse> {
    const res = await fetch(`${this.baseUrl}/api/health`);
    if (!res.ok) throw new Error('API not available');
    return res.json();
  }

  async uploadScan(file: File): Promise<ScanUploadResponse> {
    const formData = new FormData();
    formData.append('file', file);

    const res = await fetch(`${this.baseUrl}/api/scan/upload`, {
      method: 'POST',
      body: formData,
    });

    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.detail || 'Upload failed');
    }
    return res.json();
  }

  async scanVulnerabilities(request: VulnScanRequest): Promise<VulnScanResponse> {
    const res = await fetch(`${this.baseUrl}/api/vulnerabilities/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });

    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.detail || 'Scan failed');
    }
    return res.json();
  }

  async analyzeThreats(request: AnalysisRequest): Promise<AnalysisResponse> {
    const res = await fetch(`${this.baseUrl}/api/analysis/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });

    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.detail || 'Analysis failed');
    }
    return res.json();
  }
}

export const api = new APIClient();
export default api;
