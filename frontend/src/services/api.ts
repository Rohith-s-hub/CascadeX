// frontend/src/services/api.ts
// Updated to match rewritten backend API

const API_BASE_URL = '/api/simulation';

// ═══════════════════════════════════════════════════════════════
// INTERFACES
// ═══════════════════════════════════════════════════════════════

export interface NodeStatus {
  id: string;
  name: string;
  cve_id?: string;
  type: string;
  node_type?: string;
  stability?: number;
  risk: number;
  connections: any[];
  connection_count?: number;
  status: "operational" | "warning" | "critical" | "elevated" | "not_applicable" | "exploited" | "mitigated";
  cvss_score?: number | null;
  severity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | null;
  exploit_available?: boolean;
  exploit_maturity?: string;
  exploit_confidence?: number;
  exploit_sources?: string[];
  patch_available?: boolean;
  patch_confidence?: number;
  description?: string;
  attack_vector?: string;
  attack_complexity?: string;
  privileges_required?: string;
  user_interaction?: string;
  affected_products?: string[];
  affected_vendors?: string[];
  cwe_ids?: string[];
  published_date?: string;
  last_modified_date?: string;
  // Intelligence fields
  attack_stage?: string;
  stage_confidence?: number;
  stage_reasons?: string[];
  is_entry_point?: boolean;
  // Asset matching
  asset_matches?: any[];
  asset_match_count?: number;
  has_asset_match?: boolean;
  relevance_score?: number;
  // Risk factors
  risk_factors?: Record<string, any>;
  risk_explanation?: string[];
  evidence_summary?: Record<string, any>;
  // Time to exploit
  time_to_exploit?: {
    estimate: string;
    confidence: number;
    factors: string[];
  };
  // CISA KEV
  cisa_kev?: boolean;
}

export interface ScanParams {
  keywords?: string[];
  severity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "";
  days_back?: number;
  max_results?: number;
  include_infrastructure?: boolean;
}

export interface ScanResponse {
  success: boolean;
  scan_id?: number;
  total_found?: number;
  total_processed?: number;
  vulnerabilities: NodeStatus[];
  nodes?: NodeStatus[];  // backward compatibility
  attack_chains?: any[];
  timeline?: Record<string, number[]>;
  risk_propagation?: any[];
  analytics?: Record<string, any>;
  system_status?: Record<string, any>;
  prioritized_actions?: any[];
  scan_metadata?: {
    duration_seconds: number;
    total_fetched: number;
    passed_validation: number;
    filtered_count: number;
    future_cves_rejected: number;
    saved_to_db: number;
    asset_context_available: boolean;
    asset_count: number;
  };
  stats?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  duration_seconds?: number;
  error?: string;
}

export interface MitigationResponse {
  success: boolean;
  message?: string;
  mitigation_id?: number;
  cve_id?: string;
  action?: string;
  risk_reduction?: number;
  new_status?: string;
  applied_at?: string;
  error?: string;
}

export interface StatsResponse {
  total_cves: number;
  total_assets?: number;
  by_severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  by_status: {
    critical?: number;
    warning?: number;
    exploited?: number;
    mitigated: number;
    active?: number;
    not_applicable?: number;
  };
  exploit_available: number;
  patch_available: number;
  active_vulnerabilities?: number;
  recent_scans: Array<{
    id: number;
    started_at?: string;
    date?: string;
    total_found: number;
    duration_seconds?: number;
    duration?: number;
    severity_filter?: string;
  }>;
  last_scan?: string | null;
}

export interface MitreMapping {
  tactics: Array<{
    id: string;
    name: string;
    count?: number;
  }>;
  techniques: Array<{
    id: string;
    name: string;
    confidence: number;
    is_subtechnique?: boolean;
    tactics?: string[];
  }>;
  overall_confidence: number;
  mapping_methods: string[];
  evidence: any[];
  technique_count: number;
  tactic_count: number;
}

export interface MitreCoverage {
  vulnerabilities_analyzed: number;
  covered_tactics: any[];
  uncovered_tactics: any[];
  coverage_percentage: number;
  technique_distribution: Record<string, number>;
  most_common_tactics: any[];
  total_techniques_mapped: number;
  gaps: string[];
}

export interface ComplianceAssessment {
  success: boolean;
  frameworks?: Record<string, any>;
  overall_score?: number;
  findings?: any[];
  error?: string;
}

export interface TrendingData {
  success: boolean;
  snapshots?: any[];
  trend?: string;
  error?: string;
}

export interface AlertData {
  count: number;
  alerts: Array<{
    id: number;
    type: string;
    message: string;
    severity: string;
    acknowledged: boolean;
    created_at: string;
  }>;
}

// ═══════════════════════════════════════════════════════════════
// API SERVICE CLASS
// ═══════════════════════════════════════════════════════════════

class CVEApiService {
  private baseUrl: string;

  constructor() {
    this.baseUrl = API_BASE_URL;
  }

  // ─────────────────────────────────────────────────────────
  // HEALTH CHECK
  // ─────────────────────────────────────────────────────────

  async healthCheck(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/health/`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  async getHealthDetails(): Promise<any> {
    try {
      const response = await fetch(`${this.baseUrl}/health/`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      });
      if (!response.ok) return null;
      return await response.json();
    } catch {
      return null;
    }
  }

  // ─────────────────────────────────────────────────────────
  // CVE SCANNING
  // ─────────────────────────────────────────────────────────

  async scanCVEs(params: ScanParams = {}): Promise<ScanResponse> {
    try {
      const response = await fetch(`${this.baseUrl}/scan/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          keywords: params.keywords || [],
          severity: params.severity || '',
          days_back: params.days_back || 30,
          max_results: params.max_results || 50,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        return {
          success: false,
          vulnerabilities: [],
          nodes: [],
          error: data.error || `HTTP ${response.status}`,
        };
      }

      // Normalize response: backend returns 'vulnerabilities', 
      // but frontend might expect 'nodes'
      const nodes = data.vulnerabilities || data.nodes || [];

      return {
        ...data,
        success: true,
        vulnerabilities: nodes,
        nodes: nodes,  // backward compatibility
        total_found: nodes.length,
      };
    } catch (error) {
      console.error('Failed to scan CVEs:', error);
      return {
        success: false,
        vulnerabilities: [],
        nodes: [],
        error: error instanceof Error ? error.message : 'Network error - is the backend running?',
      };
    }
  }

  // ─────────────────────────────────────────────────────────
  // CASCADE NODES
  // ─────────────────────────────────────────────────────────

  async getCascadeNodes(params: {
    severity?: string;
    limit?: number;
    include_infrastructure?: boolean;
  } = {}): Promise<{
    nodes: NodeStatus[];
    count: number;
    attack_chains?: any[];
    timeline?: Record<string, number[]>;
    risk_propagation?: any[];
    analytics?: Record<string, any>;
    system_status?: Record<string, any>;
    prioritized_actions?: any[];
  }> {
    try {
      const queryParams = new URLSearchParams();
      if (params.severity) queryParams.append('severity', params.severity);
      if (params.limit) queryParams.append('limit', params.limit.toString());
      if (params.include_infrastructure !== undefined) {
        queryParams.append(
          'include_infrastructure',
          params.include_infrastructure.toString()
        );
      }

      const url = `${this.baseUrl}/cascade/nodes/?${queryParams.toString()}`;
      const response = await fetch(url);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const data = await response.json();
      
      return {
        nodes: data.nodes || [],
        count: data.count || 0,
        attack_chains: data.attack_chains || [],
        timeline: data.timeline || {},
        risk_propagation: data.risk_propagation || [],
        analytics: data.analytics || {},
        system_status: data.system_status || {},
        prioritized_actions: data.prioritized_actions || [],
      };
    } catch (error) {
      console.error('Failed to get cascade nodes:', error);
      return { nodes: [], count: 0 };
    }
  }

  // ─────────────────────────────────────────────────────────
  // CVE LIST & DETAIL
  // ─────────────────────────────────────────────────────────

  async getCVEList(params: {
    severity?: string;
    status?: string;
    limit?: number;
    offset?: number;
  } = {}): Promise<{ cves: any[]; count: number; total: number }> {
    try {
      const queryParams = new URLSearchParams();
      if (params.severity) queryParams.append('severity', params.severity);
      if (params.status) queryParams.append('status', params.status);
      if (params.limit) queryParams.append('limit', params.limit.toString());
      if (params.offset) queryParams.append('offset', params.offset.toString());

      const response = await fetch(`${this.baseUrl}/cves/?${queryParams.toString()}`);

      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } catch (error) {
      console.error('Failed to get CVE list:', error);
      return { cves: [], count: 0, total: 0 };
    }
  }

  async getCVEDetail(cveId: string): Promise<any | null> {
    try {
      const response = await fetch(`${this.baseUrl}/cves/${cveId}/`);

      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } catch (error) {
      console.error('Failed to get CVE detail:', error);
      return null;
    }
  }

  // ─────────────────────────────────────────────────────────
  // RISK EXPLANATION
  // ─────────────────────────────────────────────────────────

  async getRiskExplanation(cveId: string): Promise<any | null> {
    try {
      const response = await fetch(`${this.baseUrl}/cves/${cveId}/explain/`);

      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } catch (error) {
      console.error('Failed to get risk explanation:', error);
      return null;
    }
  }

  // ─────────────────────────────────────────────────────────
  // MITIGATION
  // ─────────────────────────────────────────────────────────

  async mitigate(cveId: string, action: string, notes?: string): Promise<MitigationResponse> {
    try {
      const response = await fetch(`${this.baseUrl}/mitigate/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          cve_id: cveId,
          action: action,
          notes: notes || '',
        }),
      });

      return await response.json();
    } catch (error) {
      console.error('Failed to mitigate:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Mitigation failed',
      };
    }
  }

  // ─────────────────────────────────────────────────────────
  // STATISTICS
  // ─────────────────────────────────────────────────────────

  async getStats(): Promise<StatsResponse | null> {
    try {
      const response = await fetch(`${this.baseUrl}/stats/`);

      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } catch (error) {
      console.error('Failed to get stats:', error);
      return null;
    }
  }

  // ─────────────────────────────────────────────────────────
  // MITRE ATT&CK
  // ─────────────────────────────────────────────────────────

  async getMitreMapping(cveId: string): Promise<MitreMapping | null> {
    try {
      const response = await fetch(`${this.baseUrl}/mitre/map/${cveId}/`);

      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } catch (error) {
      console.error('Failed to get MITRE mapping:', error);
      return null;
    }
  }

  async getMitreCoverage(limit: number = 200): Promise<MitreCoverage | null> {
    try {
      const response = await fetch(`${this.baseUrl}/mitre/coverage/?limit=${limit}`);

      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } catch (error) {
      console.error('Failed to get MITRE coverage:', error);
      return null;
    }
  }

  // ─────────────────────────────────────────────────────────
  // ASSETS
  // ─────────────────────────────────────────────────────────

  async getAssets(params: {
    criticality?: string;
    internet_facing?: boolean;
    limit?: number;
  } = {}): Promise<{ assets: any[]; count: number; total: number }> {
    try {
      const queryParams = new URLSearchParams();
      if (params.criticality) queryParams.append('criticality', params.criticality);
      if (params.internet_facing !== undefined) {
        queryParams.append('internet_facing', params.internet_facing.toString());
      }
      if (params.limit) queryParams.append('limit', params.limit.toString());

      const response = await fetch(`${this.baseUrl}/assets/?${queryParams.toString()}`);

      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } catch (error) {
      console.error('Failed to get assets:', error);
      return { assets: [], count: 0, total: 0 };
    }
  }

  async getAssetDetail(assetId: string): Promise<any | null> {
    try {
      const response = await fetch(`${this.baseUrl}/assets/${assetId}/`);

      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } catch (error) {
      console.error('Failed to get asset detail:', error);
      return null;
    }
  }

  // ─────────────────────────────────────────────────────────
  // COMPLIANCE (Maps to existing backend endpoints)
  // ─────────────────────────────────────────────────────────

  async getComplianceAssessment(framework?: string): Promise<ComplianceAssessment> {
    try {
      const queryParams = new URLSearchParams();
      if (framework) queryParams.append('framework', framework);

      const response = await fetch(
        `${this.baseUrl}/compliance/?${queryParams.toString()}`
      );

      if (!response.ok) {
        return { success: false, error: `HTTP ${response.status}` };
      }

      return await response.json();
    } catch (error) {
      console.error('Failed to get compliance:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Compliance fetch failed',
      };
    }
  }

  // ─────────────────────────────────────────────────────────
  // TRENDING
  // ─────────────────────────────────────────────────────────

  async getTrendingData(days: number = 30): Promise<TrendingData> {
    try {
      const response = await fetch(`${this.baseUrl}/trending/?days=${days}`);

      if (!response.ok) {
        return { success: false, error: `HTTP ${response.status}` };
      }

      return await response.json();
    } catch (error) {
      console.error('Failed to get trending data:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Trending fetch failed',
      };
    }
  }

  async captureSnapshot(): Promise<any> {
    try {
      const response = await fetch(`${this.baseUrl}/trending/snapshot/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });

      return await response.json();
    } catch (error) {
      console.error('Failed to capture snapshot:', error);
      return { success: false };
    }
  }

  // ─────────────────────────────────────────────────────────
  // ALERTS
  // ─────────────────────────────────────────────────────────

  async getAlerts(params: {
    limit?: number;
    severity?: string;
  } = {}): Promise<AlertData> {
    try {
      const queryParams = new URLSearchParams();
      if (params.limit) queryParams.append('limit', params.limit.toString());
      if (params.severity) queryParams.append('severity', params.severity);

      const response = await fetch(`${this.baseUrl}/alerts/?${queryParams.toString()}`);

      if (!response.ok) {
        return { count: 0, alerts: [] };
      }

      return await response.json();
    } catch (error) {
      console.error('Failed to get alerts:', error);
      return { count: 0, alerts: [] };
    }
  }

  // ─────────────────────────────────────────────────────────
  // MONITOR
  // ─────────────────────────────────────────────────────────

  async getMonitorStatus(): Promise<any> {
    try {
      const response = await fetch(`${this.baseUrl}/monitor/status/`);

      if (!response.ok) return null;
      return await response.json();
    } catch {
      return null;
    }
  }

  async controlMonitor(action: 'start' | 'stop'): Promise<any> {
    try {
      const response = await fetch(`${this.baseUrl}/monitor/control/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action }),
      });

      return await response.json();
    } catch (error) {
      console.error('Failed to control monitor:', error);
      return { success: false };
    }
  }

  // ─────────────────────────────────────────────────────────
  // GENERIC FETCH (for App.tsx compatibility)
  // ─────────────────────────────────────────────────────────

  async fetchEndpoint(path: string, options: RequestInit = {}): Promise<any> {
    try {
      const url = path.startsWith('http')
        ? path
        : `${this.baseUrl}${path}`;

      const response = await fetch(url, {
        headers: { 'Content-Type': 'application/json' },
        ...options,
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error(`API fetch failed for ${path}:`, error);
      return null;
    }
  }
}

// ═══════════════════════════════════════════════════════════════
// EXPORT
// ═══════════════════════════════════════════════════════════════

export const cveApi = new CVEApiService();
export default cveApi;
