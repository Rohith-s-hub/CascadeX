// frontend/src/App.tsx
// @ts-ignore
import { authFetch } from './services/auth';
import { AssetManagerPanel } from './components/AssetManagerPanel';
// @ts-ignore
import { useAuth } from './services/AuthContext';
import {
  lazy,
  Suspense,
  useState,
  useEffect,
  useMemo,
  useCallback,
  useRef,
  type ReactNode,
} from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Line } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  RadialLinearScale,
  Title,
  Tooltip,
  Legend,
  Filler,
} from "chart.js";
import {
  Activity,
  Shield,
  RotateCcw,
  Network,
  Download,
  AlertCircle,
  Info,
  ArrowRight,
  Gauge,
  ShieldAlert,
  ShieldCheck,
  Bug,
  Skull,
  ScanLine,
  RefreshCw,
  Wifi,
  Search,
  AlertTriangle,
  ArrowUpRight,
  ArrowDownRight,
  Maximize2,
  Minimize2,
  Check,
  Copy,
  Timer,
  Bell,
  BellRing,
  TrendingUp,
  TrendingDown,
  Slack,
  Radio,
  Radar as RadarIcon,
  Building2,
  Landmark,
  FileCheck,
  Send,
  Webhook,
  MessageSquare,
  TicketCheck,
  Siren,
  History,
  Camera,
  LineChart,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  Eye,
  Crosshair,
  Terminal,
  Globe,
  Server,
  Database,
  Zap,
  LogOut,
  UserCircle,
  ExternalLink,
  X,
} from "lucide-react";

const InfrastructureGraph = lazy(() => import("./components/InfrastructureGraph"));

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  RadialLinearScale,
  Title,
  Tooltip,
  Legend,
  Filler
);

// ═══════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════

interface Asset {
  id: string;
  name: string;
  type:
    | "os"
    | "service"
    | "framework"
    | "application"
    | "database"
    | "network_device";
  vendor: string;
  product: string;
  version: string;
  exposure: "internet" | "dmz" | "internal" | "isolated";
  criticality: "critical" | "high" | "medium" | "low";
  tags: string[];
}

interface AssetMatch {
  asset_id: string;
  asset_name: string;
  match_type:
    | "exact_version"
    | "product_match"
    | "vendor_match"
    | "tag_match";
  confidence: number;
  matched_on: string;
}

interface ExploitIntelligence {
  available: boolean;
  confidence: number;
  sources: (
    | "exploitdb"
    | "github_poc"
    | "metasploit"
    | "nuclei"
    | "vendor_advisory"
    | "unknown"
  )[];
  maturity: "weaponized" | "poc" | "theoretical" | "none";
}

interface PatchIntelligence {
  available: boolean;
  confidence: number;
  sources: string[];
  workaround_available: boolean;
  vendor_response:
    | "patched"
    | "acknowledged"
    | "no_response"
    | "wont_fix"
    | "unknown";
}

interface RiskFactors {
  cvss_component: number;
  exploitability: number;
  exposure: number;
  asset_value: number;
  chain_amplification: number;
  raw_total: number;
  final_score: number;
  breakdown: string[];
}

interface CVEConnection {
  target: string;
  score: number;
  strength: "strong" | "medium" | "weak";
  reasons: string[];
  chain_viable: boolean;
}

interface TimeToExploit {
  estimate: "minutes" | "hours" | "days" | "weeks" | "unknown";
  confidence: number;
  factors: string[];
}

interface ComplianceImpact {
  framework: string;
  framework_key: string;
  control_id: string;
  control_name: string;
  control_description: string;
  impact: string;
  impact_score?: number;
  match_reason: string;
}

interface CVENode {
  id: string;
  name: string;
  type: string;
  node_type?: string;
  description: string;
  cvss_score: number | null;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | null;
  stability: number;
  risk: number;
  risk_factors: RiskFactors;
  status:
    | "operational"
    | "warning"
    | "critical"
    | "exploited"
    | "mitigated"
    | "irrelevant";
  connections: CVEConnection[];
  connected_ids: string[];
  connection_count: number;
  has_strong_connections: boolean;
  published_date?: string;
  exploit_intel: ExploitIntelligence;
  patch_intel: PatchIntelligence;
  attack_vector?: string;
  attack_complexity?: string;
  privileges_required?: string;
  user_interaction?: string;
  scope?: string;
  cve_id?: string;
  affected_products: string[];
  affected_vendors: string[];
  attack_stage: string;
  stage_confidence: number;
  stage_reasons: string[];
  cwe_ids: string[];
  references: { url: string; source: string; tags: string[] }[];
  asset_matches: AssetMatch[];
  asset_relevant: boolean;
  relevance_score: number;
  time_to_exploit: TimeToExploit;
  priority_rank?: number;
  is_entry_point?: boolean;
  compliance_impacts?: ComplianceImpact[];
  // ── EPSS — Exploit Prediction Scoring System ──────────────
  epss_score?: number | null;
  epss_percentile?: number | null;
  epss_updated_at?: string | null;
  cisa_kev?: boolean;
}

interface AttackChainStep {
  cve_id: string;
  stage: string;
  stage_order: number;
  risk: number;
  cvss: number;
  exploit_available: boolean;
  patch_available: boolean;
  description: string;
  affected_products: string[];
  time_to_exploit: string;
}

interface AttackChain {
  chain_id: string;
  steps: AttackChainStep[];
  length: number;
  chain_risk: number;
  shared_products: string[];
  shared_vendors: string[];
  fully_exploitable: boolean;
  narrative: string;
  impact_summary: string;
  recommended_break_point: string;
  total_time_estimate: string;
}

interface RiskPropagation {
  from: string;
  to: string;
  intensity: number;
  type: "connection" | "attack_chain";
  strength: string;
  reason: string;
  attack_vector: string;
}

interface PrioritizedAction {
  rank: number;
  cve_id: string;
  action: string;
  urgency: "immediate" | "urgent" | "scheduled" | "monitor";
  reason: string;
  impact: string;
  effort: "low" | "medium" | "high";
  risk_reduction: number;
  chains_broken: number;
}

interface SystemStatus {
  overall: "compromised" | "critical" | "at_risk" | "elevated" | "guarded" | "secure";
  reason?: string;
  entry_points: number;
  full_chains: number;
  estimated_compromise: "imminent" | "high" | "medium" | "low";
  top_risks: Array<{
    cve_id: string;
    risk_score: number;
    severity: string;
    exploit_status: string;
  }>;
  attack_surface: string;
  recommendation: string;
  asset_matches_found?: number;
  verified_exploitable?: number;
  critical_count?: number;
  high_count?: number;
  exploitable_count?: number;
  kev_count?: number;
  matched_vulnerabilities?: number;
  unmatched_vulnerabilities?: number;
  data_quality?: string;
  has_asset_inventory?: boolean;
  total_applicable?: number;
}

interface SecurityEvent {
  id: number;
  timestamp: string;
  type: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  message: string;
  cve?: string;
  node?: string;
  details?: string;
  confidence?: number;
}

interface Analytics {
  totalVulnerabilities: number;
  relevantVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  avgCvssScore: number;
  avgRealRisk: number;
  exploitedCount: number;
  patchedCount: number;
  systemHealth: number;
  attackChainCount: number;
  connectedNodes: number;
  isolatedNodes: number;
  patchCoverage: number;
  assetCoverage: number;
}

interface ComplianceAssessmentResult {
  cve_id: string;
  severity?: string;
  base_score?: number;
  compliance_impacts: ComplianceImpact[];
  frameworks_affected: string[];
  total_controls_affected: number;
  compliance_risk: string;
}

interface ComplianceFrameworkControl {
  control_id: string;
  control_name: string;
  description: string;
  weight: number;
  impact_score: number;
  max_possible_score: number;
  degradation_percent: number;
  matched_cve_count: number;
  matched_asset_count: number;
  matched_cves: string[];
  matched_assets: string[];
  severity_breakdown: Record<string, number>;
  match_reasons: string[];
  status: "affected" | "healthy";
}

interface ComplianceFrameworkSummary {
  name: string;
  total_controls: number;
  controls_affected: number;
  controls_healthy?: number;
  compliance_percentage: number;
  status:
    | "compliant"
    | "partially_compliant"
    | "at_risk"
    | "non_compliant";
  affected_cve_count: number;
  affected_asset_count?: number;
  weighted_control_capacity?: number;
  weighted_impact_score?: number;
  degradation_ratio?: number;
  top_controls?: ComplianceFrameworkControl[];
  controls?: ComplianceFrameworkControl[];
  summary_text?: string;
}

interface ComplianceAssessment {
  generated_at?: string;
  results: ComplianceAssessmentResult[];
  framework_summary: Record<string, ComplianceFrameworkSummary>;
  overall_compliance: number;
  top_findings?: {
    cve_id: string;
    severity: string;
    compliance_risk: string;
    frameworks_affected: string[];
    total_controls_affected: number;
    highest_impact_score: number;
  }[];
  total_vulnerabilities?: number;
  data_sources?: {
    vulnerability_count: number;
    frameworks: string[];
    realtime: boolean;
    refreshed_at: string;
    asset_matched_vulnerabilities?: number;
  };
}

interface AlertRecord {
  id: number;
  type: string;
  message: string;
  severity: "critical" | "high" | "medium" | "info";
  acknowledged: boolean;
  created_at: string;
  data?: any;
}

interface TrendDataPoint {
  snapshot_id?: number;
  timestamp: string;
  system_health: number;
  total_cves: number;
  critical: number;
  high: number;
  medium?: number;
  low?: number;
  avg_risk: number;
  entry_points: number;
  assets_scanned?: number;
  asset_matches?: number;
  exploit_count: number;
  trigger?: string;
}

interface TrendingData {
  success?: boolean;
  period_days: number;
  data_points: number;
  trend_direction:
    | "improving"
    | "degrading"
    | "stable"
    | "insufficient_data"
    | "no_data";
  latest_health: number | null;
  latest_timestamp?: string | null;
  latest_snapshot_id?: number | null;
  previous_health?: number | null;
  change?: {
    health_change: number;
    total_cves_change: number;
    critical_change: number;
    high_change: number;
    avg_risk_change: number;
    entry_points_change: number;
    exploit_count_change: number;
  } | null;
  trend: TrendDataPoint[];
}

interface ActiveScanHost {
  ip: string;
  hostname: string;
  os: string;
  services: {
    port: number;
    protocol: string;
    service: string;
    product: string;
    version: string;
  }[];
}

interface ActiveScanResult {
  success: boolean;
  scan_id?: string;
  scan_type: string;
  target: string;
  hosts: ActiveScanHost[];
  host_count: number;
  total_services: number;
  vulnerabilities_found: any[];
  vuln_count?: number;
  duration: number;
  assets_saved?: number;
  trend_snapshot?: any;
  error?: string;
}

interface MonitorStatus {
  running: boolean;
  last_check: string | null;
  check_interval: number;
  stats: {
    checks_performed: number;
    new_cves_found: number;
    alerts_sent: number;
    errors: number;
  };
}

interface IntegrationConfigRecord {
  type: "slack" | "jira" | "pagerduty" | "webhook";
  enabled: boolean;
  config: Record<string, string>;
}

// ═══════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "") + "/api/simulation";
const LIVE_REFRESH_INTERVAL = 60000;
const ALERT_POLL_INTERVAL = 60000; // 1 minute
const MONITOR_POLL_INTERVAL = 60000; // 1 minute
const TREND_POLL_INTERVAL = 120000; // 2 minutes
const COMPLIANCE_POLL_INTERVAL = 300000; // 5 minutes
const MAX_EVENTS = 30;

const RISK_WEIGHTS = {
  cvss: 0.35,
  exploitability: 0.25,
  exposure: 0.2,
  asset_value: 0.1,
  chain_amplification: 0.1,
} as const;

const EXPLOIT_MATURITY_SCORES: Record<string, number> = {
  weaponized: 10,
  poc: 7,
  theoretical: 4,
  none: 1,
};

const EXPOSURE_SCORES: Record<string, number> = {
  internet: 10,
  dmz: 7,
  internal: 4,
  isolated: 2,
};

const ASSET_CRITICALITY_SCORES: Record<string, number> = {
  critical: 10,
  high: 8,
  medium: 5,
  low: 2,
};

const STAGE_CONFIG: Record<
  string,
  { label: string; color: string; bg: string; icon: string; order: number }
> = {
  recon: {
    label: "Reconnaissance",
    color: "#8b5cf6",
    bg: "rgba(139,92,246,0.15)",
    icon: "🔍",
    order: 0,
  },
  entry: {
    label: "Initial Access",
    color: "#F59E0B",
    bg: "rgba(245,158,11,0.10)",
    icon: "🚪",
    order: 1,
  },
  persistence: {
    label: "Persistence",
    color: "#F59E0B",
    bg: "rgba(245,158,11,0.10)",
    icon: "🔄",
    order: 2,
  },
  privilege_escalation: {
    label: "Privilege Escalation",
    color: "#6366F1",
    bg: "rgba(99,102,241,0.10)",
    icon: "📈",
    order: 3,
  },
  lateral_movement: {
    label: "Lateral Movement",
    color: "#06b6d4",
    bg: "rgba(6,182,212,0.10)",
    icon: "↔️",
    order: 4,
  },
  code_execution: {
    label: "Code Execution",
    color: "#ef4444",
    bg: "rgba(239,68,68,0.10)",
    icon: "⚡",
    order: 5,
  },
  data_extraction: {
    label: "Data Extraction",
    color: "#8B5CF6",
    bg: "rgba(168,85,247,0.15)",
    icon: "📤",
    order: 6,
  },
  impact: {
    label: "Impact",
    color: "#EF4444",
    bg: "rgba(220,38,38,0.15)",
    icon: "💥",
    order: 7,
  },
  unknown: {
    label: "Unclassified",
    color: "#A1A1AA",
    bg: "rgba(100,116,139,0.15)",
    icon: "❓",
    order: 99,
  },
};

const COMPLIANCE_FRAMEWORKS: Record<
  string,
  { name: string; icon: any; color: string }
> = {
  SOC2: { name: "SOC 2", icon: ShieldCheck, color: "#3b82f6" },
  PCI_DSS: { name: "PCI DSS", icon: Landmark, color: "#8b5cf6" },
  HIPAA: { name: "HIPAA", icon: Building2, color: "#6366F1" },
  NIST_800_53: { name: "NIST 800-53", icon: FileCheck, color: "#22C55E" },
};

const chartColors = {
  blue: "rgb(59,130,246)",
  green: "rgb(34,197,94)",
  yellow: "rgb(234,179,8)",
  red: "rgb(239,68,68)",
  purple: "rgb(168,85,247)",
  cyan: "rgb(6,182,212)",
  orange: "rgb(249,115,22)",
  pink: "rgb(236,72,153)",
};

// ═══════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════

const formatTimestamp = () =>
  new Date().toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

const formatDate = (iso?: string | null) => {
  if (!iso) return "N/A";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "N/A";
  return d.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
};

const safeArray = <T,>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : []);

const safeNumber = (v: any, fallback = 0) =>
  Number.isFinite(Number(v)) ? Number(v) : fallback;

function normalizeAssetRecord(raw: any): Asset {
  const primaryService = safeArray<any>(raw.services)[0] || {};
  const exposure: Asset["exposure"] = raw.internet_facing
    ? "internet"
    : raw.requires_vpn
    ? "isolated"
    : raw.behind_firewall
    ? "internal"
    : "dmz";

  return {
    id: String(raw.id || raw.ip_address || raw.hostname || crypto.randomUUID()),
    name: raw.hostname || raw.ip_address || "Unknown asset",
    type: raw.os_type ? "os" : primaryService.service ? "service" : "application",
    vendor: String(primaryService.vendor || primaryService.product || raw.os_type || "unknown")
      .toLowerCase()
      .replace(/\s+/g, "_"),
    product: String(primaryService.product || raw.os_type || raw.hostname || "unknown")
      .toLowerCase()
      .replace(/\s+/g, "_"),
    version: String(primaryService.version || raw.os_version || ""),
    exposure,
    criticality: (raw.criticality || "medium") as Asset["criticality"],
    tags: [
      raw.environment,
      raw.os_type,
      raw.hostname,
      ...safeArray<any>(raw.services).flatMap((service) => [
        service.service,
        service.product,
        service.version,
      ]),
    ]
      .filter(Boolean)
      .map((value) => String(value)),
  };
}

async function apiFetch<T = any>(
  path: string,
  options?: RequestInit
): Promise<T> {
  const token = localStorage.getItem('cascadex_access');
  const res = await fetch(`${API_BASE_URL}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(token ? { "Authorization": `Bearer ${token}` } : {}),
      ...(options?.headers || {}),
    },
    ...options,
  });

  // Token expired — try refresh once
  if (res.status === 401 && token) {
    const refreshToken = localStorage.getItem('cascadex_refresh');
    if (refreshToken) {
      try {
        const refreshRes = await fetch(`${API_BASE_URL}/auth/token/refresh/`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh: refreshToken }),
        });
        if (refreshRes.ok) {
          const refreshData = await refreshRes.json();
          if (refreshData.tokens?.access) {
            localStorage.setItem('cascadex_access', refreshData.tokens.access);
            // Retry with new token
            const retryRes = await fetch(`${API_BASE_URL}${path}`, {
              headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${refreshData.tokens.access}`,
                ...(options?.headers || {}),
              },
              ...options,
            });
            const retryText = await retryRes.text();
            let retryData: any = {};
            try { retryData = retryText ? JSON.parse(retryText) : {}; } catch { retryData = { raw: retryText }; }
            if (!retryRes.ok) throw new Error(retryData?.error || `HTTP ${retryRes.status}`);
            return retryData as T;
          }
        }
      } catch {}
    }
    // Refresh failed — redirect to login
    localStorage.removeItem('cascadex_access');
    localStorage.removeItem('cascadex_refresh');
    localStorage.removeItem('cascadex_user');
    window.location.href = '/login';
  }

  const text = await res.text();
  let data: any = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { raw: text };
  }

  if (!res.ok) {
    throw new Error(data?.error || data?.message || `HTTP ${res.status}`);
  }

  return data as T;
}

function getFrameworkStatusTone(status: string) {
  switch (status) {
    case "compliant":
      return "bg-[#22C55E]/15 text-[#4ADE80] border-[#22C55E]/25";
    case "partially_compliant":
      return "bg-[#3B82F6]/15 text-[#60A5FA] border-blue-500/40";
    case "at_risk":
      return "bg-[#F59E0B]/15 text-[#FCD34D] border-yellow-500/40";
    default:
      return "bg-[#EF4444]/15 text-[#F87171] border-[#EF4444]/25";
  }
}

// ═══════════════════════════════════════════════════════════════
// FRONTEND INTELLIGENCE
// ═══════════════════════════════════════════════════════════════

function matchCVEToAssets(
  cve: { affected_products: string[]; affected_vendors: string[]; description: string },
  assets: Asset[]
): AssetMatch[] {
  if (assets.length === 0) return [];
  const matches: AssetMatch[] = [];

  for (const asset of assets) {
    const assetKey = `${asset.vendor}:${asset.product}`.toLowerCase();
    const prodLow = asset.product.toLowerCase();
    const vendLow = asset.vendor.toLowerCase();
    const descLow = (cve.description || "").toLowerCase();

    for (const prod of cve.affected_products || []) {
      const pl = prod.toLowerCase();

      if (pl === assetKey) {
        matches.push({
          asset_id: asset.id,
          asset_name: asset.name,
          match_type: "exact_version",
          confidence: 95,
          matched_on: prod,
        });
      } else if (pl.includes(prodLow) && pl.includes(vendLow)) {
        matches.push({
          asset_id: asset.id,
          asset_name: asset.name,
          match_type: "product_match",
          confidence: 80,
          matched_on: prod,
        });
      } else if (prodLow.length > 2 && pl.includes(prodLow)) {
        matches.push({
          asset_id: asset.id,
          asset_name: asset.name,
          match_type: "product_match",
          confidence: 60,
          matched_on: prod,
        });
      }
    }

    if (
      prodLow.length > 2 &&
      descLow.includes(prodLow) &&
      !matches.some((m) => m.asset_id === asset.id)
    ) {
      matches.push({
        asset_id: asset.id,
        asset_name: asset.name,
        match_type: "tag_match",
        confidence: 35,
        matched_on: `description mentions "${asset.product}"`,
      });
    }

    for (const tag of asset.tags || []) {
      if (
        tag.length > 2 &&
        descLow.includes(tag.toLowerCase()) &&
        !matches.some((m) => m.asset_id === asset.id && m.match_type === "tag_match")
      ) {
        matches.push({
          asset_id: asset.id,
          asset_name: asset.name,
          match_type: "tag_match",
          confidence: 25,
          matched_on: `tag: ${tag}`,
        });
      }
    }
  }

  const best = new Map<string, AssetMatch>();
  for (const m of matches) {
    const e = best.get(m.asset_id);
    if (!e || m.confidence > e.confidence) best.set(m.asset_id, m);
  }
  return Array.from(best.values()).sort((a, b) => b.confidence - a.confidence);
}

function buildExploitIntelligence(raw: any): ExploitIntelligence {
  const available = !!raw.exploit_available;
  const refs = safeArray<any>(raw.references);
  const sources: ExploitIntelligence["sources"] = [];
  let maturity: ExploitIntelligence["maturity"] = "none";

  if (available) {
    if (refs.some((r) => (r.url || "").includes("exploit-db"))) {
      sources.push("exploitdb");
    }
    if (
      refs.some(
        (r) =>
          (r.url || "").includes("github.com") &&
          safeArray<string>(r.tags).includes("exploit")
      )
    ) {
      sources.push("github_poc");
    }
    if (
      refs.some(
        (r) => (r.url || "").includes("rapid7") || (r.url || "").includes("metasploit")
      )
    ) {
      sources.push("metasploit");
    }

    if (sources.includes("metasploit")) maturity = "weaponized";
    else if (sources.includes("exploitdb") || sources.includes("github_poc")) maturity = "poc";
    else {
      maturity = "none";
      sources.push("unknown");
    }
  }

  let confidence = 5;
  if (available && maturity === "weaponized") confidence = 95;
  else if (available && maturity === "poc") confidence = 75;
  else if (available) confidence = 30;

  return { available, confidence, sources, maturity };
}

function buildPatchIntelligence(raw: any): PatchIntelligence {
  const available = !!raw.patch_available;
  const desc = (raw.description || "").toLowerCase();
  const sources: string[] = [];
  let workaround = false;
  let vendorResponse: PatchIntelligence["vendor_response"] = "unknown";

  if (available) {
    sources.push("inferred");
    vendorResponse = "patched";
  } else {
    if (desc.includes("vendor was contacted") && desc.includes("did not respond")) {
      vendorResponse = "no_response";
    }
    if (desc.includes("workaround") || desc.includes("mitigat")) {
      workaround = true;
    }
  }

  return {
    available,
    confidence: available ? 70 : 50,
    sources,
    workaround_available: workaround,
    vendor_response: vendorResponse,
  };
}

function estimateTimeToExploit(raw: any, exploitIntel: ExploitIntelligence): TimeToExploit {
  const priv = raw.privileges_required || "";
  const vec = raw.attack_vector || "";
  const complexity = raw.attack_complexity || "";
  const factors: string[] = [];

  if (priv === "NONE" && exploitIntel.available && vec === "NETWORK") {
    factors.push("No auth + public exploit + network");
    return { estimate: "minutes", confidence: 85, factors };
  }
  if (priv === "NONE" && vec === "NETWORK") {
    factors.push("No auth + network accessible");
    return { estimate: "hours", confidence: 70, factors };
  }
  if (priv === "LOW" && exploitIntel.available) {
    factors.push("Low privilege + exploit available");
    return { estimate: "hours", confidence: 65, factors };
  }
  if (complexity === "HIGH") {
    factors.push("High attack complexity");
    return { estimate: "weeks", confidence: 50, factors };
  }
  if (vec === "LOCAL") {
    factors.push("Local access required");
    return { estimate: "days", confidence: 45, factors };
  }

  factors.push("Default estimate");
  return { estimate: "days", confidence: 40, factors };
}

function calculateRiskFactors(
  raw: any,
  exploitIntel: ExploitIntelligence,
  assetMatches: AssetMatch[],
  assets: Asset[],
  chainCount: number
): RiskFactors {
  const breakdown: string[] = [];
  const cvss = typeof raw.cvss_score === "number" ? raw.cvss_score : 5.0;
  breakdown.push(
    `CVSS ${cvss.toFixed(1)} × ${(RISK_WEIGHTS.cvss * 100).toFixed(0)}%`
  );

  const exploitability = EXPLOIT_MATURITY_SCORES[exploitIntel.maturity] || 1;
  breakdown.push(`Exploit "${exploitIntel.maturity}" = ${exploitability}/10`);

  let exposure = 5;
  if (assetMatches.length > 0) {
    const matched = assetMatches
      .map((m) => assets.find((a) => a.id === m.asset_id))
      .filter(Boolean) as Asset[];
    if (matched.length > 0) {
      exposure = Math.max(...matched.map((a) => EXPOSURE_SCORES[a.exposure] || 5));
      breakdown.push(
        `Confirmed exposure: "${matched[0].exposure}" (${matched[0].name}) = ${exposure}/10`
      );
    }
  } else {
    if (raw.attack_vector === "NETWORK") {
      exposure = 6;
      breakdown.push("Inferred network exposure = 6/10");
    } else if (raw.attack_vector === "LOCAL") {
      exposure = 3;
      breakdown.push("Inferred local exposure = 3/10");
    } else {
      exposure = 4;
      breakdown.push("Unknown exposure = 4/10");
    }
  }

  let assetValue = 3;
  if (assetMatches.length > 0) {
    const matched = assetMatches
      .map((m) => assets.find((a) => a.id === m.asset_id))
      .filter(Boolean) as Asset[];
    if (matched.length > 0) {
      assetValue = Math.max(
        ...matched.map((a) => ASSET_CRITICALITY_SCORES[a.criticality] || 5)
      );
    }
  } else if (raw.type === "database") {
    assetValue = 7;
  }
  breakdown.push(`Asset value = ${assetValue}/10`);

  const chainAmp = chainCount > 0 ? Math.min(10, chainCount * 3) : 0;
  breakdown.push(
    chainCount > 0
      ? `Part of ${chainCount} validated chain(s) → ${chainAmp}/10`
      : "Not in any chain → 0/10"
  );

  const rawTotal =
    cvss * RISK_WEIGHTS.cvss * 10 +
    exploitability * RISK_WEIGHTS.exploitability * 10 +
    exposure * RISK_WEIGHTS.exposure * 10 +
    assetValue * RISK_WEIGHTS.asset_value * 10 +
    chainAmp * RISK_WEIGHTS.chain_amplification * 10;

  const finalScore = Math.round(Math.min(100, Math.max(0, rawTotal)));

  return {
    cvss_component: cvss,
    exploitability,
    exposure,
    asset_value: assetValue,
    chain_amplification: chainAmp,
    raw_total: rawTotal,
    final_score: finalScore,
    breakdown,
  };
}

function normalizeNode(raw: any, assets: Asset[], chainCounts: Map<string, number>): CVENode {
  const exploitIntel = raw.exploit_intel || {
    available: !!raw.exploit_available,
    confidence: raw.exploit_confidence || 0,
    sources: safeArray<string>(raw.exploit_sources),
    maturity: raw.exploit_maturity || "unknown",
  };
  const patchIntel = raw.patch_intel || {
    available: !!raw.patch_available,
    confidence: raw.patch_confidence || 0,
    sources: safeArray<string>(raw.patch_sources),
    workaround_available: false,
    vendor_response: raw.patch_available ? "patched" : "unknown",
  };
  const assetMatches =
    safeArray<any>(raw.asset_matches).length > 0
      ? safeArray<any>(raw.asset_matches)
      : matchCVEToAssets(raw, assets);
  const cveId = raw.cve_id || raw.id || `cve-${Math.random().toString(36).slice(2)}`;
  const chainCount = chainCounts.get(cveId) || 0;
  const tte = raw.time_to_exploit || estimateTimeToExploit(raw, exploitIntel);
  const riskFactors =
    raw.risk_factors && typeof raw.risk_factors === "object"
      ? raw.risk_factors
      : calculateRiskFactors(raw, exploitIntel, assetMatches, assets, chainCount);

  const assetRelevant = assetMatches.length > 0;
  const relevanceScore =
    assetMatches.length > 0
      ? Math.max(...assetMatches.map((m) => m.confidence))
      : 0;

  const isEntryPoint =
    typeof raw.is_entry_point === "boolean"
      ? raw.is_entry_point
      : raw.attack_vector === "NETWORK" &&
        (raw.privileges_required === "NONE" || raw.privileges_required === "") &&
        raw.status !== "mitigated";

  let nodeStatus: CVENode["status"] = "warning";
  if (raw.status === "mitigated") nodeStatus = "mitigated";
  else if (raw.status === "not_applicable") nodeStatus = "irrelevant";
  else if (raw.status === "critical") nodeStatus = "critical";
  else if (raw.status === "operational") nodeStatus = "operational";
  else if (exploitIntel.maturity === "weaponized") nodeStatus = "exploited";
  else if (riskFactors.final_score >= 70) nodeStatus = "critical";
  else if (riskFactors.final_score >= 40) nodeStatus = "warning";
  else nodeStatus = "operational";

  const connections: CVEConnection[] = safeArray<any>(raw.connections).map((c) => ({
    target: c.target || "",
    score: c.score || (typeof c.strength === "number" ? c.strength : 0),
    strength:
      typeof c.strength === "string"
        ? c.strength
        : (c.score || c.strength || 0) >= 80
        ? "strong"
        : (c.score || c.strength || 0) >= 60
        ? "medium"
        : "weak",
    reasons: safeArray<string>(c.reasons),
    chain_viable: !!c.chain_viable,
  }));

  return {
    id: cveId,
    name: raw.name || cveId,
    type: raw.type || raw.node_type || "vulnerability",
    node_type: raw.node_type,
    description: raw.description || "No description available",
    cvss_score: typeof raw.cvss_score === "number" ? raw.cvss_score : null,
    severity: raw.severity || null,
    stability:
      typeof raw.stability === "number"
        ? raw.stability
        : Math.max(
            0,
            100 - (typeof raw.risk === "number" ? raw.risk : riskFactors.final_score)
          ),
    risk: typeof raw.risk === "number" ? raw.risk : riskFactors.final_score,
    risk_factors: riskFactors,
    status: nodeStatus,
    connections,
    connected_ids: safeArray<string>(raw.connected_ids),
    connection_count:
      connections.length || safeArray<string>(raw.connected_ids).length,
    has_strong_connections: connections.some((c) => c.strength === "strong"),
    published_date: raw.published_date,
    exploit_intel: exploitIntel,
    patch_intel: patchIntel,
    attack_vector: raw.attack_vector,
    attack_complexity: raw.attack_complexity,
    privileges_required: raw.privileges_required,
    user_interaction: raw.user_interaction,
    scope: raw.scope,
    cve_id: cveId,
    affected_products: safeArray<string>(raw.affected_products),
    affected_vendors: safeArray<string>(raw.affected_vendors),
    attack_stage: raw.attack_stage || "unknown",
    stage_confidence: raw.stage_confidence || 0,
    stage_reasons: safeArray<string>(raw.stage_reasons),
    cwe_ids: safeArray<string>(raw.cwe_ids),
    references: safeArray<any>(raw.references),
    asset_matches: assetMatches,
    asset_relevant: assetRelevant,
    relevance_score:
      typeof raw.relevance_score === "number" ? raw.relevance_score : relevanceScore,
    time_to_exploit: tte,
    is_entry_point: isEntryPoint,
    compliance_impacts: raw.compliance_impacts,
    // ── EPSS passthrough ──────────────────────────────────────
    epss_score: raw.epss_score ?? raw.risk_factors?.epss_score ?? null,
    epss_percentile: raw.epss_percentile ?? raw.risk_factors?.epss_percentile ?? null,
    epss_updated_at: raw.epss_updated_at ?? null,
    cisa_kev: raw.cisa_kev ?? false,
  };
}

function isApplicableNode(node: CVENode): boolean {
  return node.status !== "irrelevant";
}

function isBackendExploitableNode(node: CVENode): boolean {
  return (
    node.exploit_intel.maturity === "weaponized" ||
    node.exploit_intel.maturity === "poc"
  );
}

function buildSecurityEvents(
  nodes: CVENode[],
  chains: AttackChain[],
  sysStatus: SystemStatus
): SecurityEvent[] {
  const applicableNodes = nodes.filter(isApplicableNode);
  const hiddenUnmatchedCount = Math.max(0, nodes.length - applicableNodes.length);
  const events: SecurityEvent[] = [];
  let id = 1;
  const ts = formatTimestamp;

  let systemMessage = `System: ${sysStatus.overall.toUpperCase()} — ${applicableNodes.length} applicable vulnerabilities`;
  if (applicableNodes.length === 0) {
    systemMessage =
      hiddenUnmatchedCount > 0
        ? `System: ${sysStatus.overall.toUpperCase()} — no applicable vulnerabilities`
        : `System: ${sysStatus.overall.toUpperCase()} — no active vulnerabilities`;
  }

  const detailParts = [
    `${sysStatus.entry_points} entry points`,
    `${sysStatus.full_chains} chains`,
  ];
  if (hiddenUnmatchedCount > 0) {
    detailParts.push(`${hiddenUnmatchedCount} unmatched CVEs hidden`);
  }

  events.push({
    id: id++,
    timestamp: ts(),
    type: "scan",
    severity:
      sysStatus.overall === "compromised"
        ? "critical"
        : sysStatus.overall === "critical"
        ? "high"
        : "info",
    message: systemMessage,
    details: detailParts.join(", "),
    confidence: 90,
  });

  for (const chain of chains) {
    events.push({
      id: id++,
      timestamp: ts(),
      type: "chain",
      severity: chain.fully_exploitable ? "critical" : "high",
      message: `Chain: ${chain.steps.map((s) => s.cve_id).join(" → ")}`,
      details: chain.impact_summary,
      confidence: chain.fully_exploitable ? 90 : 60,
    });
  }

  const sorted = [...applicableNodes].sort((a, b) => b.risk - a.risk);
  for (const node of sorted.slice(0, 20)) {
    if (node.status === "mitigated" || node.status === "irrelevant") continue;

    if (node.exploit_intel.available && !node.patch_intel.available) {
      events.push({
        id: id++,
        timestamp: ts(),
        type: "alert",
        severity: "critical",
        message: `Exploitable, no patch: ${node.cve_id} (CVSS ${node.cvss_score?.toFixed(1)})`,
        cve: node.cve_id,
        confidence: node.exploit_intel.confidence,
      });
    } else if (node.patch_intel.available) {
      events.push({
        id: id++,
        timestamp: ts(),
        type: "patch",
        severity: "medium",
        message: `Patch available: ${node.cve_id}`,
        cve: node.cve_id,
        confidence: node.patch_intel.confidence,
      });
    }
  }

  const sevOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };

  return events
    .sort((a, b) => (sevOrder[a.severity] || 4) - (sevOrder[b.severity] || 4))
    .slice(0, MAX_EVENTS);
}

// ═══════════════════════════════════════════════════════════════
// UI COMPONENTS
// ═══════════════════════════════════════════════════════════════

const SectionCard = ({
  title,
  subtitle,
  icon: Icon,
  iconClass = "from-[#3B82F6] to-[#6366F1]",
  actions,
  children,
}: {
  title: string;
  subtitle?: string;
  icon: any;
  iconClass?: string;
  actions?: ReactNode;
  children: ReactNode;
}) => (
  <div className="relative overflow-hidden rounded-2xl border border-white/6 bg-[#0d0d12]/90 p-6 shadow-[0_8px_40px_-12px_rgba(0,0,0,0.5)] backdrop-blur-xl">
    <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,rgba(99,102,241,0.06),transparent_50%),radial-gradient(ellipse_at_bottom_left,rgba(59,130,246,0.04),transparent_50%)]" />
    <div className="flex items-center justify-between gap-4 mb-6">
      <div className="flex items-center gap-3">
        <div className={`h-10 w-10 rounded-xl bg-gradient-to-br ${iconClass} flex items-center justify-center shadow-lg`}>
          <Icon className="h-5 w-5 text-white" />
        </div>
        <div>
          <h2 className="text-lg font-semibold tracking-tight text-white">{title}</h2>
          {subtitle && <p className="text-xs uppercase tracking-[0.18em] text-[#52525B] mt-0.5">{subtitle}</p>}
        </div>
      </div>
      {actions}
    </div>
    <div className="relative">{children}</div>
  </div>
);

const EmptyState = ({
  icon: Icon,
  title,
  description,
  action,
}: {
  icon: any;
  title: string;
  description: string;
  action?: ReactNode;
}) => (
  <div className="rounded-2xl border border-dashed border-white/8 bg-[#09090B]/60 py-14 text-center text-[#52525B]">
    <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl border border-white/10 bg-white/5">
      <Icon className="h-8 w-8 opacity-60" />
    </div>
    <p className="mb-1 text-base font-semibold text-[#E4E4E7]">{title}</p>
    <p className="text-sm text-[#71717A]">{description}</p>
    {action && <div className="mt-4">{action}</div>}
  </div>
);

const LoadingBlock = ({ text = "Loading..." }: { text?: string }) => (
  <div className="py-14 flex items-center justify-center text-[#71717A]">
    <div className="flex items-center gap-3">
      <RefreshCw className="h-5 w-5 animate-spin" />
      <span>{text}</span>
    </div>
  </div>
);

const ConfidenceBadge = ({ value }: { value: number }) => {
  const c =
    value >= 80
      ? "text-[#4ADE80] bg-[#22C55E]/12 border-[#22C55E]/25"
      : value >= 50
      ? "text-[#FCD34D] bg-yellow-500/15 border-yellow-500/40"
      : "text-[#A1A1AA] bg-white/6 border-white/10";
  return (
    <span className={`px-1.5 py-0.5 rounded border text-xs font-mono ${c}`}>
      {value}%
    </span>
  );
};

const SeverityBadge = ({
  severity,
  size = "sm",
}: {
  severity: string | null;
  size?: "sm" | "md";
}) => {
  const c: Record<string, string> = {
    CRITICAL: "bg-[#EF4444]/15 text-[#F87171] border-[#EF4444]/30",
    HIGH: "bg-[#F59E0B]/15 text-[#FBBF24] border-orange-500/50",
    MEDIUM: "bg-[#F59E0B]/15 text-[#FCD34D] border-yellow-500/50",
    LOW: "bg-[#22C55E]/15 text-[#4ADE80] border-[#22C55E]/30",
  };
  return (
    <span
      className={`px-2 py-0.5 rounded-full font-bold border ${
        c[severity || ""] || "bg-white/6 text-[#A1A1AA] border-white/10"
      } ${size === "md" ? "text-sm px-3 py-1" : "text-xs"}`}
    >
      {severity || "UNKNOWN"}
    </span>
  );
};

const StageBadge = ({ stage }: { stage?: string }) => {
  if (!stage) return null;
  const cfg = STAGE_CONFIG[stage] || STAGE_CONFIG.unknown;
  return (
    <span
      className="px-2 py-0.5 rounded-full text-xs font-medium border"
      style={{
        backgroundColor: cfg.bg,
        color: cfg.color,
        borderColor: `${cfg.color}50`,
      }}
    >
      {cfg.icon} {cfg.label}
    </span>
  );
};

const TTEBadge = ({ tte }: { tte: TimeToExploit }) => {
  const c: Record<string, string> = {
    minutes: "text-[#F87171]",
    hours: "text-[#FBBF24]",
    days: "text-[#FCD34D]",
    weeks: "text-[#4ADE80]",
    unknown: "text-[#A1A1AA]",
  };
  return (
    <span className={`flex items-center gap-1 text-xs font-medium ${c[tte.estimate]}`}>
      <Timer className="h-3 w-3" />
      {tte.estimate}
      <ConfidenceBadge value={tte.confidence} />
    </span>
  );
};

const CVSSScore = ({
  score,
  size = "md",
}: {
  score: number | null;
  size?: "sm" | "md" | "lg";
}) => {
  const c =
    score === null
      ? "text-[#A1A1AA]"
      : score >= 9
      ? "text-[#F87171]"
      : score >= 7
      ? "text-[#FBBF24]"
      : score >= 4
      ? "text-[#FCD34D]"
      : "text-[#4ADE80]";
  const s = { sm: "text-lg", md: "text-2xl", lg: "text-3xl" };
  return (
    <div className="flex items-center gap-1">
      <span className={`font-bold ${c} ${s[size]}`}>
        {score !== null ? score.toFixed(1) : "N/A"}
      </span>
      {score !== null && <span className="text-xs text-[#52525B]">/10</span>}
    </div>
  );
};

const CopyButton = ({ text }: { text: string }) => {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={(e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
      className="p-1 rounded hover:bg-white/8 text-[#52525B] hover:text-white transition-all duration-200"
      title="Copy"
    >
      {copied ? (
        <Check className="h-3.5 w-3.5 text-[#4ADE80]" />
      ) : (
        <Copy className="h-3.5 w-3.5" />
      )}
    </button>
  );
};

const CollapsibleSection = ({
  title,
  icon: Icon,
  iconColor,
  children,
  defaultOpen = true,
  count,
  badge,
}: {
  title: string;
  icon: any;
  iconColor: string;
  children: React.ReactNode;
  defaultOpen?: boolean;
  count?: number;
  badge?: string;
}) => {
  const [isOpen, setIsOpen] = useState(defaultOpen);
  return (
    <div className="rounded-xl bg-[#131318]/30 border border-white/5 overflow-hidden">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between p-4 hover:bg-[#131318]/50 transition-colors"
      >
        <div className="flex items-center gap-3">
          <Icon className="h-4 w-4" style={{ color: iconColor }} />
          <span className="text-sm font-medium text-[#E4E4E7]">{title}</span>
          {count !== undefined && (
            <span className="px-2 py-0.5 rounded-full bg-white/6 text-xs text-[#A1A1AA]">
              {count}
            </span>
          )}
          {badge && (
            <span className="px-2 py-0.5 rounded-full bg-[#EF4444]/15 text-[#F87171] text-xs border border-[#EF4444]/25">
              {badge}
            </span>
          )}
        </div>
        {isOpen ? (
          <ChevronUp className="h-4 w-4 text-[#52525B]" />
        ) : (
          <ChevronDown className="h-4 w-4 text-[#52525B]" />
        )}
      </button>
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="p-4 pt-0">{children}</div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

const StatCard = ({
  label,
  value,
  icon: Icon,
  color,
  subtitle,
  trend,
  badge,
  onClick,
}: {
  label: string;
  value: number | string;
  icon: any;
  color: string;
  subtitle?: string;
  trend?: "up" | "down";
  badge?: string;
  onClick?: () => void;
}) => (
  <motion.div
    initial={{ opacity: 0, y: 16 }}
    animate={{ opacity: 1, y: 0 }}
    onClick={onClick}
    className={`group relative overflow-hidden rounded-2xl border border-white/6 bg-[#131318]/80 p-5 backdrop-blur-xl shadow-[0_8px_32px_-8px_rgba(0,0,0,0.5)] transition-all duration-300 hover:-translate-y-1 hover:border-white/12 hover:shadow-[0_16px_48px_-12px_rgba(0,0,0,0.6)] ${
      onClick ? "cursor-pointer" : ""
    }`}
  >
    <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(135deg,rgba(255,255,255,0.04),transparent_50%)] opacity-0 group-hover:opacity-100 transition-opacity duration-300 rounded-2xl" />
    <div className="flex items-center justify-between mb-4">
      <div className={`h-10 w-10 rounded-xl bg-gradient-to-br ${color} flex items-center justify-center shadow-lg`}>
        <Icon className="h-5 w-5 text-white" />
      </div>
      <div className="flex items-center gap-2">
        {badge && (
          <span className="text-xs px-2 py-0.5 rounded-full bg-[#EF4444]/15 text-[#F87171] border border-[#EF4444]/25 font-semibold">
            {badge}
          </span>
        )}
        {trend === "up" && <ArrowUpRight className="h-4 w-4 text-[#F87171]" />}
        {trend === "down" && <ArrowDownRight className="h-4 w-4 text-[#4ADE80]" />}
      </div>
    </div>
    <div className="relative">
      <p className="mb-1 text-3xl font-bold tracking-tight text-white">{value}</p>
      <p className="text-sm font-medium text-[#A1A1AA]">{label}</p>
      {subtitle && <p className="mt-1 text-xs text-[#52525B]">{subtitle}</p>}
    </div>
  </motion.div>
);

const MonitorStatusBadge = ({
  status,
  onToggle,
}: {
  status: MonitorStatus | null;
  onToggle: () => void;
}) => {
  if (!status) return null;
  return (
    <button
      onClick={onToggle}
      className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border transition-colors ${
        status.running
          ? "bg-[#22C55E]/10 border-[#22C55E]/25 hover:bg-[#22C55E]/15 transition-all duration-200"
          : "bg-white/4 border-white/8 hover:bg-white/8 hover:border-white/12"
      }`}
    >
      <Radio
        className={`h-4 w-4 ${status.running ? "text-[#4ADE80] animate-pulse" : "text-[#71717A]"}`}
      />
      <span
        className={`text-xs font-medium ${
          status.running ? "text-[#4ADE80]" : "text-[#A1A1AA]"
        }`}
      >
        {status.running ? "MONITORING" : "MONITOR OFF"}
      </span>
      {status.running && status.stats.new_cves_found > 0 && (
        <span className="px-1.5 py-0.5 rounded-full bg-[#22C55E]/15 text-[#4ADE80] text-xs font-bold border border-[#22C55E]/20">
          +{status.stats.new_cves_found}
        </span>
      )}
    </button>
  );
};

const AlertBadge = ({ count, onClick }: { count: number; onClick: () => void }) => {
  if (count === 0) return null;
  return (
    <button
      onClick={onClick}
      className="relative flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#EF4444]/10 border border-[#EF4444]/25 hover:bg-[#EF4444]/15 transition-all duration-200"
    >
      <BellRing className="h-4 w-4 text-[#F87171] animate-pulse" />
      <span className="text-xs font-bold text-[#F87171]">{count}</span>
    </button>
  );
};

const ComplianceScoreRing = ({
  score,
  framework,
  size = "md",
}: {
  score: number;
  framework?: string;
  size?: "sm" | "md" | "lg";
}) => {
  const radius = size === "lg" ? 45 : size === "md" ? 35 : 25;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference;
  const color =
    score >= 85 ? "#22C55E" : score >= 70 ? "#f59e0b" : "#ef4444";
  const svgSize = size === "lg" ? 100 : size === "md" ? 80 : 60;

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width={svgSize} height={svgSize} className="-rotate-90">
        <circle
          cx={svgSize / 2}
          cy={svgSize / 2}
          r={radius}
          fill="none"
          stroke="#131318"
          strokeWidth="6"
        />
        <circle
          cx={svgSize / 2}
          cy={svgSize / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="6"
          strokeDasharray={circumference}
          strokeDashoffset={circumference - progress}
          strokeLinecap="round"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span
          className={`font-bold ${
            size === "lg" ? "text-xl" : size === "md" ? "text-lg" : "text-sm"
          }`}
          style={{ color }}
        >
          {score}%
        </span>
        {framework && <span className="text-xs text-[#52525B]">{framework}</span>}
      </div>
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════
// PANELS
// ═══════════════════════════════════════════════════════════════

const ComplianceDashboardPanel = ({
  assessment,
  isLoading,
  onRefresh,
}: {
  assessment: ComplianceAssessment | null;
  isLoading: boolean;
  onRefresh: () => void;
}) => {
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null);
  const hasOnlyGenericFindings =
    !!assessment &&
    (assessment.data_sources?.asset_matched_vulnerabilities ?? 0) === 0 &&
    (assessment.total_vulnerabilities || 0) > 0;

  if (isLoading && !assessment) {
    return (
      <SectionCard
        title="Compliance Assessment"
        subtitle="SOC 2, PCI DSS, HIPAA, NIST 800-53"
        icon={FileCheck}
        iconClass="from-[#3B82F6] to-[#6366F1]"
      >
        <LoadingBlock text="Refreshing compliance posture..." />
      </SectionCard>
    );
  }

  if (!assessment) {
    return (
      <SectionCard
        title="Compliance Assessment"
        subtitle="SOC 2, PCI DSS, HIPAA, NIST 800-53"
        icon={FileCheck}
        iconClass="from-[#3B82F6] to-[#6366F1]"
        actions={
          <button
            onClick={onRefresh}
            disabled={isLoading}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#3B82F6]/15 hover:bg-blue-500/30 text-[#60A5FA] border border-blue-500/50 text-sm disabled:opacity-50"
          >
            {isLoading ? (
              <RefreshCw className="h-4 w-4 animate-spin" />
            ) : (
              <ScanLine className="h-4 w-4" />
            )}
            Assess
          </button>
        }
      >
        <EmptyState
          icon={FileCheck}
          title="No compliance assessment loaded"
          description="Run an assessment to evaluate current framework posture."
        />
      </SectionCard>
    );
  }

  const frameworks = Object.entries(assessment.framework_summary || {});

  return (
    <SectionCard
      title="Compliance Assessment"
      subtitle={
        assessment.data_sources?.refreshed_at
          ? `Overall: ${assessment.overall_compliance}% compliant • Refreshed ${formatDate(
              assessment.data_sources.refreshed_at
            )}`
          : `Overall: ${assessment.overall_compliance}% compliant`
      }
      icon={FileCheck}
      iconClass="from-[#3B82F6] to-[#6366F1]"
      actions={
        <div className="flex items-center gap-3">
          <ComplianceScoreRing score={assessment.overall_compliance} size="sm" />
          <button
            onClick={onRefresh}
            disabled={isLoading}
            className="p-2 rounded-lg bg-white/4 border border-white/8 text-[#A1A1AA] hover:bg-white/8 hover:text-white hover:border-white/12 disabled:opacity-40 transition-all duration-200"
            title="Refresh assessment"
          >
            <RefreshCw className={`h-4 w-4 ${isLoading ? "animate-spin" : ""}`} />
          </button>
        </div>
      }
    >
      {hasOnlyGenericFindings && (
        <div className="mb-5 rounded-2xl border border-[#F59E0B]/20 bg-[#F59E0B]/10 px-4 py-3 text-sm text-amber-100">
          ⚠️ No assets registered yet. This compliance score is based on generic CVE mappings only. Add your infrastructure assets and run a CVE scan to get your real compliance posture.
        </div>
      )}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        {frameworks.map(([key, fw]) => {
          const config = COMPLIANCE_FRAMEWORKS[key];
          const Icon = config?.icon || ShieldCheck; // landing-palette icon
          const selected = selectedFramework === key;

          return (
            <motion.button
              key={key}
              whileHover={{ scale: 1.02 }}
              onClick={() => setSelectedFramework(selected ? null : key)}
              className={`text-left p-4 rounded-xl border transition-all ${
                selected
                  ? "bg-[#3B82F6]/10 border-blue-500/50"
                  : "bg-[#09090B]/60 border-white/6 hover:border-white/12 hover:bg-white/2"
              }`}
            >
              <div className="flex items-center justify-between mb-3">
                <Icon className="h-5 w-5" style={{ color: config?.color || "#3b82f6" }} />
                <span
                  className={`px-2 py-0.5 rounded-full text-xs font-bold border ${getFrameworkStatusTone(
                    fw.status
                  )}`}
                >
                  {fw.status.replace(/_/g, " ")}
                </span>
              </div>

              <p className="text-sm font-medium text-white mb-1">{fw.name}</p>
              <div className="flex items-center justify-between">
                <span className="text-xs text-[#A1A1AA]">
                  {fw.controls_affected}/{fw.total_controls} controls impacted
                </span>
                <span
                  className={`text-lg font-bold ${
                    fw.compliance_percentage >= 85
                      ? "text-[#4ADE80]"
                      : fw.compliance_percentage >= 70
                      ? "text-[#FCD34D]"
                      : "text-[#F87171]"
                  }`}
                >
                  {fw.compliance_percentage}%
                </span>
              </div>
            </motion.button>
          );
        })}
      </div>

      {selectedFramework && assessment.framework_summary[selectedFramework] && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: "auto" }}
          className="p-4 rounded-xl bg-[#09090B]/60 border border-white/6"
        >
          <div className="mb-4">
            <h3 className="text-sm font-medium text-[#E4E4E7] mb-1">
              {assessment.framework_summary[selectedFramework].name}
            </h3>
            <p className="text-xs text-[#52525B]">
              {assessment.framework_summary[selectedFramework].summary_text ||
                "Detailed framework impact overview."}
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
            <div className="rounded-xl bg-white/2 border border-white/6 p-4">
              <p className="text-xs text-[#52525B] mb-2">Top impacted controls</p>
              <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                {(assessment.framework_summary[selectedFramework].top_controls ||
                  []).map((control) => (
                  <div
                    key={control.control_id}
                    className="p-3 rounded-lg bg-[#09090B]/60 border border-white/5"
                  >
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <span className="font-mono text-xs text-[#60A5FA]">
                        {control.control_id}
                      </span>
                      <span className="text-xs text-[#F87171] font-semibold">
                        {control.degradation_percent}% degraded
                      </span>
                    </div>
                    <p className="text-sm text-white">{control.control_name}</p>
                    <p className="text-xs text-[#52525B] mt-1">
                      {control.matched_cve_count} CVEs • {control.matched_asset_count} assets
                    </p>
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-xl bg-white/2 border border-white/6 p-4">
              <p className="text-xs text-[#52525B] mb-2">Mapped CVEs</p>
              <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                {assessment.results
                  .filter((r) => r.frameworks_affected.includes(selectedFramework))
                  .slice(0, 10)
                  .map((result) => (
                    <div
                      key={result.cve_id}
                      className="flex items-center justify-between p-3 rounded-lg bg-[#09090B]/60 border border-white/5"
                    >
                      <div>
                        <span className="font-mono text-sm text-white">{result.cve_id}</span>
                        <p className="text-xs text-[#52525B]">
                          {result.total_controls_affected} affected controls
                        </p>
                      </div>
                      <span
                        className={`px-2 py-0.5 rounded text-xs ${
                          result.compliance_risk === "critical"
                            ? "bg-[#EF4444]/15 text-[#F87171]"
                            : result.compliance_risk === "high"
                            ? "bg-[#F59E0B]/15 text-[#FBBF24]"
                            : "bg-[#F59E0B]/15 text-[#FCD34D]"
                        }`}
                      >
                        {result.compliance_risk}
                      </span>
                    </div>
                  ))}
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </SectionCard>
  );
};

const TrendingPanel = ({
  data,
  isLoading,
  onRefresh,
  onSnapshot,
}: {
  data: TrendingData | null;
  isLoading: boolean;
  onRefresh: () => void;
  onSnapshot: () => void;
}) => {
  const chartData = useMemo(() => {
    if (!data || data.trend.length === 0) return null;

    return {
      labels: data.trend.map((t) => {
        const d = new Date(t.timestamp);
        return d.toLocaleDateString("en-US", {
          month: "short",
          day: "numeric",
        });
      }),
      datasets: [
        {
          label: "System Health",
          data: data.trend.map((t) => t.system_health),
          borderColor: chartColors.green,
          backgroundColor: "rgba(34,197,94,0.10)",
          fill: true,
          tension: 0.35,
        },
        {
          label: "Average Risk",
          data: data.trend.map((t) => t.avg_risk),
          borderColor: chartColors.red,
          backgroundColor: "transparent",
          borderDash: [6, 6],
          tension: 0.35,
        },
      ],
    };
  }, [data]);

  return (
    <SectionCard
      title="Risk Trending"
      subtitle={
        data
          ? `${data.data_points} snapshots over ${data.period_days} days`
          : "Historical risk analysis"
      }
      icon={LineChart}
      iconClass="from-[#8B5CF6] to-[#6366F1]"
      actions={
        <div className="flex items-center gap-2">
          {data && (
            <span
              className={`px-3 py-1 rounded-full text-xs font-bold flex items-center gap-1 ${
                data.trend_direction === "improving"
                  ? "bg-[#22C55E]/15 text-[#4ADE80]"
                  : data.trend_direction === "degrading"
                  ? "bg-[#EF4444]/15 text-[#F87171]"
                  : "bg-white/8 text-[#A1A1AA]"
              }`}
            >
              {data.trend_direction === "improving" ? (
                <TrendingDown className="h-3 w-3" />
              ) : data.trend_direction === "degrading" ? (
                <TrendingUp className="h-3 w-3" />
              ) : null}
              {data.trend_direction.replace(/_/g, " ")}
            </span>
          )}
          <button
            onClick={onSnapshot}
            className="p-2 rounded-lg bg-[#8B5CF6]/15 text-[#A78BFA] hover:bg-purple-500/30 border border-purple-500/50"
            title="Capture snapshot"
          >
            <Camera className="h-4 w-4" />
          </button>
          <button
            onClick={onRefresh}
            disabled={isLoading}
            className="p-2 rounded-lg bg-white/4 border border-white/8 text-[#A1A1AA] hover:bg-white/8 hover:text-white hover:border-white/12 disabled:opacity-40 transition-all duration-200"
            title="Refresh trending"
          >
            <RefreshCw className={`h-4 w-4 ${isLoading ? "animate-spin" : ""}`} />
          </button>
        </div>
      }
    >
      {isLoading && !data ? (
        <LoadingBlock text="Loading trend history..." />
      ) : chartData ? (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div className="p-4 rounded-xl bg-[#09090B]/60 border border-white/6">
              <p className="text-xs text-[#52525B] mb-1">Latest Health</p>
              <p className="text-2xl font-bold text-[#4ADE80]">
                {safeNumber(data?.latest_health, 0)}%
              </p>
            </div>
            <div className="p-4 rounded-xl bg-[#09090B]/60 border border-white/6">
              <p className="text-xs text-[#52525B] mb-1">Health Change</p>
              <p
                className={`text-2xl font-bold ${
                  safeNumber(data?.change?.health_change, 0) >= 0
                    ? "text-[#4ADE80]"
                    : "text-[#F87171]"
                }`}
              >
                {safeNumber(data?.change?.health_change, 0) > 0 ? "+" : ""}
                {safeNumber(data?.change?.health_change, 0)}
              </p>
            </div>
            <div className="p-4 rounded-xl bg-[#09090B]/60 border border-white/6">
              <p className="text-xs text-[#52525B] mb-1">Critical Change</p>
              <p
                className={`text-2xl font-bold ${
                  safeNumber(data?.change?.critical_change, 0) <= 0
                    ? "text-[#4ADE80]"
                    : "text-[#F87171]"
                }`}
              >
                {safeNumber(data?.change?.critical_change, 0) > 0 ? "+" : ""}
                {safeNumber(data?.change?.critical_change, 0)}
              </p>
            </div>
            <div className="p-4 rounded-xl bg-[#09090B]/60 border border-white/6">
              <p className="text-xs text-[#52525B] mb-1">Last Snapshot</p>
              <p className="text-sm font-medium text-[#FAFAFA]">
                {formatDate(data?.latest_timestamp)}
              </p>
            </div>
          </div>

          <div className="h-72">
            <Line
              data={chartData}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                  legend: {
                    position: "top",
                    labels: { color: "#A1A1AA", font: { size: 11 } },
                  },
                },
                scales: {
                  x: {
                    grid: { color: "#131318" },
                    ticks: { color: "#A1A1AA" },
                  },
                  y: {
                    min: 0,
                    max: 100,
                    grid: { color: "#131318" },
                    ticks: { color: "#A1A1AA" },
                  },
                },
              }}
            />
          </div>
        </>
      ) : (
        <EmptyState
          icon={History}
          title="No trend history yet"
          description="Snapshots are created automatically after scans, or you can capture one manually."
          action={
            <button
              onClick={onSnapshot}
              className="px-4 py-2 rounded-lg bg-[#8B5CF6]/15 text-[#A78BFA] border border-purple-500/40 hover:bg-purple-500/30"
            >
              Capture first snapshot
            </button>
          }
        />
      )}
    </SectionCard>
  );
};

const ActiveScannerPanel = ({
  onScan,
  isScanning,
  lastResult,
}: {
  onScan: (target: string, scanType: string) => void;
  isScanning: boolean;
  lastResult: ActiveScanResult | null;
}) => {
  const [target, setTarget] = useState("172.22.0.0/28");
  const [scanType, setScanType] = useState("quick");
  const [selectedHost, setSelectedHost] = useState<ActiveScanHost | null>(null);
  const [activeHostTab, setActiveHostTab] = useState<"services" | "vulnerabilities" | "scripts">("services");
  const [scanProgress, setScanProgress] = useState(0);
  const [scanPhase, setScanPhase] = useState("");
  const [elapsedTime, setElapsedTime] = useState(0);
  const scanTimerRef = useRef<number | undefined>(undefined);
  const progressRef = useRef<number | undefined>(undefined);

  const SCAN_TYPES = [
    {
      id: "quick",
      label: "Quick Scan",
      icon: Zap,
      color: "#22C55E",
      description: "Top 100 ports, fast discovery",
      time: "~30s",
      flags: "-sV -T4 --top-ports 100",
    },
    {
      id: "full",
      label: "Full Scan",
      icon: Search,
      color: "#3b82f6",
      description: "All 65535 ports, complete coverage",
      time: "~15min",
      flags: "-sV -O -A -T3 -p-",
    },
    {
      id: "vuln",
      label: "Vuln Scan",
      icon: ShieldAlert,
      color: "#ef4444",
      description: "NSE vulnerability scripts",
      time: "~5min",
      flags: "-sV --script vuln",
    },
    {
      id: "stealth",
      label: "Stealth Scan",
      icon: Eye,
      color: "#8b5cf6",
      description: "SYN scan, low detection risk",
      time: "~2min",
      flags: "-sS -T2 -f",
    },
  ];

  const selectedScanType = SCAN_TYPES.find((s) => s.id === scanType) || SCAN_TYPES[0];

  const SCAN_PHASES = [
    "Initializing scanner...",
    "Resolving target...",
    "Sending probes...",
    "Port discovery...",
    "Service fingerprinting...",
    "OS detection...",
    "Running scripts...",
    "Analyzing results...",
    "Saving assets...",
  ];

  const handleStartScan = () => {
    if (!target.trim() || isScanning) return;
    setSelectedHost(null);
    setScanProgress(0);
    setElapsedTime(0);

    let phaseIdx = 0;
    let prog = 0;

    scanTimerRef.current = window.setInterval(() => {
      setElapsedTime((prev) => prev + 1);
    }, 1000);

    progressRef.current = window.setInterval(() => {
      prog += Math.random() * 8 + 2;
      if (prog >= 95) {
        prog = 95;
        window.clearInterval(progressRef.current);
      }
      setScanProgress(Math.min(95, prog));
      phaseIdx = Math.min(
        SCAN_PHASES.length - 1,
        Math.floor((prog / 95) * SCAN_PHASES.length)
      );
      setScanPhase(SCAN_PHASES[phaseIdx]);
    }, 800);

    onScan(target.trim(), scanType);
  };

  useEffect(() => {
    if (!isScanning) {
      window.clearInterval(scanTimerRef.current);
      window.clearInterval(progressRef.current);
      if (lastResult?.success) {
        setScanProgress(100);
        setScanPhase("Scan complete");
      }
    }
    return () => {
      window.clearInterval(scanTimerRef.current);
      window.clearInterval(progressRef.current);
    };
  }, [isScanning, lastResult]);

  const getCriticalityColor = (services: any[]) => {
    if (!services || services.length === 0) return "#A1A1AA";
    const hasDB = services.some((s: any) =>
      ["postgresql", "mysql", "mongodb", "redis"].includes(
        s.service?.toLowerCase()
      )
    );
    const hasWeb = services.some((s: any) =>
      ["http", "https"].includes(s.service?.toLowerCase())
    );
    if (hasDB) return "#ef4444";
    if (hasWeb) return "#F59E0B";
    return "#3b82f6";
  };

  const getServiceIcon = (service: string) => {
    const s = service?.toLowerCase();
    if (["postgresql", "mysql", "mongodb", "redis"].includes(s))
      return Database;
    if (["http", "https"].includes(s)) return Globe;
    if (s === "ssh") return Terminal;
    if (["smtp", "imap", "pop3"].includes(s)) return MessageSquare;
    return Server;
  };

  const getRiskLevel = (host: ActiveScanHost) => {
    const svcs = host.services || [];
    const hasDB = svcs.some((s: any) =>
      ["postgresql", "mysql", "mongodb"].includes(s.service?.toLowerCase())
    );
    const hasWeb = svcs.some((s: any) => s.service?.toLowerCase() === "http");
    const portCount = svcs.length;
    if (hasDB && hasWeb) return { level: "CRITICAL", color: "#ef4444", bg: "rgba(239,68,68,0.10)" };
    if (hasDB) return { level: "HIGH", color: "#F59E0B", bg: "rgba(245,158,11,0.10)" };
    if (portCount > 5) return { level: "MEDIUM", color: "#F59E0B", bg: "rgba(245,158,11,0.10)" };
    return { level: "LOW", color: "#22C55E", bg: "rgba(16,185,129,0.15)" };
  };

  return (
    <div className="space-y-6">
      {/* ─── SCANNER CONTROL PANEL ─── */}
      <div className="relative overflow-hidden rounded-[28px] border border-white/10 bg-[#0d0d12]/75 p-6 shadow-[0_24px_80px_rgba(9,9,11,0.55)] backdrop-blur-xl">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(16,185,129,0.12),transparent_32%),radial-gradient(circle_at_bottom_left,rgba(59,130,246,0.08),transparent_28%)]" />

        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="h-12 w-12 rounded-2xl bg-gradient-to-br from-[#22C55E] to-[#16A34A] flex items-center justify-center shadow-lg shadow-green-500/25">
              <RadarIcon className="h-6 w-6 text-white" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">Active Network Scanner</h2>
              <p className="text-xs text-[#A1A1AA] uppercase tracking-widest">
                Nmap 7.95 • Real-time Discovery Engine
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#22C55E]/10 border border-[#22C55E]/20">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500" />
            </span>
            <span className="text-xs font-medium text-[#4ADE80]">ENGINE READY</span>
          </div>
        </div>

        {/* Scan Type Selection */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
          {SCAN_TYPES.map((type) => {
            const Icon = type.icon;
            const isSelected = scanType === type.id;
            return (
              <motion.button
                key={type.id}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                onClick={() => setScanType(type.id)}
                disabled={isScanning}
                className={`relative p-4 rounded-2xl border text-left transition-all ${
                  isSelected
                    ? "border-opacity-60"
                    : "border-white/6 bg-[#131318]/30 hover:border-white/10"
                }`}
                style={
                  isSelected
                    ? {
                        backgroundColor: `${type.color}15`,
                        borderColor: `${type.color}60`,
                      }
                    : {}
                }
              >
                {isSelected && (
                  <div
                    className="absolute top-2 right-2 w-2 h-2 rounded-full"
                    style={{ backgroundColor: type.color }}
                  />
                )}
                <Icon
                  className="h-5 w-5 mb-2"
                  style={{ color: isSelected ? type.color : "#A1A1AA" }}
                />
                <p
                  className="text-sm font-semibold mb-0.5"
                  style={{ color: isSelected ? type.color : "#e2e8f0" }}
                >
                  {type.label}
                </p>
                <p className="text-xs text-[#52525B]">{type.description}</p>
                <div className="flex items-center gap-1 mt-2">
                  <Timer className="h-3 w-3 text-[#52525B]" />
                  <span className="text-xs text-[#52525B]">{type.time}</span>
                </div>
              </motion.button>
            );
          })}
        </div>

        {/* Target Input */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div className="md:col-span-2">
            <label className="text-xs uppercase tracking-widest text-[#A1A1AA] mb-2 block">
              Target — IP Address / CIDR Range / Hostname
            </label>
            <div className="relative">
              <Crosshair className="absolute left-4 top-1/2 -translate-y-1/2 h-4 w-4 text-[#71717A]" />
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="192.168.1.0/24 or 10.0.0.5 or hostname"
                disabled={isScanning}
                className="w-full pl-11 pr-4 py-3.5 rounded-2xl bg-[#09090B]/60 border border-white/8 text-sm text-white placeholder:text-[#52525B] focus:outline-none focus:border-[#22C55E]/30 transition-colors"
              />
            </div>
          </div>
          <div>
            <label className="text-xs uppercase tracking-widest text-[#A1A1AA] mb-2 block">
              Nmap Flags
            </label>
            <div className="w-full px-4 py-3.5 rounded-2xl bg-[#09090B]/60 border border-white/8 text-xs font-mono text-[#A1A1AA]">
              {selectedScanType.flags}
            </div>
          </div>
        </div>

        {/* Quick target presets */}
        <div className="flex flex-wrap gap-2 mb-5">
          <span className="text-xs text-[#71717A] self-center">Quick targets:</span>
          {[
            { label: "Localhost", value: "127.0.0.1" },
            { label: "Docker DB", value: "172.22.0.2" },
            { label: "Docker Nginx", value: "172.22.0.4" },
            { label: "Docker subnet", value: "172.22.0.0/28" },
            { label: "Private LAN", value: "192.168.1.0/24" },
          ].map((preset) => (
            <button
              key={preset.value}
              onClick={() => setTarget(preset.value)}
              disabled={isScanning}
              className="px-3 py-1 rounded-full text-xs border border-white/8 bg-[#131318]/50 text-[#A1A1AA] hover:text-white hover:border-[#22C55E]/30 transition-colors disabled:opacity-50"
            >
              {preset.label}
            </button>
          ))}
        </div>

        {/* Scan Button */}
        <motion.button
          whileHover={{ scale: isScanning ? 1 : 1.01 }}
          whileTap={{ scale: isScanning ? 1 : 0.99 }}
          onClick={handleStartScan}
          disabled={isScanning || !target.trim()}
          className="w-full py-4 rounded-2xl font-semibold text-white text-base flex items-center justify-center gap-3 transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-lg"
          style={{
            background: isScanning
              ? "linear-gradient(135deg, #064e3b, #065f46)"
              : `linear-gradient(135deg, ${selectedScanType.color}, #059669)`,
            boxShadow: isScanning
              ? "none"
              : `0 8px 32px ${selectedScanType.color}30`,
          }}
        >
          {isScanning ? (
            <>
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
              >
                <RadarIcon className="h-5 w-5" />
              </motion.div>
              <span>Scanning {target}...</span>
              <span className="text-sm opacity-70">({elapsedTime}s elapsed)</span>
            </>
          ) : (
            <>
              <RadarIcon className="h-5 w-5" />
              <span>Launch {selectedScanType.label}</span>
              <ArrowRight className="h-4 w-4" />
            </>
          )}
        </motion.button>

        {/* Progress Bar */}
        <AnimatePresence>
          {isScanning && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              className="mt-4 space-y-2"
            >
              <div className="flex items-center justify-between text-xs text-[#A1A1AA]">
                <span className="flex items-center gap-2">
                  <motion.div
                    animate={{ opacity: [1, 0.3, 1] }}
                    transition={{ duration: 1.5, repeat: Infinity }}
                    className="w-2 h-2 rounded-full bg-green-400"
                  />
                  {scanPhase}
                </span>
                <span>{Math.round(scanProgress)}%</span>
              </div>
              <div className="h-1.5 bg-[#131318] rounded-full overflow-hidden">
                <motion.div
                  className="h-full rounded-full bg-gradient-to-r from-[#22C55E] to-[#4ADE80]"
                  animate={{ width: `${scanProgress}%` }}
                  transition={{ duration: 0.5 }}
                />
              </div>
              <div className="grid grid-cols-5 gap-1">
                {SCAN_PHASES.slice(0, 5).map((phase, i) => (
                  <div
                    key={i}
                    className={`h-0.5 rounded-full transition-colors ${
                      scanProgress >= (i / 5) * 95
                        ? "bg-green-500"
                        : "bg-white/8"
                    }`}
                  />
                ))}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* ─── SCAN RESULTS ─── */}
      <AnimatePresence>
        {lastResult && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-6"
          >
            {/* Summary Bar */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                {
                  label: "Hosts Discovered",
                  value: lastResult.host_count,
                  icon: Server,
                  color: "from-[#22C55E] to-[#16A34A]",
                  glow: "shadow-green-500/20",
                },
                {
                  label: "Services Found",
                  value: lastResult.total_services,
                  icon: Activity,
                  color: "from-[#3B82F6] to-[#0891B2]",
                  glow: "shadow-blue-500/20",
                },
                {
                  label: "Vulnerabilities",
                  value: lastResult.vuln_count ?? lastResult.vulnerabilities_found?.length ?? 0,
                  icon: ShieldAlert,
                  color: "from-[#EF4444] to-[#D97706]",
                  glow: "shadow-red-500/20",
                },
                {
                  label: "Assets Saved",
                  value: lastResult.assets_saved ?? 0,
                  icon: Database,
                  color: "from-[#8B5CF6] to-[#8B5CF6]",
                  glow: "shadow-purple-500/20",
                },
              ].map((stat) => (
                <motion.div
                  key={stat.label}
                  initial={{ scale: 0.9, opacity: 0 }}
                  animate={{ scale: 1, opacity: 1 }}
                  className={`rounded-2xl border border-white/10 bg-[#0d0d12]/70 p-5 shadow-lg ${stat.glow}`}
                >
                  <div
                    className={`h-10 w-10 rounded-xl bg-gradient-to-br ${stat.color} flex items-center justify-center mb-3 shadow-lg`}
                  >
                    <stat.icon className="h-5 w-5 text-white" />
                  </div>
                  <p className="text-3xl font-bold text-white">{stat.value}</p>
                  <p className="text-xs text-[#A1A1AA] mt-1">{stat.label}</p>
                </motion.div>
              ))}
            </div>

            {/* Scan Metadata */}
            <div className="rounded-2xl border border-white/10 bg-[#0d0d12]/50 px-5 py-4">
              <div className="flex flex-wrap items-center gap-6 text-xs text-[#A1A1AA]">
                <span className="flex items-center gap-2">
                  <Crosshair className="h-3.5 w-3.5 text-[#4ADE80]" />
                  Target: <span className="text-white font-mono">{lastResult.target}</span>
                </span>
                <span className="flex items-center gap-2">
                  <Activity className="h-3.5 w-3.5 text-[#60A5FA]" />
                  Type: <span className="text-white capitalize">{lastResult.scan_type}</span>
                </span>
                <span className="flex items-center gap-2">
                  <Timer className="h-3.5 w-3.5 text-[#A78BFA]" />
                  Duration: <span className="text-white">{lastResult.duration}s</span>
                </span>
                <span className="flex items-center gap-2">
                  <Info className="h-3.5 w-3.5 text-[#71717A]" />
                  Scan ID: <span className="text-white font-mono text-[10px]">{lastResult.scan_id}</span>
                </span>
                <span
                  className={`ml-auto px-3 py-1 rounded-full text-xs font-bold ${
                    lastResult.success
                      ? "bg-[#22C55E]/15 text-[#4ADE80] border border-[#22C55E]/25"
                      : "bg-[#EF4444]/15 text-[#F87171] border border-[#EF4444]/25"
                  }`}
                >
                  {lastResult.success ? "✓ Success" : "✗ Failed"}
                </span>
              </div>
            </div>

            {/* Host Grid + Detail Panel */}
            {lastResult.success && lastResult.hosts.length > 0 ? (
              <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
                {/* Host List */}
                <div className="xl:col-span-1 space-y-3">
                  <h3 className="text-sm font-semibold text-[#E4E4E7] uppercase tracking-wider flex items-center gap-2">
                    <Server className="h-4 w-4 text-[#4ADE80]" />
                    Discovered Hosts ({lastResult.host_count})
                  </h3>
                  <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
                    {lastResult.hosts.map((host, idx) => {
                      const risk = getRiskLevel(host);
                      const isSelected = selectedHost?.ip === host.ip;
                      return (
                        <motion.button
                          key={host.ip}
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: idx * 0.05 }}
                          onClick={() => {
                            setSelectedHost(host);
                            setActiveHostTab("services");
                          }}
                          className={`w-full text-left p-4 rounded-2xl border transition-all ${
                            isSelected
                              ? "border-[#22C55E]/30 bg-[#22C55E]/10"
                              : "border-white/6 bg-[#131318]/30 hover:border-white/10"
                          }`}
                        >
                          <div className="flex items-start justify-between mb-2">
                            <div className="flex items-center gap-2">
                              <div
                                className="h-8 w-8 rounded-xl flex items-center justify-center"
                                style={{ backgroundColor: `${risk.color}20` }}
                              >
                                <Server
                                  className="h-4 w-4"
                                  style={{ color: risk.color }}
                                />
                              </div>
                              <div>
                                <p className="text-sm font-semibold text-white font-mono">
                                  {host.ip}
                                </p>
                                {host.hostname !== host.ip && (
                                  <p className="text-xs text-[#A1A1AA] truncate max-w-[150px]">
                                    {host.hostname}
                                  </p>
                                )}
                              </div>
                            </div>
                            <span
                              className="px-2 py-0.5 rounded-full text-xs font-bold border"
                              style={{
                                backgroundColor: risk.bg,
                                color: risk.color,
                                borderColor: `${risk.color}40`,
                              }}
                            >
                              {risk.level}
                            </span>
                          </div>

                          <div className="flex flex-wrap gap-1 mb-2">
                            {(host.services || []).slice(0, 4).map((svc: any, i: number) => (
                              <span
                                key={i}
                                className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-white/8/50 text-[#E4E4E7] border border-white/10/50"
                              >
                                {svc.port}/{svc.protocol}
                              </span>
                            ))}
                            {(host.services || []).length > 4 && (
                              <span className="px-2 py-0.5 rounded-full text-[10px] bg-white/8/50 text-[#A1A1AA]">
                                +{(host.services || []).length - 4} more
                              </span>
                            )}
                          </div>

                          <div className="flex items-center justify-between text-xs text-[#71717A]">
                            <span>{host.service_count} service{host.service_count !== 1 ? "s" : ""}</span>
                            {host.os && (
                              <span className="truncate max-w-[120px]">{host.os.split(" ").slice(0, 3).join(" ")}</span>
                            )}
                          </div>
                        </motion.button>
                      );
                    })}
                  </div>
                </div>

                {/* Host Detail Panel */}
                <div className="xl:col-span-2">
                  {selectedHost ? (
                    <motion.div
                      key={selectedHost.ip}
                      initial={{ opacity: 0, x: 20 }}
                      animate={{ opacity: 1, x: 0 }}
                      className="rounded-2xl border border-white/10 bg-[#0d0d12]/70 overflow-hidden"
                    >
                      {/* Host Header */}
                      <div className="p-5 border-b border-white/4 bg-gradient-to-r from-[#131318]/50 to-transparent">
                        <div className="flex items-start justify-between mb-3">
                          <div className="flex items-center gap-3">
                            <div
                              className="h-12 w-12 rounded-2xl flex items-center justify-center"
                              style={{
                                backgroundColor: `${getCriticalityColor(selectedHost.services)}20`,
                                border: `2px solid ${getCriticalityColor(selectedHost.services)}50`,
                              }}
                            >
                              <Server
                                className="h-6 w-6"
                                style={{ color: getCriticalityColor(selectedHost.services) }}
                              />
                            </div>
                            <div>
                              <div className="flex items-center gap-2">
                                <h3 className="text-lg font-bold text-white font-mono">
                                  {selectedHost.ip}
                                </h3>
                                <CopyButton text={selectedHost.ip} />
                              </div>
                              <p className="text-sm text-[#A1A1AA]">{selectedHost.hostname}</p>
                            </div>
                          </div>
                          <div className="text-right">
                            {(() => {
                              const risk = getRiskLevel(selectedHost);
                              return (
                                <span
                                  className="px-3 py-1.5 rounded-xl text-sm font-bold border"
                                  style={{
                                    backgroundColor: risk.bg,
                                    color: risk.color,
                                    borderColor: `${risk.color}40`,
                                  }}
                                >
                                  {risk.level} RISK
                                </span>
                              );
                            })()}
                          </div>
                        </div>

                        {/* Host metadata */}
                        <div className="grid grid-cols-3 gap-3">
                          {[
                            {
                              label: "Open Ports",
                              value: selectedHost.service_count,
                              color: "#22C55E",
                            },
                            {
                              label: "OS",
                              value: selectedHost.os || "Unknown",
                              color: "#3b82f6",
                              small: true,
                            },
                            {
                              label: "OS Accuracy",
                              value: selectedHost.os_accuracy
                                ? `${selectedHost.os_accuracy}%`
                                : "N/A",
                              color: "#8b5cf6",
                            },
                          ].map((item) => (
                            <div
                              key={item.label}
                              className="p-3 rounded-xl bg-[#131318]/50 border border-white/5"
                            >
                              <p className="text-xs text-[#52525B] mb-1">{item.label}</p>
                              <p
                                className={`font-bold ${item.small ? "text-sm" : "text-xl"} truncate`}
                                style={{ color: item.color }}
                              >
                                {item.value}
                              </p>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Tabs */}
                      <div className="flex border-b border-white/4">
                        {[
                          {
                            id: "services" as const,
                            label: "Services",
                            icon: Activity,
                            count: (selectedHost.services || []).length,
                          },
                          {
                            id: "vulnerabilities" as const,
                            label: "Vulnerabilities",
                            icon: ShieldAlert,
                            count: (lastResult.vulnerabilities_found || []).filter(
                              (v: any) => v.host === selectedHost.ip
                            ).length,
                          },
                          {
                            id: "scripts" as const,
                            label: "Scripts",
                            icon: Terminal,
                            count: (selectedHost.scripts || []).length,
                          },
                        ].map((tab) => (
                          <button
                            key={tab.id}
                            onClick={() => setActiveHostTab(tab.id)}
                            className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 text-sm font-medium transition-colors ${
                              activeHostTab === tab.id
                                ? "text-[#4ADE80] border-b-2 border-green-400 bg-green-500/5"
                                : "text-[#71717A] hover:text-[#E4E4E7]"
                            }`}
                          >
                            <tab.icon className="h-4 w-4" />
                            {tab.label}
                            {tab.count > 0 && (
                              <span
                                className={`px-1.5 py-0.5 rounded-full text-xs font-bold ${
                                  activeHostTab === tab.id
                                    ? "bg-[#22C55E]/15 text-[#4ADE80]"
                                    : "bg-white/8 text-[#A1A1AA]"
                                }`}
                              >
                                {tab.count}
                              </span>
                            )}
                          </button>
                        ))}
                      </div>

                      {/* Tab Content */}
                      <div className="p-5 max-h-[420px] overflow-y-auto">
                        {/* Services Tab */}
                        {activeHostTab === "services" && (
                          <div className="space-y-3">
                            {(selectedHost.services || []).length === 0 ? (
                              <EmptyState
                                icon={Activity}
                                title="No services detected"
                                description="No open ports found on this host"
                              />
                            ) : (
                              (selectedHost.services || []).map((svc: any, idx: number) => {
                                const SvcIcon = getServiceIcon(svc.service);
                                const isHighRisk = ["postgresql", "mysql", "mongodb"].includes(
                                  svc.service?.toLowerCase()
                                );
                                return (
                                  <motion.div
                                    key={idx}
                                    initial={{ opacity: 0, y: 10 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    transition={{ delay: idx * 0.05 }}
                                    className={`p-4 rounded-xl border ${
                                      isHighRisk
                                        ? "bg-red-500/5 border-[#EF4444]/20"
                                        : "bg-[#131318]/30 border-white/5"
                                    }`}
                                  >
                                    <div className="flex items-start justify-between mb-2">
                                      <div className="flex items-center gap-3">
                                        <div
                                          className={`h-9 w-9 rounded-xl flex items-center justify-center ${
                                            isHighRisk
                                              ? "bg-[#EF4444]/15"
                                              : "bg-white/5"
                                          }`}
                                        >
                                          <SvcIcon
                                            className={`h-4 w-4 ${
                                              isHighRisk
                                                ? "text-[#F87171]"
                                                : "text-[#A1A1AA]"
                                            }`}
                                          />
                                        </div>
                                        <div>
                                          <div className="flex items-center gap-2">
                                            <span className="font-mono text-sm font-bold text-white">
                                              {svc.port}/{svc.protocol}
                                            </span>
                                            <span
                                              className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                                                isHighRisk
                                                  ? "bg-[#EF4444]/15 text-[#F87171]"
                                                  : "bg-white/8 text-[#E4E4E7]"
                                              }`}
                                            >
                                              {svc.service}
                                            </span>
                                            <span className="px-2 py-0.5 rounded-full text-xs bg-[#22C55E]/12 text-[#4ADE80] border border-[#22C55E]/20">
                                              OPEN
                                            </span>
                                          </div>
                                          {svc.product && (
                                            <p className="text-xs text-[#A1A1AA] mt-0.5">
                                              {svc.product}{svc.version ? ` ${svc.version}` : ""}
                                            </p>
                                          )}
                                        </div>
                                      </div>
                                      <div className="text-right">
                                        <span className="text-xs text-[#52525B]">
                                          Confidence: {svc.confidence || 0}%
                                        </span>
                                      </div>
                                    </div>

                                    {/* CPE */}
                                    {svc.cpe && svc.cpe.length > 0 && (
                                      <div className="mt-2 pt-2 border-t border-white/5">
                                        <p className="text-xs text-[#52525B] mb-1">CPE</p>
                                        {svc.cpe.map((c: string, i: number) => (
                                          <span
                                            key={i}
                                            className="inline-block px-2 py-0.5 rounded bg-white/8/50 text-xs font-mono text-[#60A5FA] mr-1"
                                          >
                                            {c}
                                          </span>
                                        ))}
                                      </div>
                                    )}

                                    {/* Extra info */}
                                    {svc.extra_info && (
                                      <p className="mt-1 text-xs text-[#71717A] italic">
                                        {svc.extra_info}
                                      </p>
                                    )}
                                  </motion.div>
                                );
                              })
                            )}
                          </div>
                        )}

                        {/* Vulnerabilities Tab */}
                        {activeHostTab === "vulnerabilities" && (
                          <div className="space-y-3">
                            {(() => {
                              const hostVulns = (lastResult.vulnerabilities_found || []).filter(
                                (v: any) => v.host === selectedHost.ip
                              );
                              if (hostVulns.length === 0) {
                                return (
                                  <div className="py-8 text-center">
                                    <ShieldCheck className="h-12 w-12 text-[#4ADE80]/50 mx-auto mb-3" />
                                    <p className="text-[#E4E4E7] font-medium">No vulnerabilities detected</p>
                                    <p className="text-sm text-[#71717A] mt-1">
                                      Run a vulnerability scan for deeper analysis
                                    </p>
                                    <button
                                      onClick={() => {
                                        setScanType("vuln");
                                        setTarget(selectedHost.ip);
                                      }}
                                      className="mt-4 px-4 py-2 rounded-xl bg-[#EF4444]/15 text-[#F87171] border border-[#EF4444]/25 text-sm hover:bg-red-500/30 transition-colors"
                                    >
                                      Run Vuln Scan on this host
                                    </button>
                                  </div>
                                );
                              }
                              return hostVulns.map((vuln: any, idx: number) => (
                                <div
                                  key={idx}
                                  className="p-4 rounded-xl bg-[#EF4444]/10 border border-[#EF4444]/20"
                                >
                                  <div className="flex items-center justify-between mb-2">
                                    <span className="text-sm font-bold text-[#F87171]">
                                      {vuln.script}
                                    </span>
                                    <span className="px-2 py-0.5 rounded text-xs bg-[#EF4444]/15 text-[#FCA5A5] font-bold">
                                      VULNERABLE
                                    </span>
                                  </div>
                                  {vuln.cves && vuln.cves.length > 0 && (
                                    <div className="flex flex-wrap gap-1 mb-2">
                                      {vuln.cves.map((cve: string) => (
                                        <span
                                          key={cve}
                                          className="px-2 py-0.5 rounded font-mono text-xs bg-[#F59E0B]/15 text-[#FBBF24]"
                                        >
                                          {cve}
                                        </span>
                                      ))}
                                    </div>
                                  )}
                                  <p className="text-xs text-[#A1A1AA] leading-relaxed">
                                    {vuln.details?.slice(0, 300)}
                                  </p>
                                  {vuln.port && (
                                    <p className="text-xs text-[#52525B] mt-1">
                                      Port: {vuln.port}
                                    </p>
                                  )}
                                </div>
                              ));
                            })()}
                          </div>
                        )}

                        {/* Scripts Tab */}
                        {activeHostTab === "scripts" && (
                          <div className="space-y-3">
                            {(selectedHost.scripts || []).length === 0 ? (
                              <EmptyState
                                icon={Terminal}
                                title="No script output"
                                description="Run a vulnerability or full scan to see NSE script results"
                              />
                            ) : (
                              (selectedHost.scripts || []).map((script: any, idx: number) => (
                                <div
                                  key={idx}
                                  className="p-4 rounded-xl bg-[#131318]/30 border border-white/5"
                                >
                                  <p className="text-sm font-bold text-[#60A5FA] mb-2 font-mono">
                                    {script.id}
                                  </p>
                                  <pre className="text-xs text-[#A1A1AA] whitespace-pre-wrap font-mono leading-relaxed">
                                    {script.output}
                                  </pre>
                                </div>
                              ))
                            )}
                          </div>
                        )}
                      </div>
                    </motion.div>
                  ) : (
                    <div className="h-full rounded-2xl border border-dashed border-white/6 bg-[#0d0d12]/30 flex items-center justify-center py-20">
                      <div className="text-center">
                        <Server className="h-12 w-12 text-[#52525B] mx-auto mb-3" />
                        <p className="text-[#A1A1AA] font-medium">Select a host to inspect</p>
                        <p className="text-sm text-[#52525B] mt-1">
                          Click any host from the list to see details
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ) : lastResult.success && lastResult.hosts.length === 0 ? (
              <div className="rounded-2xl border border-dashed border-white/6 bg-[#0d0d12]/30 py-16 text-center">
                <RadarIcon className="h-12 w-12 text-[#52525B] mx-auto mb-3" />
                <p className="text-[#E4E4E7] font-medium">No hosts discovered</p>
                <p className="text-sm text-[#71717A] mt-1">
                  Target may be offline or blocked by firewall
                </p>
              </div>
            ) : !lastResult.success ? (
              <div className="rounded-2xl border border-[#EF4444]/20 bg-[#EF4444]/10 p-6">
                <div className="flex items-center gap-3 mb-3">
                  <AlertCircle className="h-6 w-6 text-[#F87171]" />
                  <h3 className="text-[#F87171] font-bold">Scan Failed</h3>
                </div>
                <p className="text-[#E4E4E7] text-sm">{lastResult.error}</p>
              </div>
            ) : null}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

const IntegrationConfigModal = ({
  isOpen,
  onClose,
  onSave,
}: {
  isOpen: boolean;
  onClose: () => void;
  onSave: (config: IntegrationConfigRecord) => void | Promise<void>;
}) => {
  const [activeTab, setActiveTab] = useState<
    "slack" | "jira" | "pagerduty" | "webhook" | "activity"
  >("webhook");
  const [config, setConfig]       = useState<Record<string, string>>({});
  const [saving, setSaving]       = useState(false);
  const [saved, setSaved]         = useState(false);
  const [testing, setTesting]     = useState(false);
  const [activity, setActivity]   = useState<any[]>([]);
  const [integStatus, setIntegStatus] = useState<any>(null);
  const [loadingActivity, setLoadingActivity] = useState(false);

  const fetchActivity = async () => {
    setLoadingActivity(true);
    try {
      const data = await apiFetch<any>("/integrations/recent/");
      if (data && data.results) setActivity(safeArray<any>(data.results));
      if (data && data.status) setIntegStatus(data.status);
    } catch (e) {
      console.error("fetchActivity failed:", e);
    } finally {
      setLoadingActivity(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      setConfig({});
      setSaved(false);
      fetchActivity();
    }
  }, [isOpen, activeTab]);

  // Poll activity every 5 seconds when modal is open
  useEffect(() => {
    if (!isOpen) return;
    const interval = setInterval(fetchActivity, 5000);
    return () => clearInterval(interval);
  }, [isOpen]);

  const handleTest = async () => {
    setTesting(true);
    try {
      await apiFetch("/integrations/test/", { method: "POST" });
      setTimeout(fetchActivity, 1500);
    } catch (e) {
      console.error("Test failed:", e);
    } finally {
      setTesting(false);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const saveType = activeTab === "activity" ? "webhook" : activeTab;
      const result = onSave({ type: saveType as any, enabled: true, config });
      if (result instanceof Promise) await result;
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (e) {
      console.error("Save failed:", e);
    } finally {
      setSaving(false);
    }
  };

  if (!isOpen) return null;

  const tabs = [
    { id: "webhook"  as const, icon: Webhook,      label: "Webhook"   },
    { id: "slack"    as const, icon: MessageSquare, label: "Slack"     },
    { id: "jira"     as const, icon: TicketCheck,   label: "Jira"      },
    { id: "pagerduty"as const, icon: Siren,         label: "PagerDuty" },
    { id: "activity" as const, icon: Activity,      label: "Activity"  },
  ];

  const severityColor = (s: string) =>
    s === "critical" ? "#F87171" : s === "high" ? "#FBBF24" : s === "info" ? "#60A5FA" : "#A1A1AA";

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: 10 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        className="w-full max-w-2xl bg-[#0d0d12] rounded-2xl border border-white/8 shadow-[0_32px_80px_-16px_rgba(0,0,0,0.7)] overflow-hidden"
      >
        {/* ── HEADER ── */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-white/6">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-[#6366F1]/10 ring-1 ring-[#6366F1]/20">
              <Webhook className="h-4 w-4 text-[#818CF8]" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-[#FAFAFA]">Integrations</h2>
              {integStatus && (
                <p className="text-xs text-[#52525B] mt-0.5">
                  {integStatus.integrations_configured} configured •{" "}
                  <span className={integStatus.running ? "text-[#4ADE80]" : "text-[#F87171]"}>
                    worker {integStatus.running ? "active" : "stopped"}
                  </span>
                </p>
              )}
            </div>
          </div>
          <button onClick={onClose} className="p-2 rounded-lg bg-white/3 hover:bg-white/8 text-[#52525B] hover:text-white border border-white/5 transition-all">
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* ── TABS ── */}
        <div className="flex border-b border-white/6 bg-white/[0.01]">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex-1 flex items-center justify-center gap-1.5 px-3 py-2.5 text-xs font-medium transition-all ${
                activeTab === tab.id
                  ? "text-[#60A5FA] border-b-2 border-[#3B82F6] bg-[#3B82F6]/5"
                  : "text-[#71717A] hover:text-[#A1A1AA]"
              }`}
            >
              <tab.icon className="h-3.5 w-3.5" />
              {tab.label}
              {tab.id === "activity" && activity.length > 0 && (
                <span className="ml-1 px-1.5 py-0.5 rounded-full text-[9px] bg-[#3B82F6]/20 text-[#60A5FA]">
                  {activity.length}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* ── BODY ── */}
        <div className="p-6">

          {/* WEBHOOK TAB */}
          {activeTab === "webhook" && (
            <div className="space-y-4">
              <div className="p-3 rounded-xl bg-[#6366F1]/6 border border-[#6366F1]/15 flex items-start gap-3">
                <Info className="h-4 w-4 text-[#818CF8] flex-shrink-0 mt-0.5" />
                <p className="text-xs text-[#71717A] leading-relaxed">
                  CascadeX will POST a signed JSON payload to your URL every time a critical CVE is detected, a scan completes, or risk changes.
                </p>
              </div>
              <div>
                <label className="text-xs font-medium text-[#A1A1AA] mb-1.5 block">Webhook URL <span className="text-[#F87171]">*</span></label>
                <input
                  type="text"
                  value={config.url || ""}
                  onChange={(e) => setConfig({ ...config, url: e.target.value })}
                  placeholder="https://your-endpoint.com/cascadex-alerts"
                  className="w-full px-4 py-2.5 rounded-xl bg-white/3 border border-white/8 text-sm text-[#FAFAFA] placeholder:text-[#3F3F46] focus:outline-none focus:border-[#6366F1]/40 focus:bg-white/5 transition-all"
                />
              </div>
              <div>
                <label className="text-xs font-medium text-[#A1A1AA] mb-1.5 block">HMAC Secret <span className="text-[#52525B]">(optional)</span></label>
                <input
                  type="password"
                  value={config.secret || ""}
                  onChange={(e) => setConfig({ ...config, secret: e.target.value })}
                  placeholder="Any random string — used to verify authenticity"
                  className="w-full px-4 py-2.5 rounded-xl bg-white/3 border border-white/8 text-sm text-[#FAFAFA] placeholder:text-[#3F3F46] focus:outline-none focus:border-[#6366F1]/40 focus:bg-white/5 transition-all"
                />
                <p className="text-[10px] text-[#3F3F46] mt-1.5">CascadeX signs every request with this secret via HMAC-SHA256. Your server can verify using the X-CascadeX-Signature header.</p>
              </div>
              <div className="p-3 rounded-xl bg-white/2 border border-white/5">
                <p className="text-[10px] text-[#52525B] mb-2 font-medium uppercase tracking-wider">Quick test URLs</p>
                <div className="space-y-1.5">
                  {[
                    { label: "Local receiver", url: "http://172.22.0.1:9999/cascadex-webhook" },
                    { label: "webhook.site (free)", url: "https://webhook.site/your-unique-id" },
                  ].map((item) => (
                    <button key={item.label} onClick={() => setConfig({ ...config, url: item.url })}
                      className="w-full flex items-center justify-between px-3 py-2 rounded-lg bg-white/3 hover:bg-white/6 border border-white/5 transition-all group">
                      <span className="text-[11px] text-[#71717A] group-hover:text-[#A1A1AA]">{item.label}</span>
                      <span className="text-[10px] font-mono text-[#3F3F46] group-hover:text-[#52525B] truncate max-w-[200px]">{item.url}</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* SLACK TAB */}
          {activeTab === "slack" && (
            <div className="space-y-4">
              <div className="p-3 rounded-xl bg-[#22C55E]/6 border border-[#22C55E]/15 flex items-start gap-3">
                <MessageSquare className="h-4 w-4 text-[#4ADE80] flex-shrink-0 mt-0.5" />
                <p className="text-xs text-[#71717A] leading-relaxed">
                  Get instant Slack alerts when critical CVEs are detected. Go to Slack → Apps → Incoming Webhooks → Add New Webhook.
                </p>
              </div>
              <div>
                <label className="text-xs font-medium text-[#A1A1AA] mb-1.5 block">Slack Webhook URL</label>
                <input type="text" value={config.webhook_url || ""}
                  onChange={(e) => setConfig({ ...config, webhook_url: e.target.value })}
                  placeholder="https://hooks.slack.com/services/T.../B.../..."
                  className="w-full px-4 py-2.5 rounded-xl bg-white/3 border border-white/8 text-sm text-[#FAFAFA] placeholder:text-[#3F3F46] focus:outline-none focus:border-[#22C55E]/40 transition-all" />
              </div>
            </div>
          )}

          {/* JIRA TAB */}
          {activeTab === "jira" && (
            <div className="space-y-4">
              <div className="p-3 rounded-xl bg-[#3B82F6]/6 border border-[#3B82F6]/15 flex items-start gap-3">
                <TicketCheck className="h-4 w-4 text-[#60A5FA] flex-shrink-0 mt-0.5" />
                <p className="text-xs text-[#71717A] leading-relaxed">
                  Auto-create Jira tickets for critical vulnerabilities. Get your API token from id.atlassian.com → Security → API tokens.
                </p>
              </div>
              <div>
                <label className="text-xs font-medium text-[#A1A1AA] mb-1.5 block">Jira Base URL</label>
                <input type="text" value={config.base_url || ""}
                  onChange={(e) => setConfig({ ...config, base_url: e.target.value })}
                  placeholder="https://your-company.atlassian.net"
                  className="w-full px-4 py-2.5 rounded-xl bg-white/3 border border-white/8 text-sm text-[#FAFAFA] placeholder:text-[#3F3F46] focus:outline-none focus:border-[#3B82F6]/40 transition-all" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-medium text-[#A1A1AA] mb-1.5 block">Email</label>
                  <input type="email" value={config.email || ""}
                    onChange={(e) => setConfig({ ...config, email: e.target.value })}
                    className="w-full px-4 py-2.5 rounded-xl bg-white/3 border border-white/8 text-sm text-[#FAFAFA] focus:outline-none focus:border-[#3B82F6]/40 transition-all" />
                </div>
                <div>
                  <label className="text-xs font-medium text-[#A1A1AA] mb-1.5 block">API Token</label>
                  <input type="password" value={config.api_token || ""}
                    onChange={(e) => setConfig({ ...config, api_token: e.target.value })}
                    className="w-full px-4 py-2.5 rounded-xl bg-white/3 border border-white/8 text-sm text-[#FAFAFA] focus:outline-none focus:border-[#3B82F6]/40 transition-all" />
                </div>
              </div>
              <div>
                <label className="text-xs font-medium text-[#A1A1AA] mb-1.5 block">Project Key</label>
                <input type="text" value={config.project_key || ""}
                  onChange={(e) => setConfig({ ...config, project_key: e.target.value })}
                  placeholder="SEC or VULN"
                  className="w-full px-4 py-2.5 rounded-xl bg-white/3 border border-white/8 text-sm text-[#FAFAFA] focus:outline-none focus:border-[#3B82F6]/40 transition-all" />
              </div>
            </div>
          )}

          {/* PAGERDUTY TAB */}
          {activeTab === "pagerduty" && (
            <div className="space-y-4">
              <div className="p-3 rounded-xl bg-[#EF4444]/6 border border-[#EF4444]/15 flex items-start gap-3">
                <Siren className="h-4 w-4 text-[#F87171] flex-shrink-0 mt-0.5" />
                <p className="text-xs text-[#71717A] leading-relaxed">
                  Page your on-call engineer immediately when critical vulnerabilities are detected. Get your key from PagerDuty → Services → Integrations.
                </p>
              </div>
              <div>
                <label className="text-xs font-medium text-[#A1A1AA] mb-1.5 block">Integration Key</label>
                <input type="password" value={config.integration_key || ""}
                  onChange={(e) => setConfig({ ...config, integration_key: e.target.value })}
                  placeholder="Your PagerDuty Events API v2 key"
                  className="w-full px-4 py-2.5 rounded-xl bg-white/3 border border-white/8 text-sm text-[#FAFAFA] placeholder:text-[#3F3F46] focus:outline-none focus:border-[#EF4444]/40 transition-all" />
              </div>
            </div>
          )}

          {/* ACTIVITY TAB */}
          {activeTab === "activity" && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-[#E4E4E7]">Delivery Activity</p>
                  <p className="text-xs text-[#52525B]">Live webhook delivery log — auto-refreshes every 5s</p>
                </div>
                <button onClick={fetchActivity}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/4 hover:bg-white/8 border border-white/6 text-xs text-[#A1A1AA] hover:text-white transition-all">
                  <RefreshCw className={`h-3 w-3 ${loadingActivity ? "animate-spin" : ""}`} />
                  Refresh
                </button>
              </div>

              {/* Integration status bar */}
              {integStatus && (
                <div className="flex items-center gap-3 p-3 rounded-xl bg-white/2 border border-white/5">
                  <div className={`w-2 h-2 rounded-full ${integStatus.running ? "bg-[#4ADE80] animate-pulse" : "bg-[#F87171]"}`} />
                  <span className="text-xs text-[#A1A1AA]">
                    Worker {integStatus.running ? "active" : "stopped"} •{" "}
                    {integStatus.integrations_configured} integration{integStatus.integrations_configured !== 1 ? "s" : ""} •{" "}
                    Queue: {integStatus.queue_size}
                  </span>
                  <button onClick={handleTest} disabled={testing}
                    className="ml-auto flex items-center gap-1.5 px-3 py-1 rounded-lg bg-[#6366F1]/10 hover:bg-[#6366F1]/18 border border-[#6366F1]/20 text-xs text-[#818CF8] disabled:opacity-50 transition-all">
                    {testing ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Zap className="h-3 w-3" />}
                    {testing ? "Sending..." : "Send Test"}
                  </button>
                </div>
              )}

              {/* Delivery log */}
              <div className="space-y-2 max-h-[320px] overflow-y-auto
                [&::-webkit-scrollbar]:w-1
                [&::-webkit-scrollbar-track]:bg-transparent
                [&::-webkit-scrollbar-thumb]:bg-white/8
                [&::-webkit-scrollbar-thumb]:rounded-full">
                {activity.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-12 text-center">
                    <div className="w-12 h-12 rounded-full bg-white/3 flex items-center justify-center mb-3">
                      <Webhook className="h-5 w-5 text-[#3F3F46]" />
                    </div>
                    <p className="text-sm text-[#52525B]">No deliveries yet</p>
                    <p className="text-xs text-[#3F3F46] mt-1">Configure an integration and click Send Test</p>
                  </div>
                ) : (
                  activity.map((item: any, i: number) => (
                    <motion.div key={i}
                      initial={{ opacity: 0, x: -8 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.03 }}
                      className={`p-3 rounded-xl border transition-all ${
                        item.success
                          ? "bg-[#22C55E]/4 border-[#22C55E]/12"
                          : "bg-[#EF4444]/4 border-[#EF4444]/12"
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex items-center gap-2">
                          {item.success
                            ? <div className="w-1.5 h-1.5 rounded-full bg-[#4ADE80] flex-shrink-0 mt-1" />
                            : <div className="w-1.5 h-1.5 rounded-full bg-[#F87171] flex-shrink-0 mt-1" />
                          }
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="text-xs font-medium text-[#E4E4E7]">
                                {item.integration || "Unknown"}
                              </span>
                              <span className={`text-[10px] px-1.5 py-0.5 rounded-full border font-semibold`}
                                style={{
                                  color: severityColor(item.severity || "info"),
                                  backgroundColor: `${severityColor(item.severity || "info")}15`,
                                  borderColor: `${severityColor(item.severity || "info")}25`,
                                }}>
                                {(item.event_type || "event").replace(/_/g, " ")}
                              </span>
                              {item.status_code && (
                                <span className={`text-[10px] font-mono ${item.status_code === 200 ? "text-[#4ADE80]" : "text-[#F87171]"}`}>
                                  {item.status_code}
                                </span>
                              )}
                            </div>
                            {item.error && (
                              <p className="text-[10px] text-[#F87171] mt-0.5">{item.error}</p>
                            )}
                            {item.response_preview && (
                              <p className="text-[10px] text-[#52525B] mt-0.5 font-mono">{item.response_preview}</p>
                            )}
                          </div>
                        </div>
                        <span className="text-[10px] text-[#3F3F46] flex-shrink-0">
                          {item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : ""}
                        </span>
                      </div>
                    </motion.div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        {/* ── FOOTER ── */}
        {activeTab !== "activity" && (
          <div className="flex items-center justify-between gap-3 px-6 py-4 border-t border-white/6 bg-white/[0.01]">
            <button onClick={handleTest} disabled={testing}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-white/4 hover:bg-white/8 border border-white/6 text-xs text-[#A1A1AA] hover:text-white disabled:opacity-50 transition-all">
              {testing ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Zap className="h-3 w-3" />}
              {testing ? "Testing..." : "Send Test Event"}
            </button>
            <div className="flex items-center gap-2">
              <button onClick={onClose}
                className="px-4 py-2 rounded-xl bg-white/4 hover:bg-white/8 border border-white/6 text-[#A1A1AA] text-sm transition-all">
                Cancel
              </button>
              <button onClick={handleSave} disabled={saving}
                className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-[#3B82F6] to-[#6366F1] hover:from-[#2563EB] hover:to-[#4F46E5] disabled:opacity-50 text-white text-sm font-medium transition-all shadow-lg shadow-[#3B82F6]/20">
                {saving ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : saved ? <Check className="h-3.5 w-3.5" /> : <Send className="h-3.5 w-3.5" />}
                {saving ? "Saving..." : saved ? "Saved!" : "Save Integration"}
              </button>
            </div>
          </div>
        )}
      </motion.div>
    </div>
  );
};

const RiskBreakdown = ({ factors }: { factors: any }) => {
  if (!factors || typeof factors !== "object") return null;
  const cvssVal = safeNumber(factors.cvss_component, 0);
  const exploitVal = safeNumber(factors.exploitability ?? factors.exploit_component, 0);
  const exposureVal = safeNumber(factors.exposure ?? factors.exposure_component, 0);
  const assetVal = safeNumber(factors.asset_value ?? factors.criticality_component, 0);
  const chainVal = safeNumber(factors.chain_amplification, 0);
  const finalScore = safeNumber(factors.final_score ?? factors.risk_score ?? factors.raw_total, 0);
  const breakdown = safeArray<string>(factors.breakdown);
  const isBaseline = !!factors.is_baseline;

  const epssVal = safeNumber(factors.epss_score ?? 0, 0) * 100;
  const epssComp = safeNumber(factors.epss_component ?? 0, 0);

  const comps = [
    { label: "CVSS", value: cvssVal, max: 100, color: "#ef4444" },
    { label: "Exploitability", value: exploitVal, max: 100, color: "#F59E0B" },
    ...(epssVal > 0.1 ? [{ label: "EPSS", value: epssComp, max: 25, color: epssVal >= 50 ? "#F87171" : epssVal >= 10 ? "#FBBF24" : "#34D399" }] : []),
    { label: "Exposure", value: exposureVal, max: 100, color: "#F59E0B" },
    { label: "Asset/Criticality", value: assetVal, max: 100, color: "#3b82f6" },
  ];

  if (chainVal > 0) {
    comps.push({ label: "Chain Amp", value: chainVal, max: 100, color: "#8B5CF6" });
  }

  return (
    <div className="space-y-2">
      {isBaseline && (
        <p className="text-xs text-[#FBBF24] bg-[#F59E0B]/10 rounded px-2 py-1 mb-2">
          Baseline score — no confirmed asset match
        </p>
      )}
      {factors.reason && (
        <p className="text-xs text-[#A1A1AA] mb-2">{factors.reason}</p>
      )}
      {comps.map((c) => (
        <div key={c.label} className="flex items-center gap-3">
          <span className="text-xs text-[#A1A1AA] w-24">{c.label}</span>
          <div className="flex-1 h-2 bg-white/8 rounded-full overflow-hidden">
            <div
              className="h-full rounded-full"
              style={{
                width: `${Math.min((c.value / Math.max(c.max, 1)) * 100, 100)}%`,
                backgroundColor: c.color,
              }}
            />
          </div>
          <span className="text-xs text-[#E4E4E7] w-10 text-right">
            {c.value.toFixed(1)}
          </span>
        </div>
      ))}

      <div className="flex items-center gap-3 pt-2 border-t border-white/6">
        <span className="text-xs text-white font-bold w-24">Final Risk</span>
        <div className="flex-1 h-3 bg-white/8 rounded-full overflow-hidden">
          <div
            className="h-full rounded-full bg-gradient-to-r from-[#F59E0B] via-orange-500 to-[#EF4444]"
            style={{ width: `${Math.min(finalScore, 100)}%` }}
          />
        </div>
        <span
          className={`text-sm font-bold w-10 text-right ${
            finalScore >= 75
              ? "text-[#F87171]"
              : finalScore >= 50
              ? "text-[#FBBF24]"
              : finalScore >= 25
              ? "text-[#FCD34D]"
              : "text-[#4ADE80]"
          }`}
        >
          {Math.round(finalScore)}
        </span>
      </div>

      {breakdown.length > 0 && (
        <div className="mt-2 space-y-1">
          {breakdown.map((line, i) => (
            <p key={i} className="text-xs text-[#A1A1AA] flex items-start gap-2">
              <span className="text-[#4ADE80] mt-0.5">{String.fromCharCode(8226)}</span>
              {line}
            </p>
          ))}
        </div>
      )}
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════
// GRAPH MAPPERS
// ═══════════════════════════════════════════════════════════════

type InfraNodeType =
  | "vulnerability"
  | "vendor"
  | "product"
  | "application"
  | "database"
  | "server"
  | "network"
  | "gateway"
  | "cwe_category";

type InfraNodeStatus = "operational" | "warning" | "critical" | "exploited";

const mapToInfraType = (t: string): InfraNodeType => {
  const valid = new Set<InfraNodeType>([
    "vulnerability",
    "vendor",
    "product",
    "application",
    "database",
    "server",
    "network",
    "gateway",
    "cwe_category",
  ]);
  if (valid.has(t as InfraNodeType)) return t as InfraNodeType;
  if (t === "cms" || t === "framework") return "application";
  return "vulnerability";
};

const mapToInfraStatus = (s: string): InfraNodeStatus => {
  if (s === "critical") return "critical";
  if (s === "exploited") return "exploited";
  if (s === "warning") return "warning";
  return "operational";
};

const AlertsPanel = ({
  alerts,
  isOpen,
  onClose,
  onAcknowledge,
}: {
  alerts: AlertRecord[];
  isOpen: boolean;
  onClose: () => void;
  onAcknowledge: (id: number) => void;
}) => {
  if (!isOpen) return null;

  return (
    <motion.div
      initial={{ opacity: 0, x: 300 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 300 }}
      className="fixed right-0 top-0 h-full w-96 bg-[#0d0d12] border-l border-white/8 shadow-2xl z-50 overflow-hidden"
    >
      <div className="flex items-center justify-between p-4 border-b border-white/8">
        <div className="flex items-center gap-3">
          <BellRing className="h-5 w-5 text-[#F87171]" />
          <h2 className="text-lg font-semibold">Alerts</h2>
          <span className="px-2 py-0.5 rounded-full bg-[#EF4444]/15 text-[#F87171] text-xs font-bold">
            {alerts.filter((a) => !a.acknowledged).length}
          </span>
        </div>
        <button
          onClick={onClose}
          className="p-2 rounded-lg hover:bg-[#131318] text-[#A1A1AA]"
        >
          <ChevronRight className="h-5 w-5" />
        </button>
      </div>

      <div className="p-4 space-y-3 overflow-y-auto h-[calc(100%-64px)]">
        {alerts.length === 0 ? (
          <EmptyState icon={Bell} title="No alerts" description="You're all caught up." />
        ) : (
          alerts.map((alert) => (
            <motion.div
              key={alert.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className={`p-4 rounded-xl border ${
                alert.acknowledged
                  ? "bg-[#131318]/30 border-white/6 opacity-60"
                  : alert.severity === "critical"
                  ? "bg-[#EF4444]/6 border-[#EF4444]/18 backdrop-blur-sm"
                  : alert.severity === "high"
                  ? "bg-[#F59E0B]/10 border-[#F59E0B]/25"
                  : alert.severity === "medium"
                  ? "bg-yellow-500/10 border-yellow-500/40"
                  : "bg-[#131318]/50 border-white/8"
              }`}
            >
              <div className="flex items-start justify-between mb-2">
                <div className="flex items-center gap-2">
                  {alert.severity === "critical" ? (
                    <Siren className="h-4 w-4 text-[#F87171]" />
                  ) : alert.severity === "high" ? (
                    <AlertTriangle className="h-4 w-4 text-[#FBBF24]" />
                  ) : alert.severity === "medium" ? (
                    <AlertCircle className="h-4 w-4 text-[#FCD34D]" />
                  ) : (
                    <Info className="h-4 w-4 text-[#60A5FA]" />
                  )}

                  <span className="text-xs uppercase tracking-wide text-[#A1A1AA] font-semibold">
                    {(alert.type || "unknown").replace(/_/g, " ")}
                  </span>
                </div>
                <span className="text-xs text-[#52525B]">
                  {formatDate(alert.created_at)}
                </span>
              </div>

              <p className="text-sm text-[#FAFAFA] mb-3 leading-relaxed">
                {alert.message || "No alert message available"}
              </p>

              <div className="flex items-center justify-between">
                <span
                  className={`px-2 py-0.5 rounded-full text-xs font-bold ${
                    alert.severity === "critical"
                      ? "bg-[#EF4444]/15 text-[#F87171]"
                      : alert.severity === "high"
                      ? "bg-[#F59E0B]/15 text-[#FBBF24]"
                      : alert.severity === "medium"
                      ? "bg-[#F59E0B]/15 text-[#FCD34D]"
                      : "bg-[#3B82F6]/15 text-[#60A5FA]"
                  }`}
                >
                  {alert.severity}
                </span>

                {!alert.acknowledged ? (
                  <button
                    onClick={() => onAcknowledge(alert.id)}
                    className="px-3 py-1.5 rounded-lg bg-white/8 hover:bg-white/10 text-sm text-[#E4E4E7] flex items-center gap-2"
                  >
                    <Check className="h-3 w-3" />
                    Acknowledge
                  </button>
                ) : (
                  <span className="text-xs text-[#4ADE80] font-medium">
                    Acknowledged
                  </span>
                )}
              </div>
            </motion.div>
          ))
        )}
      </div>
    </motion.div>
  );
};

// ═══════════════════════════════════════════════════════════════
// MAIN APP
// ═══════════════════════════════════════════════════════════════

export function App() {
  const [rawData, setRawData] = useState<any[]>([]);
  const [nodes, setNodes] = useState<CVENode[]>([]);
  const [attackChains, setAttackChains] = useState<AttackChain[]>([]);
  const [timeline, setTimeline] = useState<Record<string, number[]>>({});
  const [riskPropagation, setRiskPropagation] = useState<RiskPropagation[]>([]);
  const [analytics, setAnalytics] = useState<Analytics | null>(null);
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [prioritization, setPrioritization] = useState<PrioritizedAction[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);

  const [isRunning, setIsRunning] = useState(false);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [simulationProgress, setSimulationProgress] = useState(0);
  const [lastUpdated, setLastUpdated] = useState("");
  const [backendConnected, setBackendConnected] = useState(false);
  const [backendError, setBackendError] = useState<string | null>(null);
  const [graphExpanded, setGraphExpanded] = useState(false);
  const [inventorySearch, setInventorySearch] = useState("");
  const [inventorySortBy, setInventorySortBy] = useState<
    "risk" | "cvss" | "relevance" | "tte"
  >("risk");
  const [showIrrelevant, setShowIrrelevant] = useState(false);
  const [activeView, setActiveView] = useState<
    "all" | "relevant" | "exploitable" | "unpatched"
  >("all");

  const [scanDepth, setScanDepth] = useState(30);
  const [severityFilter, setSeverityFilter] = useState("");
  const [maxResults, setMaxResults] = useState(50);
  const [keywords, setKeywords] = useState<string[]>([]);
  const [keywordInput, setKeywordInput] = useState("");

  const [monitorStatus, setMonitorStatus] = useState<MonitorStatus | null>(null);
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [alertsPanelOpen, setAlertsPanelOpen] = useState(false);
  const [complianceAssessment, setComplianceAssessment] =
    useState<ComplianceAssessment | null>(null);
  const [complianceLoading, setComplianceLoading] = useState(false);
  const [trendingData, setTrendingData] = useState<TrendingData | null>(null);
  const [trendingLoading, setTrendingLoading] = useState(false);
  const [activeScanResult, setActiveScanResult] = useState<ActiveScanResult | null>(null);
  const [activeScanning, setActiveScanning] = useState(false);
  const [integrationsOpen, setIntegrationsOpen] = useState(false);
  const [integrations, setIntegrations] = useState<IntegrationConfigRecord[]>([]);
  const [activeTab, setActiveTab] = useState<
    "intelligence" | "compliance" | "scanning" | "trending" | "alerts" | "integrations" | "assets"
  >("intelligence");

  const alertPollRef = useRef<number | undefined>(undefined);
  const monitorPollRef = useRef<number | undefined>(undefined);
  const trendPollRef = useRef<number | undefined>(undefined);
  const compliancePollRef = useRef<number | undefined>(undefined);

  const fetchWebhookDeliveries = useCallback(async () => {
    try {
      const data = await apiFetch<any>("/integrations/deliveries/?limit=20");
      setWebhookDeliveries(safeArray<any>(data.deliveries));
    } catch {}
  }, []);

  const fetchAssets = useCallback(async () => {
    try {
      const data = await apiFetch<{ assets?: any[] }>("/assets/?limit=100");
      setAssets(safeArray<any>(data.assets).map(normalizeAssetRecord));
    } catch {
      setAssets([]);
    }
  }, []);

  const fetchIntegrationStatus = useCallback(async () => {
    try {
      const data = await apiFetch<{
        status?: { integrations?: Array<{ type: string; enabled: boolean }> };
      }>("/integrations/status/");

      setIntegrations(
        safeArray<any>(data.status?.integrations).map((integration, index) => ({
          type: integration.type || `integration-${index}`,
          enabled: integration.enabled !== false,
          config: {},
        }))
      );
    } catch {
      setIntegrations([]);
    }
  }, []);

  const processResponse = useCallback((data: any, currentAssets: Asset[]) => {
    const rawNodes = safeArray<any>(data.vulnerabilities || data.nodes);
    const backendChains = safeArray<AttackChain>(data.attack_chains);
    const backendStatus = data.system_status as SystemStatus | undefined;
    const backendPrioritization = safeArray<PrioritizedAction>(
      data.prioritized_actions
    );

    const chainCounts = new Map<string, number>();
    for (const chain of backendChains) {
      for (const step of chain.steps) {
        chainCounts.set(step.cve_id, (chainCounts.get(step.cve_id) || 0) + 1);
      }
    }

    const enrichedNodes = rawNodes.map((raw: any) =>
      normalizeNode(raw, currentAssets, chainCounts)
    );

    const status: SystemStatus =
      backendStatus || {
        overall: "guarded",
        entry_points: enrichedNodes.filter((n) => n.is_entry_point).length,
        full_chains: backendChains.filter((c) => c.fully_exploitable).length,
        estimated_compromise: "low",
        top_risks: [],
        attack_surface: "Low",
        recommendation: "Continue monitoring.",
      };

    const actions = backendPrioritization.length > 0 ? backendPrioritization : [];
    const secEvents = buildSecurityEvents(enrichedNodes, backendChains, status);

    const total = enrichedNodes.length;
    const applicableNodes = enrichedNodes.filter(isApplicableNode);
    const relevant = applicableNodes.filter((n) => n.asset_relevant);
    const cvssValues = applicableNodes
      .map((n) => n.cvss_score)
      .filter((v): v is number => v !== null);
    const riskValues = applicableNodes
      .filter((n) => n.status !== "mitigated")
      .map((n) => n.risk);

    const computedAnalytics: Analytics = data.analytics
      ? {
          totalVulnerabilities:
            data.analytics.totalVulnerabilities ??
            data.analytics.total_vulnerabilities ??
            total,
          relevantVulnerabilities:
            data.analytics.relevantVulnerabilities ??
            data.analytics.relevant_vulnerabilities ??
            data.analytics.matched_vulnerabilities ??
            relevant.length,
          criticalCount:
            data.analytics.criticalCount ??
            data.analytics.critical_count ??
            applicableNodes.filter((n) => n.severity === "CRITICAL").length,
          highCount:
            data.analytics.highCount ??
            data.analytics.high_count ??
            applicableNodes.filter((n) => n.severity === "HIGH").length,
          mediumCount:
            data.analytics.mediumCount ??
            data.analytics.medium_count ??
            applicableNodes.filter((n) => n.severity === "MEDIUM").length,
          lowCount:
            data.analytics.lowCount ??
            data.analytics.low_count ??
            applicableNodes.filter((n) => n.severity === "LOW").length,
          avgCvssScore:
            data.analytics.avgCvssScore ??
            data.analytics.avg_cvss ??
            (cvssValues.length > 0
              ? cvssValues.reduce((a, b) => a + b, 0) / cvssValues.length
              : 0),
          avgRealRisk:
            data.analytics.avgRealRisk ??
            data.analytics.avgRisk ??
            (riskValues.length > 0
              ? riskValues.reduce((a, b) => a + b, 0) / riskValues.length
              : 0),
          exploitedCount:
            data.analytics.exploitedCount ??
            data.analytics.exploitable_count ??
            applicableNodes.filter(isBackendExploitableNode).length,
          patchedCount:
            data.analytics.patchedCount ??
            data.analytics.patched_count ??
            applicableNodes.filter((n) => n.patch_intel.available).length,
          systemHealth:
            data.analytics.systemHealth ?? data.analytics.system_health ?? 50,
          attackChainCount:
            data.analytics.attackChainCount ??
            data.analytics.attack_chain_count ??
            backendChains.length,
          connectedNodes:
            data.analytics.connectedNodes ??
            data.analytics.connected_nodes ??
            applicableNodes.filter((n) => n.connection_count > 0).length,
          isolatedNodes:
            data.analytics.isolatedNodes ??
            data.analytics.isolated_nodes ??
            applicableNodes.filter((n) => n.connection_count === 0).length,
          patchCoverage:
            data.analytics.patchCoverage ??
            data.analytics.patch_coverage ??
            (applicableNodes.length > 0
              ? Math.round(
                  (applicableNodes.filter((n) => n.patch_intel.available).length /
                    applicableNodes.length) *
                    100
                )
              : 0),
          assetCoverage:
            data.analytics.assetCoverage ??
            data.analytics.asset_coverage ??
            (currentAssets.length > 0 && applicableNodes.length > 0
              ? Math.round(
                  (relevant.length / Math.max(1, applicableNodes.length)) * 100
                )
              : 0),
        }
      : {
          totalVulnerabilities: total,
          relevantVulnerabilities: relevant.length,
          criticalCount: applicableNodes.filter((n) => n.severity === "CRITICAL").length,
          highCount: applicableNodes.filter((n) => n.severity === "HIGH").length,
          mediumCount: applicableNodes.filter((n) => n.severity === "MEDIUM").length,
          lowCount: applicableNodes.filter((n) => n.severity === "LOW").length,
          avgCvssScore:
            cvssValues.length > 0
              ? cvssValues.reduce((a, b) => a + b, 0) / cvssValues.length
              : 0,
          avgRealRisk:
            riskValues.length > 0
              ? riskValues.reduce((a, b) => a + b, 0) / riskValues.length
              : 0,
          exploitedCount: applicableNodes.filter(isBackendExploitableNode).length,
          patchedCount: applicableNodes.filter((n) => n.patch_intel.available).length,
          systemHealth: 50,
          attackChainCount: backendChains.length,
          connectedNodes: applicableNodes.filter((n) => n.connection_count > 0).length,
          isolatedNodes: applicableNodes.filter((n) => n.connection_count === 0).length,
          patchCoverage:
            applicableNodes.length > 0
              ? Math.round(
                  (applicableNodes.filter((n) => n.patch_intel.available).length /
                    applicableNodes.length) *
                    100
                )
              : 0,
          assetCoverage:
            currentAssets.length > 0 && applicableNodes.length > 0
              ? Math.round(
                  (relevant.length / Math.max(1, applicableNodes.length)) * 100
                )
              : 0,
        };

    return {
      enrichedNodes,
      backendChains,
      status,
      actions,
      secEvents,
      computedAnalytics,
    };
  }, []);

  const fetchStoredIntelligence = useCallback(async () => {
    try {
      const data = await apiFetch<any>(
        `/cascade/nodes/?limit=${maxResults}&include_infrastructure=true`
      );

      const rawNodes = safeArray<any>(data.nodes || data.vulnerabilities);
      if (rawNodes.length === 0) {
        return;
      }

      setRawData(rawNodes);
      const {
        enrichedNodes,
        backendChains,
        status,
        actions,
        secEvents,
        computedAnalytics,
      } = processResponse(data, assets);

      setNodes(enrichedNodes);
      setAttackChains(backendChains);
      setTimeline(data.timeline || {});
      setRiskPropagation(safeArray<RiskPropagation>(data.risk_propagation));
      setAnalytics(computedAnalytics);
      setSystemStatus(status);
      setPrioritization(actions);
      setEvents(secEvents);
      setLastUpdated(formatTimestamp());
    } catch {
      // Keep the dashboard usable even if stored intelligence isn't available yet.
    }
  }, [assets, maxResults, processResponse]);

  const checkBackendHealth = useCallback(async () => {
    try {
      const r = await fetch(`${API_BASE_URL}/health/`);
      const payload = await r.json().catch(() => ({}));
      if (!r.ok) {
        const dbError =
          typeof payload?.database?.error === "string" ? payload.database.error : "";
        const statusLabel =
          typeof payload?.status === "string" ? payload.status : `HTTP ${r.status}`;
        throw new Error(dbError || statusLabel);
      }
      setBackendConnected(true);
      setBackendError(null);
      return true;
    } catch (err) {
      setBackendConnected(false);
      setBackendError(err instanceof Error ? err.message : "Cannot connect");
      return false;
    }
  }, []);

  const fetchMonitorStatus = useCallback(async () => {
    try {
      const data = await apiFetch<MonitorStatus>("/monitor/status/");
      setMonitorStatus(data);
    } catch {}
  }, []);

  const toggleMonitor = useCallback(async () => {
    const isRunning = monitorStatus?.running ?? false;
    const action = isRunning ? "stop" : "start";

    // Optimistic UI update immediately
    setMonitorStatus((prev) =>
      prev ? { ...prev, running: !isRunning } : null
    );

    try {
      const data = await apiFetch<{ success: boolean; status: MonitorStatus }>(
        "/monitor/control/",
        {
          method: "POST",
          body: JSON.stringify({ action }),
        }
      );

      // Use the real status returned by backend
      if (data?.status) {
        setMonitorStatus(data.status);
      } else {
        // Fallback: fetch fresh status after short delay
        setTimeout(() => fetchMonitorStatus(), 500);
      }
    } catch (err) {
      // Revert optimistic update on failure
      setMonitorStatus((prev) =>
        prev ? { ...prev, running: isRunning } : null
      );
      setBackendError(
        err instanceof Error ? err.message : "Monitor control failed"
      );
    }
  }, [monitorStatus, fetchMonitorStatus]);

  const fetchAlerts = useCallback(async () => {
    try {
      const data = await apiFetch<{ alerts: AlertRecord[] }>("/alerts/?limit=50");
      setAlerts(safeArray<AlertRecord>(data.alerts));
    } catch {}
  }, []);

  const acknowledgeAlert = useCallback(async (id: number) => {
    try {
      await apiFetch(`/alerts/${id}/acknowledge/`, {
        method: "POST",
        body: JSON.stringify({ acknowledged_by: "dashboard" }),
      });
      setAlerts((prev) =>
        prev.map((a) => (a.id === id ? { ...a, acknowledged: true } : a))
      );
    } catch (err) {
      setBackendError(err instanceof Error ? err.message : "Alert acknowledgement failed");
    }
  }, []);

  const fetchComplianceAssessment = useCallback(async () => {
    setComplianceLoading(true);
    try {
      const data = await apiFetch<ComplianceAssessment>("/compliance/");
      setComplianceAssessment(data);
    } catch (err) {
      setBackendError(err instanceof Error ? err.message : "Compliance fetch failed");
    } finally {
      setComplianceLoading(false);
    }
  }, []);

  const fetchTrendingData = useCallback(async () => {
    setTrendingLoading(true);
    try {
      const data = await apiFetch<TrendingData>("/trending/?days=30");
      setTrendingData(data);
    } catch (err) {
      setBackendError(err instanceof Error ? err.message : "Trending fetch failed");
    } finally {
      setTrendingLoading(false);
    }
  }, []);

  const captureSnapshot = useCallback(async () => {
    try {
      await apiFetch("/trending/snapshot/", { method: "POST" });
      await fetchTrendingData();
    } catch (err) {
      setBackendError(err instanceof Error ? err.message : "Snapshot failed");
    }
  }, [fetchTrendingData]);

  const runActiveScan = useCallback(
    async (target: string, scanType: string) => {
      setActiveScanning(true);
      setBackendError(null);

      try {
        const data = await apiFetch<ActiveScanResult>("/scan/active/", {
          method: "POST",
          body: JSON.stringify({ target, scan_type: scanType }),
        });

        setActiveScanResult(data);

        if (data.success && (data.assets_saved || 0) > 0) {
          await fetchAssets();
        }

        // Refresh dependent panels after scan
        await Promise.allSettled([
          fetchComplianceAssessment(),
          fetchTrendingData(),
          fetchAlerts(),
        ]);
      } catch (err) {
        setBackendError(err instanceof Error ? err.message : "Active scan failed");
        setActiveScanResult({
          success: false,
          scan_type: scanType,
          target,
          hosts: [],
          host_count: 0,
          total_services: 0,
          vulnerabilities_found: [],
          duration: 0,
          error: err instanceof Error ? err.message : "Active scan failed",
        });
      } finally {
        setActiveScanning(false);
      }
    },
    [fetchAssets, fetchComplianceAssessment, fetchTrendingData, fetchAlerts]
  );

  const saveIntegration = useCallback(async (config: IntegrationConfigRecord) => {
    try {
      await apiFetch("/integrations/configure/", {
        method: "POST",
        body: JSON.stringify({ type: config.type, config: config.config }),
      });
      await fetchIntegrationStatus();
    } catch (err) {
      setBackendError(err instanceof Error ? err.message : "Integration save failed");
    }
  }, [fetchIntegrationStatus]);

  const handleScanCVEs = useCallback(async () => {
    setIsRunning(true);
    setSimulationProgress(10);
    setBackendError(null);

    try {
      const payload: Record<string, unknown> = {
        days_back: scanDepth,
        max_results: maxResults,
        include_infrastructure: true,
      };
      if (keywords.length > 0) payload.keywords = keywords;
      if (severityFilter) payload.severity = severityFilter;

      setSimulationProgress(35);

      const data = await apiFetch<any>("/scan/", {
        method: "POST",
        body: JSON.stringify(payload),
      });

      setSimulationProgress(70);

      setRawData(safeArray<any>(data.vulnerabilities || data.nodes));
      const {
        enrichedNodes,
        backendChains,
        status,
        actions,
        secEvents,
        computedAnalytics,
      } = processResponse(data, assets);

      setNodes(enrichedNodes);
      setAttackChains(backendChains);
      setTimeline(data.timeline || {});
      setRiskPropagation(safeArray<RiskPropagation>(data.risk_propagation));
      setAnalytics(computedAnalytics);
      setSystemStatus(status);
      setPrioritization(actions);
      setEvents(secEvents);
      setSimulationProgress(100);
      setBackendConnected(true);
      setBackendError(null);
      setLastUpdated(formatTimestamp());

      await Promise.allSettled([
        fetchComplianceAssessment(),
        fetchTrendingData(),
        fetchAlerts(),
      ]);
    } catch (err) {
      setBackendError(err instanceof Error ? err.message : "Scan failed");
      await checkBackendHealth();
    } finally {
      setIsRunning(false);
      setTimeout(() => setSimulationProgress(0), 800);
    }
  }, [
    keywords,
    severityFilter,
    scanDepth,
    maxResults,
    assets,
    checkBackendHealth,
    processResponse,
    fetchComplianceAssessment,
    fetchTrendingData,
    fetchAlerts,
  ]);

  const handleMitigate = useCallback(async (nodeId: string, action: string) => {
    try {
      const data = await apiFetch<{ success: boolean }>("/mitigate/", {
        method: "POST",
        body: JSON.stringify({
          cve_id: nodeId,
          action,
          notes: `UI ${new Date().toISOString()}`,
        }),
      });

      if (data.success) {
        setNodes((prev) =>
          prev.map((n) =>
            n.id === nodeId || n.cve_id === nodeId
              ? {
                  ...n,
                  status: "mitigated" as const,
                  risk: Math.max(3, n.risk * 0.1),
                }
              : n
          )
        );
        setEvents((prev) => [
          {
            id: Date.now(),
            timestamp: formatTimestamp(),
            type: "mitigation",
            severity: "medium",
            message: `Mitigation applied to ${nodeId}`,
            cve: nodeId,
          },
          ...prev.slice(0, MAX_EVENTS - 1),
        ]);

        Promise.allSettled([fetchComplianceAssessment(), fetchTrendingData()]);
      }
    } catch (err) {
      setBackendError(err instanceof Error ? err.message : "Mitigation failed");
    }
  }, [fetchComplianceAssessment, fetchTrendingData]);

  const handleReset = useCallback(() => {
    setRawData([]);
    setNodes([]);
    setAttackChains([]);
    setTimeline({});
    setRiskPropagation([]);
    setAnalytics(null);
    setSystemStatus(null);
    setPrioritization([]);
    setSelectedNode(null);
    setEvents([]);
    setLastUpdated("");
    setBackendError(null);
    setSimulationProgress(0);
    setComplianceAssessment(null);
    setTrendingData(null);
    setActiveScanResult(null);
    setKeywordInput("");
    setKeywords([]);
  }, []);

  useEffect(() => {
    const initializeDashboard = async () => {
      const healthy = await checkBackendHealth();

      if (!healthy) return;

      await Promise.allSettled([
        fetchAssets(),
        fetchMonitorStatus(),
        fetchAlerts(),
        fetchComplianceAssessment(),
        fetchTrendingData(),
        fetchIntegrationStatus(),
      ]);

      await fetchStoredIntelligence();
    };

    initializeDashboard();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // Run once on mount only — polling handles subsequent updates

  useEffect(() => {
    if (rawData.length === 0) return;
    const { enrichedNodes, secEvents } = processResponse(
      {
        vulnerabilities: rawData,
        attack_chains: attackChains,
        system_status: systemStatus,
        prioritized_actions: prioritization,
        analytics,
      },
      assets
    );
    setNodes(enrichedNodes);
    setEvents(secEvents);
  }, [assets]);

  useEffect(() => {
    if (alertPollRef.current) window.clearInterval(alertPollRef.current);
    if (backendConnected) {
      alertPollRef.current = window.setInterval(fetchAlerts, ALERT_POLL_INTERVAL);
    }
    return () => {
      if (alertPollRef.current) window.clearInterval(alertPollRef.current);
    };
  }, [backendConnected, fetchAlerts]);

  useEffect(() => {
    if (monitorPollRef.current) window.clearInterval(monitorPollRef.current);
    if (backendConnected) {
      monitorPollRef.current = window.setInterval(
        fetchMonitorStatus,
        MONITOR_POLL_INTERVAL
      );
    }
    return () => {
      if (monitorPollRef.current) window.clearInterval(monitorPollRef.current);
    };
  }, [backendConnected, fetchMonitorStatus]);

  useEffect(() => {
    if (trendPollRef.current) window.clearInterval(trendPollRef.current);
    if (backendConnected) {
      trendPollRef.current = window.setInterval(fetchTrendingData, TREND_POLL_INTERVAL);
    }
    return () => {
      if (trendPollRef.current) window.clearInterval(trendPollRef.current);
    };
  }, [backendConnected, fetchTrendingData]);

  useEffect(() => {
    if (compliancePollRef.current) window.clearInterval(compliancePollRef.current);
    if (backendConnected) {
      compliancePollRef.current = window.setInterval(
        fetchComplianceAssessment,
        COMPLIANCE_POLL_INTERVAL
      );
    }
    return () => {
      if (compliancePollRef.current) window.clearInterval(compliancePollRef.current);
    };
  }, [backendConnected, fetchComplianceAssessment]);

  const applicableNodes = useMemo(
    () => nodes.filter(isApplicableNode),
    [nodes]
  );

  const hasAssetInventory = systemStatus?.has_asset_inventory ?? assets.length > 0;
  const displayNodes = useMemo(() => {
    if (!hasAssetInventory || showIrrelevant) return nodes;
    // Always show ALL CVEs — sort asset-matched to top, unmatched below
    const matched = nodes.filter(n => n.status !== "irrelevant");
    const unmatched = nodes.filter(n => n.status === "irrelevant");
    return [...matched, ...unmatched];
  }, [nodes, hasAssetInventory, showIrrelevant]);
  const deprioritizedCount = Math.max(0, nodes.length - applicableNodes.length);
  const hiddenIrrelevantCount = 0;  // No longer hiding anything
  const complianceGenericOnly =
    !!complianceAssessment &&
    hasAssetInventory &&
    (complianceAssessment.data_sources?.asset_matched_vulnerabilities ?? 0) === 0 &&
    (complianceAssessment.total_vulnerabilities || 0) > 0;

  const filteredNodes = useMemo(() => {
    let filtered = displayNodes;

    if (activeView === "relevant") filtered = filtered.filter((n) => n.asset_relevant);
    else if (activeView === "exploitable")
      filtered = filtered.filter(isBackendExploitableNode);
    else if (activeView === "unpatched")
      filtered = filtered.filter(
        (n) => !n.patch_intel.available && n.severity === "CRITICAL"
      );

    if (inventorySearch.trim()) {
      const s = inventorySearch.toLowerCase();
      filtered = filtered.filter(
        (n) =>
          (n.cve_id || "").toLowerCase().includes(s) ||
          n.description.toLowerCase().includes(s) ||
          n.affected_products.some((p) => p.toLowerCase().includes(s))
      );
    }

    return [...filtered].sort((a, b) => {
      if (inventorySortBy === "cvss") return (b.cvss_score || 0) - (a.cvss_score || 0);
      if (inventorySortBy === "relevance") return b.relevance_score - a.relevance_score;
      if (inventorySortBy === "tte") {
        const o = { minutes: 0, hours: 1, days: 2, weeks: 3, unknown: 4 };
        return (o[a.time_to_exploit.estimate] || 4) - (o[b.time_to_exploit.estimate] || 4);
      }
      return b.risk - a.risk;
    });
  }, [
    displayNodes,
    inventorySearch,
    inventorySortBy,
    activeView,
    showIrrelevant,
  ]);

  // Build raw CVE data for graph's internal transformer (vendor->product->CVE hierarchy)
  const graphCVEData = useMemo(
    () =>
      displayNodes
        .filter((cve) => cve.status !== "irrelevant")
        .map((cve) => ({
          cve_id: cve.cve_id || cve.id,
          description: cve.description || "",
          cvss_score: cve.cvss_score ?? 0,
          severity: cve.severity || "MEDIUM",
          attack_vector: cve.attack_vector || "",
          attack_complexity: cve.attack_complexity || "",
          privileges_required: cve.privileges_required || "",
          user_interaction: cve.user_interaction || "",
          scope: cve.scope || "",
          exploit_available: isBackendExploitableNode(cve),
          patch_available: cve.patch_intel?.available || false,
          affected_products: cve.affected_products || [],
          affected_vendors: cve.affected_vendors || [],
          cwe_ids: cve.cwe_ids || [],
          published_date: cve.published_date || "",
          last_modified_date: "",
          vuln_status: cve.status || "",
          references: cve.references || [],
          // ── EPSS fields ─────────────────────────────────────────────
          epss_score: cve.epss_score ?? cve.risk_factors?.epss_score ?? null,
          epss_percentile: cve.epss_percentile ?? cve.risk_factors?.epss_percentile ?? null,
          epss_updated_at: cve.epss_updated_at ?? null,
          // ── Asset confirmation ────────────────────────────────────────
          cisa_kev: cve.cisa_kev ?? false,
          asset_matches: cve.asset_matches ?? [],
        })),
    [displayNodes]
  );

  // Empty array for nodes prop — graph will use rawCVEData instead
  const graphNodes: any[] = [];

  const unacknowledgedAlerts = alerts.filter((a) => !a.acknowledged).length;

  const alertLevel = useMemo(() => {
    if (!systemStatus) return "medium";
    if (
      systemStatus.overall === "compromised" ||
      systemStatus.overall === "critical"
    ) {
      return "critical";
    }
    if (systemStatus.overall === "at_risk") return "high";
    return "medium";
  }, [systemStatus]);

  const executiveSummary = useMemo(() => {
    const criticalNodes =
      systemStatus?.critical_count ??
      applicableNodes.filter((node) => node.severity === "CRITICAL").length;
    const exploitableNodes =
      systemStatus?.exploitable_count ??
      applicableNodes.filter(isBackendExploitableNode).length;
    const matchedAssets =
      systemStatus?.matched_vulnerabilities ??
      applicableNodes.filter((node) => node.asset_relevant).length;

    return {
      criticalNodes,
      exploitableNodes,
      matchedAssets,
      healthLabel: systemStatus?.overall
        ? systemStatus.overall.replace(/_/g, " ")
        : backendConnected
        ? "ready"
        : "offline",
    };
  }, [applicableNodes, backendConnected, systemStatus]);

  return (
    <div className="min-h-screen bg-[#09090B] text-[#FAFAFA]">
      <header className="border-b border-white/5 bg-[#09090B]/80 backdrop-blur-2xl sticky top-0 z-50 shadow-[0_1px_0_rgba(255,255,255,0.04)]">
        <div className="max-w-[1920px] mx-auto px-6 py-4">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <motion.div
                initial={{ rotate: 0 }}
                animate={{ rotate: isRunning ? 360 : 0 }}
                transition={{
                  duration: 2,
                  repeat: isRunning ? Infinity : 0,
                  ease: "linear",
                }}
                className="h-11 w-11 rounded-xl bg-gradient-to-br from-[#3B82F6] to-[#6366F1] flex items-center justify-center shadow-lg shadow-[#3B82F6]/30 ring-1 ring-white/10"
              >
                <ShieldAlert className="h-6 w-6 text-white" />
              </motion.div>
              <div>
                <h1 className="text-xl font-bold tracking-tight bg-gradient-to-r from-[#60A5FA] via-[#818CF8] to-[#A78BFA] bg-clip-text text-transparent">
                  CascadeX Intelligence
                </h1>
                <p className="text-xs text-[#52525B] mt-0.5 tracking-wide">
                  v4.0 — Full-spectrum vulnerability management
                </p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              {/* User welcome + logout */}
              {(() => {
                const savedUser = localStorage.getItem('cascadex_user');
                const user = savedUser ? JSON.parse(savedUser) : null;
                const displayName = user?.first_name || user?.username || 'User';
                return (
                  <div className="flex items-center gap-2">
                    <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white/[0.04] border border-white/[0.08]">
                      <UserCircle className="h-4 w-4 text-[#818CF8]" />
                      <span className="text-[13px] text-[#A1A1AA]">
                        Welcome, <span className="text-white font-medium">{displayName}</span>
                      </span>
                    </div>
                    <button
                      onClick={() => {
                        localStorage.removeItem('cascadex_access');
                        localStorage.removeItem('cascadex_refresh');
                        localStorage.removeItem('cascadex_user');
                        window.location.href = '/login';
                      }}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/[0.04] border border-white/[0.08] hover:bg-red-500/10 hover:border-red-500/30 text-[#71717A] hover:text-red-400 transition-all duration-200"
                      title="Sign out"
                    >
                      <LogOut className="h-4 w-4" />
                      <span className="hidden sm:inline text-[13px]">Sign out</span>
                    </button>
                  </div>
                );
              })()}

              <button
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border ${
                  backendConnected
                    ? "bg-[#22C55E]/10 border-[#22C55E]/25 backdrop-blur-sm"
                    : "bg-[#EF4444]/10 border-[#EF4444]/25 backdrop-blur-sm"
                }`}
                onClick={checkBackendHealth}
              >
                {backendConnected ? (
                  <Wifi className="h-4 w-4 text-[#4ADE80]" />
                ) : (
                  <AlertCircle className="h-4 w-4 text-[#F87171]" />
                )}
                <span
                  className={`text-xs font-medium ${
                    backendConnected ? "text-[#4ADE80]" : "text-[#F87171]"
                  }`}
                >
                  {backendConnected ? "Connected" : "Offline"}
                </span>
              </button>

              <MonitorStatusBadge status={monitorStatus} onToggle={toggleMonitor} />
              <AlertBadge count={unacknowledgedAlerts} onClick={() => setAlertsPanelOpen(true)} />

              <button
                onClick={() => setIntegrationsOpen(true)}
                className="p-2 rounded-lg bg-white/4 border border-white/8 hover:bg-white/8 hover:border-white/12 text-[#A1A1AA] hover:text-white transition-all duration-200"
                title="Integrations"
              >
                <Webhook className="h-4 w-4" />
              </button>

              {analytics && (
                <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-white/4 border border-white/8 backdrop-blur-sm">
                  <Activity
                    className={`h-5 w-5 ${
                      alertLevel === "critical"
                        ? "text-[#F87171] animate-pulse"
                        : alertLevel === "high"
                        ? "text-[#FBBF24]"
                        : "text-[#FCD34D]"
                    }`}
                  />
                  <span className="text-sm font-medium">
                    Risk:{" "}
                    <span className="font-bold">
                      {Number.isFinite(analytics.avgRealRisk)
                        ? Math.round(analytics.avgRealRisk)
                        : 0}
                    </span>
                    <span className="text-[#71717A]">/100</span>
                  </span>
                </div>
              )}

              {(analytics || nodes.length > 0) && (
                <button
                  onClick={async () => {
                    try {
                      const exportPayload = await apiFetch<any>("/report/export/?days=30");
                      const blob = new Blob(
                        [JSON.stringify(exportPayload, null, 2)],
                        { type: "application/json" }
                      );
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement("a");
                      a.href = url;
                      a.download = `cascadex_${new Date().toISOString().split("T")[0]}.json`;
                      a.click();
                      URL.revokeObjectURL(url);
                    } catch (err) {
                      setBackendError(
                        err instanceof Error ? err.message : "Export failed"
                      );
                    }
                  }}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 border border-white/8 hover:border-white/14 text-[#A1A1AA] hover:text-white text-sm transition-all duration-200"
                >
                  <Download className="h-4 w-4" />
                  <span className="hidden md:inline">Export</span>
                </button>
              )}

              <button
                onClick={handleReset}
                className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/8 hover:border-white/14 text-[#A1A1AA] hover:text-white font-medium transition-all duration-200"
              >
                <RotateCcw className="h-4 w-4" />
                Reset
              </button>

              <button
                onClick={handleScanCVEs}
                disabled={isRunning || !backendConnected}
                className="flex items-center gap-2 px-6 py-2.5 rounded-lg font-medium bg-gradient-to-r from-[#3B82F6] to-[#6366F1] hover:from-[#2563EB] hover:to-[#4F46E5] disabled:opacity-40 text-white shadow-lg shadow-[#3B82F6]/25 hover:shadow-[#3B82F6]/35 hover:-translate-y-px transition-all duration-200"
              >
                {isRunning ? (
                  <motion.div
                    animate={{ rotate: 360 }}
                    transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                  >
                    <RefreshCw className="h-4 w-4" />
                  </motion.div>
                ) : (
                  <ScanLine className="h-4 w-4" />
                )}
                {isRunning ? "Scanning..." : "Scan CVEs"}
              </button>
            </div>
          </div>

          {simulationProgress > 0 && (
            <div className="mt-4 h-0.5 bg-white/6 rounded-full overflow-hidden">
              <motion.div
                className="h-full bg-gradient-to-r from-[#3B82F6] to-[#6366F1] rounded-full"
                initial={{ width: 0 }}
                animate={{ width: `${simulationProgress}%` }}
              />
            </div>
          )}

          <div className="flex items-center gap-2 mt-4">
            {[
              { id: "intelligence" as const, icon: Network, label: "Intelligence" },
              { id: "compliance" as const, icon: FileCheck, label: "Compliance" },
              { id: "scanning" as const, icon: RadarIcon, label: "Active Scan" },
              { id: "trending" as const, icon: LineChart, label: "Trending" },
              { id: "alerts" as const, icon: BellRing, label: "Alerts" },
              { id: "assets" as const, icon: Server, label: "Assets" },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => {
                  setActiveTab(tab.id);
                  if (tab.id === "compliance") fetchComplianceAssessment();
                  if (tab.id === "trending") fetchTrendingData();
                  if (tab.id === "alerts") fetchAlerts();
                }}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                  activeTab === tab.id
                    ? "bg-[#3B82F6]/15 text-[#60A5FA] border border-[#3B82F6]/30 shadow-[0_0_12px_rgba(59,130,246,0.15)]"
                    : "bg-white/3 text-[#71717A] border border-white/6 hover:bg-white/6 hover:text-[#A1A1AA] hover:border-white/10 transition-all duration-200"
                }`}
              >
                <tab.icon className="h-4 w-4" />
                {tab.label}
              </button>
            ))}
          </div>

          {lastUpdated && (
            <div className="mt-2 text-xs text-[#52525B] text-right tracking-wide">
              Updated: {lastUpdated}
            </div>
          )}
        </div>
      </header>

      <main className="max-w-[1920px] mx-auto px-6 py-6">
        <AnimatePresence>
          {backendError && (
            <motion.div
              initial={{ opacity: 0, y: -14 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -14 }}
              className="mb-6 p-4 rounded-xl border bg-amber-500/15 border-amber-500/40"
            >
              <div className="flex items-center gap-3">
                <AlertCircle className="h-6 w-6 text-[#FBBF24]" />
                <div className="flex-1">
                  <p className="font-semibold text-[#FBBF24]">Backend Warning</p>
                  <p className="text-sm text-[#E4E4E7]">{backendError}</p>
                </div>
                <button
                  onClick={checkBackendHealth}
                  className="px-4 py-2 rounded-lg bg-[#F59E0B]/15 text-amber-300 text-sm flex items-center gap-2"
                >
                  <RefreshCw className="h-3 w-3" />
                  Retry
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {activeTab === "intelligence" && (
          <>
            <div className="grid grid-cols-1 gap-6 2xl:grid-cols-[1.45fr_1fr] mb-6">
              <div className="relative overflow-hidden rounded-[32px] border border-white/10 bg-[linear-gradient(135deg,rgba(9,9,11,0.95),rgba(13,13,18,0.90))] p-6 shadow-[0_24px_90px_rgba(9,9,11,0.60)]">
                <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(99,102,241,0.16),transparent_30%),radial-gradient(circle_at_bottom_right,rgba(59,130,246,0.10),transparent_28%)]" />
                <div className="relative grid gap-5 lg:grid-cols-[1.4fr_repeat(3,minmax(0,1fr))]">
                  <div className="space-y-4">
                    <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs uppercase tracking-[0.28em] text-[#E4E4E7]">
                      <Activity className="h-3.5 w-3.5 text-[#FCA5A5]" />
                      Release Readiness
                    </div>
                    <div>
                      <h2 className="max-w-xl text-3xl font-semibold tracking-tight text-white md:text-4xl">
                        Operational clarity for high-risk exposure before release.
                      </h2>
                      <p className="mt-3 max-w-2xl text-sm leading-6 text-[#E4E4E7]">
                        Review attack chains, asset relevance, mitigations, and live alerting in one place with cleaner triage and scan controls.
                      </p>
                    </div>
                    <div className="flex flex-wrap gap-3 text-sm text-[#E4E4E7]">
                      <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1.5">
                        Posture: <span className="font-semibold capitalize text-white">{executiveSummary.healthLabel}</span>
                      </span>
                      <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1.5">
                        Assets in scope: <span className="font-semibold text-white">{assets.length}</span>
                      </span>
                      <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1.5">
                        Integrations: <span className="font-semibold text-white">{integrations.length}</span>
                      </span>
                    </div>
                  </div>

                  {[
                    {
                      label: "Critical Findings",
                      value: executiveSummary.criticalNodes,
                      tone: "text-[#FCA5A5]",
                    },
                    {
                      label: "Exploitable CVEs",
                      value: executiveSummary.exploitableNodes,
                      tone: "text-[#FCD34D]",
                    },
                    {
                      label: "Asset-Matched CVEs",
                      value: executiveSummary.matchedAssets,
                      tone: "text-[#67E8F9]",
                    },
                  ].map((item) => (
                    <div
                      key={item.label}
                      className="rounded-[24px] border border-white/10 bg-[#09090B]/45 p-5 backdrop-blur"
                    >
                      <p className="text-xs uppercase tracking-[0.24em] text-[#A1A1AA]">
                        {item.label}
                      </p>
                      <p className={`mt-4 text-4xl font-semibold tracking-tight ${item.tone}`}>
                        {item.value}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="rounded-[32px] border border-white/10 bg-[#0d0d12]/78 p-6 shadow-[0_24px_90px_rgba(9,9,11,0.50)] backdrop-blur-xl">
                <div className="mb-5 flex items-start justify-between gap-4">
                  <div>
                    <p className="text-xs uppercase tracking-[0.24em] text-[#A1A1AA]">
                      Scan Control Center
                    </p>
                    <h3 className="mt-2 text-2xl font-semibold tracking-tight text-white">
                      Tune coverage before every run
                    </h3>
                  </div>
                  <button
                    onClick={handleScanCVEs}
                    disabled={isRunning || !backendConnected}
                    className="rounded-2xl bg-gradient-to-r from-[#EF4444] to-[#F59E0B] px-4 py-2.5 text-sm font-semibold text-white shadow-lg shadow-red-500/25 transition hover:from-[#F87171] hover:to-[#FBBF24] disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {isRunning ? "Scanning..." : "Run Scan"}
                  </button>
                </div>

                <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                  <div>
                    <label className="mb-1.5 block text-xs uppercase tracking-[0.22em] text-[#A1A1AA]">
                      Severity
                    </label>
                    <select
                      value={severityFilter}
                      onChange={(e) => setSeverityFilter(e.target.value)}
                      className="w-full rounded-2xl border border-white/10 bg-[#09090B]/70 px-4 py-3 text-sm text-white outline-none transition focus:border-red-400/60"
                    >
                      <option value="">All severities</option>
                      <option value="CRITICAL">Critical only</option>
                      <option value="HIGH">High and above</option>
                      <option value="MEDIUM">Medium and above</option>
                      <option value="LOW">Low and above</option>
                    </select>
                  </div>

                  <div>
                    <label className="mb-1.5 block text-xs uppercase tracking-[0.22em] text-[#A1A1AA]">
                      Lookback Window
                    </label>
                    <select
                      value={scanDepth}
                      onChange={(e) => setScanDepth(Number(e.target.value))}
                      className="w-full rounded-2xl border border-white/10 bg-[#09090B]/70 px-4 py-3 text-sm text-white outline-none transition focus:border-red-400/60"
                    >
                      {[7, 30, 60, 90, 180].map((days) => (
                        <option key={days} value={days}>
                          {days} days
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="mb-1.5 block text-xs uppercase tracking-[0.22em] text-[#A1A1AA]">
                      Result Cap
                    </label>
                    <select
                      value={maxResults}
                      onChange={(e) => setMaxResults(Number(e.target.value))}
                      className="w-full rounded-2xl border border-white/10 bg-[#09090B]/70 px-4 py-3 text-sm text-white outline-none transition focus:border-red-400/60"
                    >
                      {[25, 50, 100, 250].map((size) => (
                        <option key={size} value={size}>
                          {size} findings
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="mb-1.5 block text-xs uppercase tracking-[0.22em] text-[#A1A1AA]">
                      Keywords
                    </label>
                    <input
                      type="text"
                      value={keywordInput}
                      onChange={(e) => {
                        const value = e.target.value;
                        setKeywordInput(value);
                        setKeywords(
                          value
                            .split(",")
                            .map((keyword) => keyword.trim())
                            .filter(Boolean)
                        );
                      }}
                      placeholder="apache, nginx, openssl"
                      className="w-full rounded-2xl border border-white/10 bg-[#09090B]/70 px-4 py-3 text-sm text-white outline-none transition placeholder:text-[#71717A] focus:border-red-400/60"
                    />
                  </div>
                </div>

                <div className="mt-5 space-y-4">
                  <div>
                    <p className="mb-2 text-xs uppercase tracking-[0.22em] text-[#A1A1AA]">
                      Inventory Lens
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {[
                        { id: "all" as const, label: "All Findings" },
                        { id: "relevant" as const, label: "Asset Relevant" },
                        { id: "exploitable" as const, label: "Exploitable" },
                        { id: "unpatched" as const, label: "Critical Unpatched" },
                      ].map((view) => (
                        <button
                          key={view.id}
                          onClick={() => setActiveView(view.id)}
                          className={`rounded-full px-3 py-2 text-sm transition ${
                            activeView === view.id
                              ? "bg-red-500/18 text-red-200 ring-1 ring-red-400/40"
                              : "bg-white/5 text-[#E4E4E7] hover:bg-white/10"
                          }`}
                        >
                          {view.label}
                        </button>
                      ))}
                    </div>
                  </div>

                  <label className="flex items-center justify-between rounded-2xl border border-white/10 bg-[#09090B]/50 px-4 py-3 text-sm text-[#E4E4E7]">
                    <span>Show irrelevant nodes when asset inventory exists</span>
                    <button
                      type="button"
                      onClick={() => setShowIrrelevant((current) => !current)}
                      className={`relative h-7 w-12 rounded-full transition ${
                        showIrrelevant ? "bg-red-500" : "bg-white/8"
                      }`}
                    >
                      <span
                        className={`absolute top-1 h-5 w-5 rounded-full bg-white transition ${
                          showIrrelevant ? "left-6" : "left-1"
                        }`}
                      />
                    </button>
                  </label>
                </div>
              </div>
            </div>

            {analytics && (
              <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4 mb-6">
                <StatCard
                  label="Total CVEs"
                  value={analytics.totalVulnerabilities}
                  icon={Bug}
                  color="from-[#8B5CF6] to-[#6366F1]"
                  subtitle={
                    assets.length > 0
                      ? `${analytics.relevantVulnerabilities} relevant`
                      : `CVSS ${analytics.avgCvssScore.toFixed(1)}`
                  }
                />
                <StatCard
                  label="Avg Real Risk"
                  value={
                    Number.isFinite(analytics.avgRealRisk)
                      ? Math.round(analytics.avgRealRisk)
                      : 0
                  }
                  icon={Gauge}
                  color="from-[#F59E0B] to-[#EF4444]"
                  badge={analytics.avgRealRisk >= 60 ? "HIGH" : undefined}
                />
                <StatCard
                  label="Exploitable"
                  value={analytics.exploitedCount}
                  icon={Skull}
                  color="from-[#EF4444] to-[#DC2626]"
                  trend={analytics.exploitedCount > 3 ? "up" : undefined}
                />
                <StatCard
                  label="Attack Chains"
                  value={analytics.attackChainCount}
                  icon={Activity}
                  color="from-[#F59E0B] to-[#D97706]"
                  subtitle={
                    attackChains.filter((c) => c.fully_exploitable).length > 0
                      ? `${attackChains.filter((c) => c.fully_exploitable).length} exploitable`
                      : undefined
                  }
                />
                <StatCard
                  label="Patch Coverage"
                  value={`${analytics.patchCoverage}%`}
                  icon={ShieldCheck}
                  color="from-[#22C55E] to-[#16A34A]"
                  trend={analytics.patchCoverage < 50 ? "down" : undefined}
                />
                <StatCard
                  label="Compliance"
                  value={
                    complianceGenericOnly
                      ? "N/A"
                      : complianceAssessment
                      ? `${complianceAssessment.overall_compliance}%`
                      : "N/A"
                  }
                  icon={FileCheck}
                  color="from-[#3B82F6] to-[#6366F1]"
                  subtitle={
                    complianceGenericOnly ? "Add assets for real score" : undefined
                  }
                  onClick={() => setActiveTab("compliance")}
                />
              </div>
            )}

            <div className="mb-6">
              <SectionCard
                title="Intelligence Graph"
                subtitle="Node size reflects real-world risk score"
                icon={Network}
                iconClass="from-[#EF4444] to-[#F59E0B]"
                actions={
                  <button
                    onClick={() => setGraphExpanded(!graphExpanded)}
                    className="p-2 rounded-lg bg-white/5 text-[#A1A1AA] hover:bg-white/10 hover:text-white border border-white/5 hover:border-white/10 transition-all duration-200"
                  >
                    {graphExpanded ? (
                      <Minimize2 className="h-4 w-4" />
                    ) : (
                      <Maximize2 className="h-4 w-4" />
                    )}
                  </button>
                }
              >
                <motion.div
                  className="rounded-xl overflow-hidden bg-[#09090B]/80 border border-white/6 shadow-[0_0_0_1px_rgba(99,102,241,0.1),0_32px_64px_-16px_rgba(0,0,0,0.6)]"
                  animate={{ height: graphExpanded ? 900 : 620 }}
                  transition={{ duration: 0.3 }}
                >
                  {graphCVEData.length > 0 ? (
                    <Suspense fallback={<LoadingBlock text="Preparing intelligence graph..." />}>
                      <InfrastructureGraph
                        nodes={graphNodes}
                        rawCVEData={graphCVEData}
                        selectedNode={selectedNode}
                        onNodeSelect={setSelectedNode}
                        onMitigate={handleMitigate}
                      />
                    </Suspense>
                  ) : (
                    <div className="flex h-full items-center justify-center px-6">
                      <EmptyState
                        icon={Network}
                        title={
                          hiddenIrrelevantCount > 0
                            ? "No applicable vulnerabilities"
                            : "No vulnerability data"
                        }
                        description={
                          hiddenIrrelevantCount > 0
                            ? `${hiddenIrrelevantCount} stored CVEs do not match your asset inventory and are hidden. Turn on "Show irrelevant nodes" to inspect unmatched records.`
                            : "Run a CVE scan to populate intelligence."
                        }
                      />
                    </div>
                  )}
                </motion.div>
              </SectionCard>
            </div>

            {attackChains.length > 0 && (
              <div className="mb-6">
                <SectionCard
                  title="Attack Chains"
                  subtitle="Validated multi-step compromise paths"
                  icon={Activity}
                  iconClass="from-[#F59E0B] to-[#D97706]"
                >
                  <div className="space-y-4">
                    {attackChains.slice(0, 5).map((chain) => (
                      <motion.div
                        key={chain.chain_id}
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className={`p-4 rounded-xl border ${
                          chain.fully_exploitable
                            ? "bg-[#EF4444]/6 border-[#EF4444]/18 backdrop-blur-sm"
                            : "bg-[#0d0d12]/80 border-white/8"
                        }`}
                      >
                        <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
                          <div className="flex items-center gap-3">
                            <span className="text-sm font-bold text-[#FAFAFA] font-mono">
                              {chain.chain_id.toUpperCase()}
                            </span>
                            <span className="px-2.5 py-0.5 rounded-full text-xs bg-[#F59E0B]/15 text-[#FBBF24] border border-[#F59E0B]/25 font-semibold tracking-wide">
                              Risk {chain.chain_risk}
                            </span>
                            {chain.fully_exploitable && (
                              <span className="px-2.5 py-0.5 rounded-full text-xs bg-[#EF4444]/15 text-[#F87171] border border-[#EF4444]/30 font-semibold animate-pulse-glow">
                                Exploitable
                              </span>
                            )}
                          </div>
                          <span className="text-xs text-[#52525B]">
                            {chain.total_time_estimate}
                          </span>
                        </div>

                        <div className="flex items-center gap-2 overflow-x-auto pb-2">
                          {chain.steps.map((step, i) => (
                            <div
                              key={step.cve_id}
                              className="flex items-center gap-2 flex-shrink-0"
                            >
                              <div
                                className={`p-3 rounded-lg border min-w-[180px] cursor-pointer hover:scale-[1.02] transition-transform ${
                                  step.exploit_available
                                    ? "bg-[#EF4444]/6 border-[#EF4444]/18 backdrop-blur-sm"
                                    : "bg-[#131318]/50 border-white/10"
                                }`}
                                onClick={() => setSelectedNode(step.cve_id)}
                              >
                                <div className="flex items-center justify-between mb-1">
                                  <span className="text-xs font-bold text-white font-mono">
                                    {step.cve_id}
                                  </span>
                                  <span className="text-xs text-[#A1A1AA]">
                                    CVSS {step.cvss}
                                  </span>
                                </div>
                                <StageBadge stage={step.stage} />
                              </div>
                              {i < chain.steps.length - 1 && (
                                <ArrowRight className="h-5 w-5 text-[#FBBF24] flex-shrink-0" />
                              )}
                            </div>
                          ))}
                        </div>
                      </motion.div>
                    ))}
                  </div>
                </SectionCard>
              </div>
            )}

            <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 mb-6">
              <div className="xl:col-span-2">
                <SectionCard
                  title="Vulnerability Inventory"
                  subtitle={
                    nodes.length > 0
                      ? hiddenIrrelevantCount > 0
                        ? `${filteredNodes.length} shown · ${hiddenIrrelevantCount} unmatched hidden`
                        : `${filteredNodes.length} of ${displayNodes.length} vulnerabilities`
                      : "Real-time CVE intelligence feed"
                  }
                  icon={Bug}
                  iconClass="from-[#EF4444] to-[#8B5CF6]"
                  actions={
                    nodes.length > 0 && (
                      <div className="flex items-center gap-2">
                        <div className="relative">
                          <Search className="h-3.5 w-3.5 text-[#52525B] absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                          <input
                            type="text"
                            value={inventorySearch}
                            onChange={(e) => setInventorySearch(e.target.value)}
                            placeholder="Search CVEs, products..."
                            className="pl-8 pr-3 py-1.5 rounded-xl bg-white/4 border border-white/8 text-xs text-[#E4E4E7] placeholder:text-[#3F3F46] focus:outline-none focus:border-[#6366F1]/40 focus:bg-white/6 transition-all w-44"
                          />
                        </div>
                        <select
                          value={inventorySortBy}
                          onChange={(e) => setInventorySortBy(e.target.value as "risk" | "cvss" | "relevance" | "tte")}
                          className="px-2.5 py-1.5 rounded-xl bg-white/4 border border-white/8 text-xs text-[#A1A1AA] focus:outline-none focus:border-white/14 appearance-none cursor-pointer"
                        >
                          <option value="risk">Risk ↓</option>
                          <option value="cvss">CVSS ↓</option>
                          <option value="relevance">Relevance ↓</option>
                          <option value="tte">Time to Exploit</option>
                        </select>
                      </div>
                    )
                  }
                >
                  {/* ── SUMMARY BAR ──────────────────────────────── */}
                  {filteredNodes.length > 0 && (
                    <div className="flex items-center gap-3 mb-4 p-3 rounded-xl bg-white/2 border border-white/5">
                      {[
                        { label: "Critical", count: filteredNodes.filter(n => n && n.severity === "CRITICAL").length, color: "#F87171", bg: "rgba(239,68,68,0.10)" },
                        { label: "High",     count: filteredNodes.filter(n => n && n.severity === "HIGH").length,     color: "#FBBF24", bg: "rgba(245,158,11,0.10)" },
                        { label: "Medium",   count: filteredNodes.filter(n => n && n.severity === "MEDIUM").length,   color: "#FCD34D", bg: "rgba(253,224,71,0.08)"  },
                        { label: "Low",      count: filteredNodes.filter(n => n && n.severity === "LOW").length,      color: "#4ADE80", bg: "rgba(34,197,94,0.08)"   },
                        { label: "Exploit",  count: filteredNodes.filter(n => !!n.exploit_available).length,     color: "#A78BFA", bg: "rgba(167,139,250,0.10)" },
                        { label: "Patch",    count: filteredNodes.filter(n => n.patch_intel?.available === true).length, color: "#22D3EE", bg: "rgba(34,211,238,0.08)" },
                      ].map(s => (
                        <div key={s.label} className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg flex-1 justify-center" style={{ backgroundColor: s.bg }}>
                          <span className="text-sm font-bold" style={{ color: s.color }}>{s.count}</span>
                          <span className="text-[10px] uppercase tracking-wide" style={{ color: s.color + "90" }}>{s.label}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* ── CVE LIST ─────────────────────────────────── */}
                  <div className="space-y-2.5 max-h-[600px] overflow-y-auto pr-1
                    [&::-webkit-scrollbar]:w-1
                    [&::-webkit-scrollbar-track]:bg-transparent
                    [&::-webkit-scrollbar-thumb]:bg-white/8
                    [&::-webkit-scrollbar-thumb]:rounded-full">
                    {filteredNodes.length === 0 ? (
                      <EmptyState
                        icon={Search}
                        title={nodes.length === 0 ? "No vulnerability data" : hiddenIrrelevantCount > 0 ? "No applicable vulnerabilities" : "No matching results"}
                        description={nodes.length === 0 ? "Run a CVE scan to populate intelligence." : hiddenIrrelevantCount > 0 ? `${hiddenIrrelevantCount} CVEs hidden — enable Show irrelevant nodes to inspect.` : "Try adjusting your search or filters."}
                      />
                    ) : (
                      filteredNodes.slice(0, 20).map((cve, idx) => {
                        const isSelected  = selectedNode === (cve.cve_id || cve.id);
                        const isExploited = cve.status === "exploited";
                        const isCritical  = cve.status === "critical" || cve.severity === "CRITICAL";
                        const isIrrelevant = cve.status === "irrelevant";
                        const riskVal     = Math.round(cve.risk || 0);
                        const riskColor   = riskVal >= 75 ? "#F87171" : riskVal >= 50 ? "#FBBF24" : riskVal >= 25 ? "#FCD34D" : "#4ADE80";
                        const riskLabel   = riskVal >= 75 ? "HIGH" : riskVal >= 50 ? "MED" : "LOW";
                        const cvssColor   = (cve.cvss_score||0) >= 9 ? "#F87171" : (cve.cvss_score||0) >= 7 ? "#FBBF24" : (cve.cvss_score||0) >= 4 ? "#FCD34D" : "#4ADE80";

                        return (
                          <motion.div
                            key={cve.cve_id || cve.id}
                            initial={{ opacity: 0, y: 6 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: idx * 0.018, duration: 0.22, ease: [0.16,1,0.3,1] }}
                            onClick={() => { try { setSelectedNode(isSelected ? null : (cve.cve_id || cve.id)); } catch(e) { console.error(e); } }}
                            className={`
                              relative overflow-hidden rounded-2xl border cursor-pointer
                              transition-all duration-250 group
                              ${isSelected
                                ? "border-[#6366F1]/45 bg-[#0d0d12] shadow-[0_0_0_1px_rgba(99,102,241,0.15),0_8px_32px_-8px_rgba(99,102,241,0.18)]"
                                : isCritical || isExploited
                                ? "border-[#EF4444]/15 bg-[#EF4444]/3 hover:border-[#EF4444]/28 hover:bg-[#EF4444]/5"
                                : isIrrelevant
                                ? "border-white/4 bg-[#09090B]/50 opacity-55 hover:opacity-75"
                                : "border-white/6 bg-[#0d0d12]/75 hover:border-white/12 hover:bg-[#0d0d12]/90"
                              }
                            `}
                          >
                            {/* selected indigo glow */}
                            {isSelected && (
                              <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_70%_50%_at_0%_0%,rgba(99,102,241,0.07),transparent_60%)]" />
                            )}

                            {/* critical top accent line */}
                            {(isCritical || isExploited) && (
                              <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-[#EF4444]/40 to-transparent" />
                            )}

                            <div className="relative p-4">

                              {/* ══ TOP ROW ══════════════════════════════ */}
                              <div className="flex items-start gap-3">

                                {/* severity color bar */}
                                <div className="flex-shrink-0 mt-1">
                                  <div className="w-1 h-10 rounded-full" style={{
                                    background: isCritical || isExploited
                                      ? "linear-gradient(180deg,#F87171,#EF4444)"
                                      : cve.severity === "HIGH"
                                      ? "linear-gradient(180deg,#FBBF24,#F59E0B)"
                                      : cve.severity === "MEDIUM"
                                      ? "linear-gradient(180deg,#FCD34D,#EAB308)"
                                      : cve.severity === "LOW"
                                      ? "linear-gradient(180deg,#4ADE80,#22C55E)"
                                      : "linear-gradient(180deg,rgba(255,255,255,0.15),rgba(255,255,255,0.05))"
                                  }} />
                                </div>

                                {/* main content */}
                                <div className="flex-1 min-w-0">

                                  {/* CVE ID row */}
                                  <div className="flex items-center justify-between gap-2 mb-1.5">
                                    <div className="flex items-center gap-2 min-w-0">
                                      <span className="font-mono font-bold text-sm text-[#FAFAFA] tracking-tight flex-shrink-0">
                                        {cve.cve_id || cve.id}
                                      </span>
                                      <CopyButton text={cve.cve_id || cve.id} />
                                    </div>
                                    <div className="flex items-center gap-1.5 flex-shrink-0">
                                      {isIrrelevant
                                        ? <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-white/4 text-[#3F3F46] border border-white/6">N/A</span>
                                        : <SeverityBadge severity={cve.severity} />
                                      }
                                    </div>
                                  </div>

                                  {/* product / name */}
                                  <p className="text-[11px] text-[#52525B] truncate mb-2">
                                    {cve.affected_products?.[0] || cve.name || "Unknown product"}
                                  </p>

                                  {/* description */}
                                  <p className="text-[11px] text-[#71717A] leading-relaxed line-clamp-2 mb-3">
                                    {cve.description || "No description available."}
                                  </p>

                                  {/* ── METRIC ROW ───────────────────── */}
                                  <div className="flex items-center gap-2 mb-3">

                                    {/* CVSS */}
                                    <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-white/3 border border-white/6 flex-1 justify-center">
                                      <span className="text-sm font-bold" style={{ color: cvssColor }}>
                                        {cve.cvss_score != null ? cve.cvss_score.toFixed(1) : "—"}
                                      </span>
                                      <span className="text-[10px] text-[#3F3F46] uppercase tracking-wide">CVSS</span>
                                    </div>

                                    {/* Risk score */}
                                    <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg flex-1 justify-center border"
                                      style={{ backgroundColor: `${riskColor}10`, borderColor: `${riskColor}20` }}>
                                      <span className="text-sm font-bold" style={{ color: riskColor }}>{riskVal}</span>
                                      <span className="text-[10px] uppercase tracking-wide" style={{ color: `${riskColor}70` }}>Risk</span>
                                    </div>

                                    {/* EPSS Score */}
                                    {(() => {
                                      const epss = cve.risk_factors?.epss_score ?? 0;
                                      const epssColor = epss >= 0.5 ? "#F87171" : epss >= 0.1 ? "#FBBF24" : "#34D399";
                                      return epss > 0 ? (
                                        <div
                                          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg flex-1 justify-center border"
                                          style={{ backgroundColor: `${epssColor}10`, borderColor: `${epssColor}25` }}
                                          title={`EPSS: ${(epss*100).toFixed(1)}% probability of exploitation in next 30 days`}
                                        >
                                          <span className="text-sm font-bold" style={{ color: epssColor }}>
                                            {(epss * 100).toFixed(0)}%
                                          </span>
                                          <span className="text-[10px] uppercase tracking-wide" style={{ color: `${epssColor}70` }}>EPSS</span>
                                        </div>
                                      ) : null;
                                    })()}

                                    {/* Relevance */}
                                    <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-[#6366F1]/8 border border-[#6366F1]/15 flex-1 justify-center">
                                      <span className="text-sm font-bold text-[#818CF8]">{typeof cve.relevance_score === "number" ? cve.relevance_score : "—"}</span>
                                      <span className="text-[10px] text-[#6366F1]/60 uppercase tracking-wide">Rel</span>
                                    </div>

                                    {/* Connections */}
                                    <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-[#8B5CF6]/8 border border-[#8B5CF6]/15 flex-1 justify-center">
                                      <span className="text-sm font-bold text-[#A78BFA]">{cve.connection_count ?? "—"}</span>
                                      <span className="text-[10px] text-[#8B5CF6]/60 uppercase tracking-wide">Links</span>
                                    </div>
                                  </div>

                                  {/* ── BADGES ROW ───────────────────── */}
                                  <div className="flex flex-wrap items-center gap-1.5">
                                    {cve.attack_stage && cve.attack_stage !== "unknown" && (
                                      <StageBadge stage={cve.attack_stage} />
                                    )}
                                    <TTEBadge tte={cve.time_to_exploit} />
                                    {cve.exploit_available && (
                                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-[#A78BFA]/10 text-[#A78BFA] border border-[#A78BFA]/20">
                                        <Skull className="h-2.5 w-2.5" /> Exploit PoC
                                      </span>
                                    )}
                                    {cve.patch_intel?.available === true && (
                                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-[#22C55E]/10 text-[#4ADE80] border border-[#22C55E]/20">
                                        <ShieldCheck className="h-2.5 w-2.5" /> Patch Available
                                      </span>
                                    )}
                                    {isIrrelevant && (
                                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-white/3 text-[#3F3F46] border border-white/5">
                                        No asset match
                                      </span>
                                    )}
                                  </div>

                                </div>
                              </div>

                              {/* ══ EXPANDED SECTION ════════════════════ */}
                              <AnimatePresence>
                                {isSelected && (
                                  <motion.div
                                    key={`expanded-${cve.cve_id || cve.id}`}
                                    initial={{ opacity: 0, height: 0 }}
                                    animate={{ opacity: 1, height: "auto" }}
                                    exit={{ opacity: 0, height: 0 }}
                                    transition={{ duration: 0.22, ease: [0.16,1,0.3,1] }}
                                    className="overflow-hidden"
                                  >
                                    <div className="mt-4 pt-4 border-t border-[#6366F1]/12">

                                      {/* section label */}
                                      <div className="flex items-center gap-2 mb-3">
                                        <div className="h-px flex-1 bg-gradient-to-r from-[#6366F1]/20 to-transparent" />
                                        <span className="text-[9px] text-[#6366F1]/60 uppercase tracking-widest font-semibold">Risk Intelligence</span>
                                        <div className="h-px flex-1 bg-gradient-to-l from-[#6366F1]/20 to-transparent" />
                                      </div>

                                      {/* affected products full list */}
                                      {(Array.isArray(cve.affected_products) && cve.affected_products.length > 0) && (
                                        <div className="mb-3">
                                          <p className="text-[10px] text-[#3F3F46] uppercase tracking-wider mb-1.5">Affected Products</p>
                                          <div className="flex flex-wrap gap-1">
                                            {(Array.isArray(cve.affected_products) ? cve.affected_products : []).slice(0, 5).map((prod: string) => (
                                              <span key={prod} className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-[#3B82F6]/8 text-[#60A5FA] border border-[#3B82F6]/15 truncate max-w-[180px]">
                                                {prod}
                                              </span>
                                            ))}
                                            {(Array.isArray(cve.affected_products) && cve.affected_products.length > 5) && (
                                              <span className="px-2 py-0.5 rounded-full text-[10px] bg-white/4 text-[#52525B] border border-white/6">
                                                +{cve.affected_products.length - 5} more
                                              </span>
                                            )}
                                          </div>
                                        </div>
                                      )}

                                      {/* risk breakdown */}
                                      {cve.risk_factors && typeof cve.risk_factors === "object" && Object.keys(cve.risk_factors).length > 0 && <RiskBreakdown factors={cve.risk_factors} />}

                                      {/* quick actions */}
                                      <div className="flex gap-2 mt-3">
                                        <a
                                          href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                                          target="_blank"
                                          rel="noopener noreferrer"
                                          onClick={(e) => e.stopPropagation()}
                                          className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl bg-white/3 hover:bg-white/6 border border-white/6 hover:border-white/10 text-[#A1A1AA] hover:text-white text-xs font-medium transition-all duration-200"
                                        >
                                          <ExternalLink className="h-3 w-3" /> NVD
                                        </a>
                                        <button
                                          onClick={(e) => { e.stopPropagation(); setSelectedNode(cve.cve_id || cve.id); }}
                                          className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl bg-[#6366F1]/10 hover:bg-[#6366F1]/18 border border-[#6366F1]/20 hover:border-[#6366F1]/30 text-[#818CF8] text-xs font-medium transition-all duration-200"
                                        >
                                          <Network className="h-3 w-3" /> Graph
                                        </button>
                                        <button
                                          onClick={(e) => { e.stopPropagation(); }}
                                          className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl bg-gradient-to-r from-[#3B82F6]/12 to-[#6366F1]/12 hover:from-[#3B82F6]/20 hover:to-[#6366F1]/20 border border-[#3B82F6]/20 hover:border-[#3B82F6]/30 text-[#60A5FA] text-xs font-medium transition-all duration-200"
                                        >
                                          <Zap className="h-3 w-3" /> Mitigate
                                        </button>
                                      </div>
                                    </div>
                                  </motion.div>
                                )}
                              </AnimatePresence>

                            </div>
                          </motion.div>
                        );
                      })
                    )}
                  </div>
                </SectionCard>
              </div>

              <div>
                <SectionCard
                  title="Security Events"
                  subtitle="Recent engine observations and changes"
                  icon={Activity}
                  iconClass="from-[#F59E0B] to-[#EF4444]"
                >
                  <div className="h-[500px] overflow-y-auto space-y-2 pr-2">
                    {events.length > 0 ? (
                      events.map((event) => (
                        <motion.div
                          key={event.id}
                          initial={{ opacity: 0, x: 20 }}
                          animate={{ opacity: 1, x: 0 }}
                          className={`p-3 rounded-lg border ${
                            event.severity === "critical"
                              ? "bg-[#EF4444]/10 border-[#EF4444]/25 backdrop-blur-sm"
                              : "bg-[#0d0d12]/80 border-white/8"
                          }`}
                        >
                          <div className="flex items-start gap-3">
                            <Info className="h-4 w-4 text-[#A1A1AA] mt-0.5" />
                            <div className="flex-1 min-w-0">
                              <p className="text-sm text-[#FAFAFA]">{event.message}</p>
                              {event.details && (
                                <p className="text-xs text-[#52525B] mt-1">
                                  {event.details}
                                </p>
                              )}
                              <span className="text-xs text-[#52525B]">
                                {event.timestamp}
                              </span>
                            </div>
                          </div>
                        </motion.div>
                      ))
                    ) : (
                      <EmptyState
                        icon={Activity}
                        title="No events"
                        description="Events will appear as scans and assessments run."
                      />
                    )}
                  </div>
                </SectionCard>
              </div>
            </div>
          </>
        )}

        {activeTab === "compliance" && (
          <ComplianceDashboardPanel
            assessment={complianceAssessment}
            isLoading={complianceLoading}
            onRefresh={fetchComplianceAssessment}
          />
        )}

        {activeTab === "scanning" && (
          <ActiveScannerPanel
            onScan={runActiveScan}
            isScanning={activeScanning}
            lastResult={activeScanResult}
          />
        )}

        {activeTab === "trending" && (
          <TrendingPanel
            data={trendingData}
            isLoading={trendingLoading}
            onRefresh={fetchTrendingData}
            onSnapshot={captureSnapshot}
          />
        )}

        {activeTab === "alerts" && (
          <div className="rounded-2xl border border-white/8 bg-[#0d0d12] p-6">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-3">
                <BellRing className="h-5 w-5 text-[#F87171]" />
                <h2 className="text-lg font-semibold">Alerts</h2>
                <span className="px-2 py-0.5 rounded-full bg-[#EF4444]/15 text-[#F87171] text-xs font-bold">
                  {alerts.filter((a) => !a.acknowledged).length}
                </span>
              </div>
              <button
                onClick={fetchAlerts}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/8 text-[#A1A1AA] hover:text-white text-sm transition-all"
              >
                <RefreshCw className="h-3.5 w-3.5" />
                Refresh
              </button>
            </div>
            <div className="space-y-3">
              {alerts.length === 0 ? (
                <div className="text-center py-16">
                  <Bell className="h-12 w-12 text-[#27272A] mx-auto mb-4" />
                  <p className="text-[#71717A] text-sm">No alerts. You're all caught up.</p>
                </div>
              ) : (
                alerts.map((alert) => (
                  <div
                    key={alert.id}
                    className={`p-4 rounded-xl border ${
                      alert.acknowledged
                        ? "bg-[#131318]/30 border-white/6 opacity-60"
                        : alert.severity === "critical"
                        ? "bg-[#EF4444]/6 border-[#EF4444]/18"
                        : alert.severity === "high"
                        ? "bg-[#F59E0B]/10 border-[#F59E0B]/25"
                        : "bg-white/[0.02] border-white/8"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            alert.severity === "critical" ? "bg-[#EF4444]/15 text-[#F87171]" :
                            alert.severity === "high" ? "bg-[#F59E0B]/15 text-[#FBBF24]" :
                            alert.severity === "medium" ? "bg-[#3B82F6]/15 text-[#60A5FA]" :
                            "bg-white/10 text-[#A1A1AA]"
                          }`}>{alert.severity}</span>
                          <span className="text-[11px] text-[#52525B]">{alert.type}</span>
                        </div>
                        <p className="text-sm text-[#E4E4E7]">{alert.message}</p>
                        <p className="text-[11px] text-[#52525B] mt-1">{new Date(alert.created_at).toLocaleString()}</p>
                      </div>
                      {!alert.acknowledged && (
                        <button
                          onClick={() => acknowledgeAlert(alert.id)}
                          className="flex items-center gap-1 px-2 py-1 rounded-lg bg-white/5 hover:bg-white/10 text-[#71717A] hover:text-white text-[11px] transition-all"
                        >
                          <Check className="h-3 w-3" />
                          Ack
                        </button>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {activeTab === "integrations" && (
          <div className="rounded-2xl border border-white/8 bg-[#0d0d12] p-6">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-3">
                <Webhook className="h-5 w-5 text-[#818CF8]" />
                <h2 className="text-lg font-semibold">Integrations</h2>
                <span className="px-2 py-0.5 rounded-full bg-[#6366F1]/15 text-[#818CF8] text-xs font-bold">
                  {integrations.length}
                </span>
              </div>
              <button
                onClick={() => setIntegrationsOpen(true)}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-[#3B82F6] to-[#6366F1] text-white text-sm font-medium shadow-lg shadow-[#3B82F6]/25 hover:shadow-[#3B82F6]/35 transition-all"
              >
                <Send className="h-3.5 w-3.5" />
                Configure
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
              {[
                { type: "webhook", icon: Webhook, label: "Webhooks", color: "text-[#818CF8]", bg: "bg-[#6366F1]/10" },
                { type: "slack", icon: Slack, label: "Slack", color: "text-[#36C5F0]", bg: "bg-[#36C5F0]/10" },
                { type: "jira", icon: TicketCheck, label: "Jira", color: "text-[#2684FF]", bg: "bg-[#2684FF]/10" },
                { type: "pagerduty", icon: Siren, label: "PagerDuty", color: "text-[#06AC38]", bg: "bg-[#06AC38]/10" },
              ].map(({ type, icon: Icon, label, color, bg }) => {
                const configured = integrations.filter(i => i.type === type);
                return (
                  <div key={type} className="p-4 rounded-xl border border-white/8 bg-white/[0.02]">
                    <div className="flex items-center gap-3 mb-2">
                      <div className={`p-2 rounded-lg ${bg}`}>
                        <Icon className={`h-4 w-4 ${color}`} />
                      </div>
                      <div>
                        <p className="text-sm font-medium text-white">{label}</p>
                        <p className="text-[11px] text-[#52525B]">
                          {configured.length > 0
                            ? `${configured.length} configured`
                            : "Not configured"}
                        </p>
                      </div>
                    </div>
                    <div className={`w-full h-1 rounded-full ${configured.length > 0 ? bg : "bg-white/5"}`} />
                  </div>
                );
              })}
            </div>

            {webhookDeliveries.length > 0 && (
              <div>
                <h3 className="text-sm font-semibold text-[#A1A1AA] mb-3 flex items-center gap-2">
                  <History className="h-4 w-4" />
                  Recent Deliveries
                </h3>
                <div className="space-y-2">
                  {webhookDeliveries.slice(0, 10).map((d, i) => (
                    <div key={i} className="flex items-center justify-between p-3 rounded-lg border border-white/6 bg-white/[0.02]">
                      <div className="flex items-center gap-3">
                        <div className={`w-2 h-2 rounded-full ${d.status === "success" ? "bg-emerald-400" : "bg-red-400"}`} />
                        <div>
                          <p className="text-[13px] text-[#E4E4E7]">{d.event_type}</p>
                          <p className="text-[11px] text-[#52525B]">{d.integration_name}</p>
                        </div>
                      </div>
                      <div className="text-right">
                        <span className={`text-[11px] font-medium ${d.status === "success" ? "text-emerald-400" : "text-red-400"}`}>
                          {d.status_code || d.status}
                        </span>
                        <p className="text-[10px] text-[#3F3F46]">{new Date(d.delivered_at).toLocaleString()}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {webhookDeliveries.length === 0 && integrations.length === 0 && (
              <div className="text-center py-16">
                <Webhook className="h-12 w-12 text-[#27272A] mx-auto mb-4" />
                <p className="text-[#71717A] text-sm">No integrations configured yet.</p>
                <p className="text-[#52525B] text-xs mt-1">Click Configure to set up Slack, Jira, PagerDuty, or Webhooks.</p>
              </div>
            )}
          </div>
        )}
        {activeTab === "assets" && (
          <AssetManagerPanel
            apiFetch={apiFetch}
            onAssetChange={() => {
              fetchAssets();
            }}
          />
        )}
      </main>

      <AnimatePresence>
        {alertsPanelOpen && (
          <AlertsPanel
            alerts={alerts}
            isOpen={alertsPanelOpen}
            onClose={() => setAlertsPanelOpen(false)}
            onAcknowledge={acknowledgeAlert}
          />
        )}
      </AnimatePresence>

      <IntegrationConfigModal
        isOpen={integrationsOpen}
        onClose={() => setIntegrationsOpen(false)}
        onSave={saveIntegration}
      />

      <footer className="border-t border-white/4 mt-16 bg-[#09090B]/80 backdrop-blur-2xl">
        <div className="max-w-[1920px] mx-auto px-6 py-6">
          <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-[#71717A]">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-[#60A5FA]" />
              <p>CascadeX Intelligence Engine v4.0</p>
            </div>
            <div className="flex items-center gap-4 text-xs text-[#52525B]">
              <span className="flex items-center gap-1">
                <RadarIcon className="h-3 w-3" /> Active Scanning
              </span>
              <span className="flex items-center gap-1">
                <Radio className="h-3 w-3" /> Real-time Monitor
              </span>
              <span className="flex items-center gap-1">
                <FileCheck className="h-3 w-3" /> Compliance
              </span>
              <span className="flex items-center gap-1">
                <LineChart className="h-3 w-3" /> Trending
              </span>
              <span className="flex items-center gap-1">
                <Webhook className="h-3 w-3" /> Integrations
              </span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
