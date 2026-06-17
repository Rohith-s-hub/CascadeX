import React, { useMemo, useState, useEffect, useCallback, useRef } from "react";
import { createPortal } from "react-dom";
import { motion, AnimatePresence } from "framer-motion";
import {
  Server,
  Database,
  Globe,
  Network,
  Bug,
  Shield,
  ShieldAlert,
  ShieldX,
  ShieldCheck,
  Skull,
  CheckCircle,
  MonitorSmartphone,
  AlertTriangle,
  Zap,
  X,
  ChevronRight,
  Activity,
  Target,
  GitBranch,
  ArrowRight,
  Radio,
  Cpu,
  Clock,
  ExternalLink,
  Copy,
  Check,
  Loader2,
  Ban,
  Terminal,
  CircleSlash,
  PlayCircle,
  Link2,
  Layers,
  FileWarning,
  Lock,
  Unlock,
  Eye,
  Code,
  Workflow,
  Filter,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Search,
  SlidersHorizontal,
  LayoutGrid,
  GitMerge,
  Package,
  ChevronDown,
  Info,
  TrendingUp,
  BarChart2,
  Crosshair,
  RefreshCw,
} from "lucide-react";

// ═══════════════════════════════════════════════════════════════════════
// TYPE DEFINITIONS
// ═══════════════════════════════════════════════════════════════════════

export interface CVEVulnerability {
  cve_id: string;
  description: string;
  cvss_score: number;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  attack_vector: string;
  attack_complexity: string;
  privileges_required: string;
  user_interaction: string;
  scope: string;
  exploit_available: boolean;
  patch_available: boolean;
  affected_products: string[];
  affected_vendors: string[];
  cwe_ids: string[];
  published_date: string;
  last_modified_date: string;
  vuln_status: string;
  references: { url: string; source: string; tags: string[] }[];
  // ── EPSS — Exploit Prediction Scoring System (FIRST.org) ──────────
  // Real ML model: probability of exploitation in next 30 days
  epss_score: number | null;       // 0.0–1.0 exploitation probability
  epss_percentile: number | null;  // relative rank vs all scored CVEs
  epss_updated_at: string | null;  // ISO timestamp of last EPSS fetch
  // ── Asset + threat intelligence ───────────────────────────────────
  cisa_kev?: boolean;              // In CISA Known Exploited Vulnerabilities
  asset_matches?: {                // Confirmed matches from backend
    asset_id: string;
    asset_name: string;
    confidence: number;
    matched_product: string;
  }[];
}

export interface NodeStatus {
  id: string;
  name: string;
  type:
    | "vulnerability"
    | "server"
    | "database"
    | "network"
    | "gateway"
    | "application"
    | "vendor"
    | "product"
    | "cwe_category";
  stability: number;
  risk: number;
  connections: string[];
  status: "operational" | "warning" | "critical" | "exploited" | "mitigated";
  cvss_score?: number;
  severity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  exploit_available?: boolean;
  patch_available?: boolean;
  cve_id?: string;
  description?: string;
  attack_vector?: string;
  attack_complexity?: string;
  privileges_required?: string;
  cwe_ids?: string[];
  affected_products?: string[];
  affected_vendors?: string[];
  vuln_status?: string;
  published_date?: string;
  references?: { url: string; source: string; tags: string[] }[];
  // ── EPSS fields ───────────────────────────────────────────────────
  epss_score?: number | null;
  epss_percentile?: number | null;
  cisa_kev?: boolean;
  // ── Asset confirmation ────────────────────────────────────────────
  asset_match_count?: number;
  confirmed_on_asset?: boolean;   // true = validated against real asset
}

interface Position {
  x: number;
  y: number;
}

interface CascadeNode extends NodeStatus {
  position: Position;
  level: number;
  children: string[];
  parents: string[];
  cascadePhase?: string;
  chainConfidence?: number;
}

interface Edge {
  id: string;
  source: string;
  target: string;
  sourcePos: Position;
  targetPos: Position;
  risk: number;
  edgeType: "vendor" | "product" | "cwe_chain" | "cascade" | "exploit_path";
  label?: string;
  confidence?: number;
  // ── Honest chain classification ───────────────────────────────────
  // confirmed     = both CVEs on same asset (real chain)
  // high_inferred = proven CWE relationship
  // inferred      = same vendor + exploit available
  // weak          = heuristic only
  edgeConfirmation?: "confirmed" | "high_inferred" | "inferred" | "weak";
}

interface MitigationAction {
  id: string;
  label: string;
  description: string;
  icon: React.ReactNode;
  type: "patch" | "isolate" | "block" | "monitor" | "script";
  risk_reduction: number;
  time_estimate: string;
}

export interface InfrastructureGraphProps {
  nodes: NodeStatus[];
  rawCVEData?: CVEVulnerability[];
  selectedNode: string | null;
  onNodeSelect: (nodeId: string | null) => void;
  onMitigate?: (nodeId: string, action: string) => void;
  onNodesUpdate?: (nodes: NodeStatus[]) => void;
}

type GraphMode = "cascade" | "blast_radius" | "infrastructure";

interface GraphFilters {
  severity: Set<string>;
  exploitOnly: boolean;
  patchableOnly: boolean;
  phase: Set<string>;
  minCvss: number;
}

// ═══════════════════════════════════════════════════════════════════════
// CWE TAXONOMY
// ═══════════════════════════════════════════════════════════════════════

const CWE_PHASE_MAP: Record<string, { phase: string; order: number; label: string }> = {
  "CWE-200": { phase: "recon", order: 0, label: "Information Exposure" },
  "CWE-204": { phase: "recon", order: 0, label: "Observable Response Discrepancy" },
  "CWE-209": { phase: "recon", order: 0, label: "Error Info Leak" },
  "CWE-524": { phase: "recon", order: 0, label: "Cache Info Leak" },
  "CWE-668": { phase: "recon", order: 0, label: "Resource Exposure" },
  "CWE-287": { phase: "initial_access", order: 1, label: "Auth Bypass" },
  "CWE-295": { phase: "initial_access", order: 1, label: "Cert Validation Failure" },
  "CWE-296": { phase: "initial_access", order: 1, label: "Cert Chain Failure" },
  "CWE-306": { phase: "initial_access", order: 1, label: "Missing Auth" },
  "CWE-346": { phase: "initial_access", order: 1, label: "Origin Validation Failure" },
  "CWE-352": { phase: "initial_access", order: 1, label: "CSRF" },
  "CWE-601": { phase: "initial_access", order: 1, label: "Open Redirect" },
  "CWE-862": { phase: "initial_access", order: 1, label: "Missing Authorization" },
  "CWE-74": { phase: "execution", order: 2, label: "Injection" },
  "CWE-78": { phase: "execution", order: 2, label: "OS Command Injection" },
  "CWE-79": { phase: "execution", order: 2, label: "XSS" },
  "CWE-80": { phase: "execution", order: 2, label: "Script Injection" },
  "CWE-89": { phase: "execution", order: 2, label: "SQL Injection" },
  "CWE-94": { phase: "execution", order: 2, label: "Code Injection" },
  "CWE-116": { phase: "execution", order: 2, label: "Output Encoding Failure" },
  "CWE-502": { phase: "execution", order: 2, label: "Deserialization" },
  "CWE-918": { phase: "execution", order: 2, label: "SSRF" },
  "CWE-1321": { phase: "execution", order: 2, label: "Prototype Pollution" },
  "CWE-1336": { phase: "execution", order: 2, label: "Template Injection" },
  "CWE-15": { phase: "escalation", order: 3, label: "External System Setting" },
  "CWE-22": { phase: "escalation", order: 3, label: "Path Traversal" },
  "CWE-23": { phase: "escalation", order: 3, label: "Relative Path Traversal" },
  "CWE-61": { phase: "escalation", order: 3, label: "Symlink Following" },
  "CWE-67": { phase: "escalation", order: 3, label: "Improper Filename Handling" },
  "CWE-73": { phase: "escalation", order: 3, label: "External File Control" },
  "CWE-269": { phase: "escalation", order: 3, label: "Privilege Escalation" },
  "CWE-266": { phase: "escalation", order: 3, label: "Incorrect Privilege" },
  "CWE-283": { phase: "escalation", order: 3, label: "Unverified Ownership" },
  "CWE-284": { phase: "escalation", order: 3, label: "Access Control Failure" },
  "CWE-285": { phase: "escalation", order: 3, label: "Improper Authorization" },
  "CWE-434": { phase: "escalation", order: 3, label: "Unrestricted File Upload" },
  "CWE-20": { phase: "impact", order: 4, label: "Input Validation Failure" },
  "CWE-122": { phase: "impact", order: 4, label: "Heap Buffer Overflow" },
  "CWE-362": { phase: "impact", order: 4, label: "Race Condition" },
  "CWE-367": { phase: "impact", order: 4, label: "TOCTOU Race" },
  "CWE-396": { phase: "impact", order: 4, label: "Broad Exception" },
  "CWE-400": { phase: "impact", order: 4, label: "Resource Exhaustion" },
  "CWE-770": { phase: "impact", order: 4, label: "Uncontrolled Allocation" },
};

const PHASE_COLORS: Record<string, { main: string; bg: string; label: string }> = {
  recon: { main: "#8B5CF6", bg: "rgba(139,92,246,0.12)", label: "🔍 Reconnaissance" },
  initial_access: { main: "#F59E0B", bg: "rgba(245,158,11,0.12)", label: "🚪 Initial Access" },
  execution: { main: "#EF4444", bg: "rgba(239,68,68,0.12)", label: "⚡ Execution" },
  escalation: { main: "#6366F1", bg: "rgba(99,102,241,0.12)", label: "📈 Escalation" },
  impact: { main: "#EF4444", bg: "rgba(239,68,68,0.10)", label: "💥 Impact" },
  unknown: { main: "#A1A1AA", bg: "rgba(161,161,170,0.10)", label: "❓ Unknown" },
};

// ═══════════════════════════════════════════════════════════════════════
// CVE DATA TRANSFORMER
// ═══════════════════════════════════════════════════════════════════════

export function transformCVEsToNodes(cves: CVEVulnerability[]): NodeStatus[] {
  if (!cves || !Array.isArray(cves) || cves.length === 0) return [];

  const nodes: NodeStatus[] = [];
  const vendorProducts = new Map<string, Set<string>>();
  const productCVEs = new Map<string, string[]>();

  cves.forEach((cve) => {
    if (!cve.cve_id) return;
    const vendors = cve.affected_vendors || [];
    const products = cve.affected_products || [];

    vendors.forEach((vendor) => {
      if (!vendorProducts.has(vendor)) vendorProducts.set(vendor, new Set());
    });

    products.forEach((product) => {
      const vendorName = product.split(":")[0] || "unknown";
      const productKey = `product:${product}`;
      if (vendorProducts.has(vendorName)) vendorProducts.get(vendorName)!.add(productKey);
      if (!productCVEs.has(productKey)) productCVEs.set(productKey, []);
      productCVEs.get(productKey)!.push(cve.cve_id);
    });
  });

  vendorProducts.forEach((products, vendorName) => {
    const vendorCves = cves.filter((c) => c.affected_vendors?.includes(vendorName));
    const maxCvss = Math.max(...vendorCves.map((c) => c.cvss_score || 0), 0);
    const hasCritical = vendorCves.some((c) => c.severity === "CRITICAL");
    const hasExploit = vendorCves.some((c) => c.exploit_available);

    nodes.push({
      id: `vendor:${vendorName}`,
      name: formatDisplayName(vendorName),
      type: "vendor",
      stability: Math.max(10, 100 - maxCvss * 10),
      risk: Math.min(100, maxCvss * 10),
      connections: Array.from(products),
      status: hasCritical ? "critical" : hasExploit ? "exploited" : maxCvss >= 7 ? "warning" : "operational",
      cvss_score: maxCvss,
      severity: hasCritical ? "CRITICAL" : maxCvss >= 7 ? "HIGH" : "MEDIUM",
      description: `${vendorCves.length} vulnerabilities affecting ${vendorName} products`,
    });
  });

  productCVEs.forEach((cveIds, productKey) => {
    const productCveData = cves.filter((c) => cveIds.includes(c.cve_id));
    const maxCvss = Math.max(...productCveData.map((c) => c.cvss_score || 0), 0);
    const productName = productKey.replace("product:", "").split(":")[1] || productKey;
    const hasCritical = productCveData.some((c) => c.severity === "CRITICAL");
    const hasExploit = productCveData.some((c) => c.exploit_available);

    nodes.push({
      id: productKey,
      name: formatDisplayName(productName),
      type: "product",
      stability: Math.max(10, 100 - maxCvss * 10),
      risk: Math.min(100, maxCvss * 10),
      connections: cveIds.map((id) => `cve:${id}`),
      status: hasCritical ? "critical" : hasExploit ? "exploited" : maxCvss >= 7 ? "warning" : "operational",
      cvss_score: maxCvss,
      severity: hasCritical ? "CRITICAL" : maxCvss >= 7 ? "HIGH" : "MEDIUM",
      affected_products: [productKey.replace("product:", "")],
      description: `${productCveData.length} CVEs affecting ${formatDisplayName(productName)}`,
    });
  });

  const cvesByProduct = new Map<string, CVEVulnerability[]>();
  cves.forEach((cve) => {
    (cve.affected_products || []).forEach((product) => {
      const key = `product:${product}`;
      if (!cvesByProduct.has(key)) cvesByProduct.set(key, []);
      cvesByProduct.get(key)!.push(cve);
    });
  });

  cves.forEach((cve) => {
    if (!cve.cve_id) return;

    const phaseOrder = getPhaseOrder(cve.cwe_ids || []);
    const cascadeConnections: string[] = [];

    (cve.affected_products || []).forEach((product) => {
      const key = `product:${product}`;
      const siblingCves = cvesByProduct.get(key) || [];
      siblingCves.forEach((sibling) => {
        if (sibling.cve_id === cve.cve_id) return;
        const siblingOrder = getPhaseOrder(sibling.cwe_ids || []);
        if (siblingOrder > phaseOrder && (sibling.cvss_score || 0) >= 5) {
          const targetId = `cve:${sibling.cve_id}`;
          if (!cascadeConnections.includes(targetId)) cascadeConnections.push(targetId);
        }
      });
    });

    cves.forEach((other) => {
      if (other.cve_id === cve.cve_id) return;
      if (cascadeConnections.includes(`cve:${other.cve_id}`)) return;
      const otherOrder = getPhaseOrder(other.cwe_ids || []);
      if (otherOrder <= phaseOrder) return;
      const confidence = computeChainConfidence(cve, other);
      if (confidence >= 70) cascadeConnections.push(`cve:${other.cve_id}`);
    });

    // ── EPSS-blended risk score ──────────────────────────────────────
    // Formula: 60% CVSS base + 40% EPSS exploitation probability
    // Rationale: CVSS=severity of bug, EPSS=likelihood of real attack
    // FIRST.org recommends combining both for prioritization accuracy.
    // Example: CVSS=9.8 + EPSS=0.02 → high severity but low real risk
    //          CVSS=5.5 + EPSS=0.94 → moderate severity, actively exploited
    const cvssRisk = Math.min(100, (cve.cvss_score || 0) * 10);
    const epssRisk = cve.epss_score != null
      ? Math.min(100, cve.epss_score * 100)
      : cvssRisk;
    const blendedRisk = cve.epss_score != null
      ? Math.round(cvssRisk * 0.6 + epssRisk * 0.4)
      : cvssRisk;
    // ─────────────────────────────────────────────────────────────────

    // Asset confirmation from backend intelligence engine
    const assetMatches = cve.asset_matches || [];
    const confirmedOnAsset = assetMatches.length > 0;

    nodes.push({
      id: `cve:${cve.cve_id}`,
      name: cve.cve_id,
      type: "vulnerability",
      stability: Math.max(5, 100 - blendedRisk),
      risk: blendedRisk,
      connections: cascadeConnections,
      status: determineNodeStatus(cve),
      cvss_score: cve.cvss_score,
      severity: cve.severity,
      exploit_available: cve.exploit_available,
      patch_available: cve.patch_available,
      cve_id: cve.cve_id,
      description: cve.description,
      attack_vector: cve.attack_vector,
      attack_complexity: cve.attack_complexity,
      privileges_required: cve.privileges_required,
      cwe_ids: cve.cwe_ids,
      affected_products: cve.affected_products,
      affected_vendors: cve.affected_vendors,
      vuln_status: cve.vuln_status,
      published_date: cve.published_date,
      references: cve.references,
      // ── EPSS fields ───────────────────────────────────────────────
      epss_score: cve.epss_score,
      epss_percentile: cve.epss_percentile,
      cisa_kev: cve.cisa_kev,
      // ── Asset confirmation ────────────────────────────────────────
      asset_match_count: assetMatches.length,
      confirmed_on_asset: confirmedOnAsset,
    });
  });

  return nodes;
}

function computeChainConfidence(source: CVEVulnerability, target: CVEVulnerability): number {
  let score = 0;

  const chains: [string[], string[]][] = [
    [["CWE-200", "CWE-204", "CWE-209"], ["CWE-287", "CWE-306", "CWE-862"]],
    [["CWE-352", "CWE-346", "CWE-601"], ["CWE-79", "CWE-94", "CWE-78"]],
    [["CWE-287", "CWE-306", "CWE-295"], ["CWE-269", "CWE-284", "CWE-285"]],
    [["CWE-434", "CWE-22"], ["CWE-78", "CWE-94"]],
    [["CWE-79", "CWE-80"], ["CWE-287", "CWE-200"]],
    [["CWE-918"], ["CWE-200", "CWE-284"]],
    [["CWE-74", "CWE-89", "CWE-78"], ["CWE-400", "CWE-122"]],
  ];

  const sourceCWEs = source.cwe_ids || [];
  const targetCWEs = target.cwe_ids || [];

  for (const [sp, tp] of chains) {
    const srcMatch = sourceCWEs.some((c) => sp.includes(c));
    const tgtMatch = targetCWEs.some((c) => tp.includes(c));
    if (srcMatch && tgtMatch) score += 50;
  }

  const srcVendors = source.affected_vendors || [];
  const tgtVendors = target.affected_vendors || [];
  if (srcVendors.some((v) => tgtVendors.includes(v))) score += 20;
  if (source.exploit_available) score += 15;
  if (target.severity === "CRITICAL" || target.severity === "HIGH") score += 15;

  return Math.min(100, score);
}

function checkCWEChainRelationship(sourceCWEs: string[], targetCWEs: string[]): boolean {
  const chains: [string[], string[]][] = [
    [["CWE-200", "CWE-204", "CWE-209"], ["CWE-287", "CWE-306", "CWE-862"]],
    [["CWE-352", "CWE-346", "CWE-601"], ["CWE-79", "CWE-94", "CWE-78"]],
    [["CWE-287", "CWE-306", "CWE-295"], ["CWE-269", "CWE-284", "CWE-285"]],
    [["CWE-434", "CWE-22"], ["CWE-78", "CWE-94"]],
    [["CWE-79", "CWE-80"], ["CWE-287", "CWE-200"]],
    [["CWE-918"], ["CWE-200", "CWE-284"]],
    [["CWE-74", "CWE-89", "CWE-78"], ["CWE-400", "CWE-122"]],
  ];
  for (const [sp, tp] of chains) {
    if (sourceCWEs.some((c) => sp.includes(c)) && targetCWEs.some((c) => tp.includes(c))) return true;
  }
  return false;
}

function formatDisplayName(raw: string): string {
  return raw
    .replace(/_/g, " ")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .split(" ")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
    .join(" ");
}

function getPrimaryPhase(cweIds: string[]): string {
  for (const cwe of cweIds) {
    const mapped = CWE_PHASE_MAP[cwe];
    if (mapped) return mapped.phase;
  }
  return "unknown";
}

function getPhaseOrder(cweIds: string[]): number {
  let minOrder = 99;
  for (const cwe of cweIds) {
    const mapped = CWE_PHASE_MAP[cwe];
    if (mapped && mapped.order < minOrder) minOrder = mapped.order;
  }
  return minOrder === 99 ? 2 : minOrder;
}

function determineNodeStatus(cve: CVEVulnerability): "operational" | "warning" | "critical" | "exploited" | "mitigated" {
  if (cve.exploit_available && cve.cvss_score >= 8) return "exploited";
  if (cve.severity === "CRITICAL") return "critical";
  if (cve.exploit_available) return "critical";
  if (cve.severity === "HIGH") return "warning";
  return "operational";
}

// ═══════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════

function getStatusColor(status: string) {
  switch (status) {
    case "exploited": return { main: "#6366F1", glow: "rgba(236,72,153,0.4)", bg: "rgba(99,102,241,0.12)" };
    case "critical": return { main: "#EF4444", glow: "rgba(239,68,68,0.4)", bg: "rgba(239,68,68,0.12)" };
    case "warning": return { main: "#F59E0B", glow: "rgba(245,158,11,0.28)", bg: "rgba(245,158,11,0.15)" };
    case "operational": return { main: "#22C55E", glow: "rgba(34,197,94,0.28)", bg: "rgba(34,197,94,0.10)" };
    case "mitigated": return { main: "#06B6D4", glow: "rgba(6,182,212,0.26)", bg: "rgba(6,182,212,0.12)" };
    default: return { main: "#A1A1AA", glow: "rgba(100,116,139,0.4)", bg: "rgba(161,161,170,0.10)" };
  }
}

function getSeverityColor(severity?: string) {
  switch (severity) {
    case "CRITICAL": return "#EF4444";
    case "HIGH": return "#F59E0B";
    case "MEDIUM": return "#F59E0B";
    case "LOW": return "#22C55E";
    default: return "#A1A1AA";
  }
}

// ═══════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════

const NODE_SIZE = 56;
const LEVEL_GAP_X = 220;
const NODE_GAP_Y = 90;
const PADDING = 100;

const MITIGATION_ACTIONS: MitigationAction[] = [
  { id: "patch", label: "Apply Security Patch", description: "Install the latest security patch to fix the vulnerability", icon: <Shield className="h-5 w-5" />, type: "patch", risk_reduction: 95, time_estimate: "5-10 min" },
  { id: "isolate", label: "Isolate System", description: "Temporarily isolate the affected system from the network", icon: <CircleSlash className="h-5 w-5" />, type: "isolate", risk_reduction: 80, time_estimate: "Immediate" },
  { id: "block", label: "Block Attack Vector", description: "Configure firewall rules to block the exploit path", icon: <Ban className="h-5 w-5" />, type: "block", risk_reduction: 70, time_estimate: "2-5 min" },
  { id: "monitor", label: "Enhanced Monitoring", description: "Enable detailed logging and real-time alerts", icon: <Activity className="h-5 w-5" />, type: "monitor", risk_reduction: 30, time_estimate: "1-2 min" },
  { id: "script", label: "Run Remediation Script", description: "Execute automated remediation playbook", icon: <Terminal className="h-5 w-5" />, type: "script", risk_reduction: 85, time_estimate: "3-8 min" },
];

// ═══════════════════════════════════════════════════════════════════════
// NODE ICON
// ═══════════════════════════════════════════════════════════════════════

function NodeIcon({ type, severity, size = 22 }: { type: string; severity?: string; size?: number }) {
  const props = { size, strokeWidth: 1.5 };
  if (type === "vulnerability") {
    switch (severity) {
      case "CRITICAL": return <ShieldX {...props} />;
      case "HIGH": return <ShieldAlert {...props} />;
      case "MEDIUM": return <Shield {...props} />;
      default: return <Bug {...props} />;
    }
  }
  switch (type) {
    case "vendor": return <Globe {...props} />;
    case "product": return <Server {...props} />;
    case "gateway": return <Globe {...props} />;
    case "server": return <Server {...props} />;
    case "database": return <Database {...props} />;
    case "network": return <Network {...props} />;
    case "application": return <MonitorSmartphone {...props} />;
    default: return <Cpu {...props} />;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// LAYOUT ENGINE
// ═══════════════════════════════════════════════════════════════════════

function buildCascadeLayout(
  safeNodes: NodeStatus[],
  mitigatedNodes: Set<string>,
  mode: GraphMode,
  filters: GraphFilters
): {
  cascadeNodes: CascadeNode[];
  edges: Edge[];
  dimensions: { width: number; height: number };
  maxLevel: number;
  phaseLabels: { phase: string; x: number }[];
} {
  const emptyResult = {
    cascadeNodes: [] as CascadeNode[],
    edges: [] as Edge[],
    dimensions: { width: 1000, height: 600 },
    maxLevel: 0,
    phaseLabels: [] as { phase: string; x: number }[],
  };

  if (safeNodes.length === 0) return emptyResult;

  try {
    let filteredNodes = safeNodes.filter((n) => {
      if (n.type !== "vulnerability") return true;
      if (filters.severity.size > 0 && n.severity && !filters.severity.has(n.severity)) return false;
      if (filters.exploitOnly && !n.exploit_available) return false;
      if (filters.patchableOnly && !n.patch_available) return false;
      if (filters.phase.size > 0 && n.cwe_ids) {
        const phase = getPrimaryPhase(n.cwe_ids);
        if (!filters.phase.has(phase)) return false;
      }
      if (n.cvss_score != null && n.cvss_score < filters.minCvss) return false;
      return true;
    });

    const nodeMap = new Map<string, NodeStatus>();
    filteredNodes.forEach((n) => nodeMap.set(n.id, n));

    const children = new Map<string, string[]>();
    const parents = new Map<string, string[]>();
    filteredNodes.forEach((n) => { children.set(n.id, []); parents.set(n.id, []); });

    filteredNodes.forEach((node) => {
      if (!Array.isArray(node.connections)) return;
      node.connections.forEach((conn) => {
        if (!conn) return;
        let targetId = conn;
        if (!nodeMap.has(targetId)) {
          const found = filteredNodes.find((n) => n.name === conn);
          if (found) targetId = found.id;
          else return;
        }
        if (targetId === node.id) return;

        if (mode === "blast_radius") {
          const src = nodeMap.get(node.id);
          const tgt = nodeMap.get(targetId);
          if (src?.type === "vulnerability" && tgt?.type === "vulnerability") return;
        }

        if (mode === "infrastructure") {
          const src = nodeMap.get(node.id);
          const tgt = nodeMap.get(targetId);
          if (src?.type === "vulnerability" && tgt?.type === "vulnerability") return;
        }

        const childList = children.get(node.id);
        if (childList && !childList.includes(targetId)) childList.push(targetId);
        const parentList = parents.get(targetId);
        if (parentList && !parentList.includes(node.id)) parentList.push(node.id);
      });
    });

    let roots = filteredNodes.filter((n) => (parents.get(n.id) || []).length === 0);
    if (roots.length === 0) {
      roots = filteredNodes
        .filter((n) => n.status === "exploited" || n.severity === "CRITICAL")
        .sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0));
    }
    if (roots.length === 0 && filteredNodes.length > 0) {
      roots = [filteredNodes.reduce((a, b) => ((a.risk || 0) > (b.risk || 0) ? a : b))];
    }

    const levels = new Map<string, number>();
    const visited = new Set<string>();
    const queue: { id: string; level: number }[] = [];
    roots.forEach((r) => { queue.push({ id: r.id, level: 0 }); visited.add(r.id); });

    let maxLvl = 0;
    while (queue.length > 0) {
      const { id, level } = queue.shift()!;
      levels.set(id, level);
      maxLvl = Math.max(maxLvl, level);
      (children.get(id) || []).forEach((childId) => {
        if (!visited.has(childId)) {
          visited.add(childId);
          queue.push({ id: childId, level: level + 1 });
        }
      });
    }

    filteredNodes.forEach((n) => {
      if (!levels.has(n.id)) {
        if (n.type === "vulnerability" && n.cwe_ids) {
          const phaseOrder = getPhaseOrder(n.cwe_ids);
          levels.set(n.id, phaseOrder);
          maxLvl = Math.max(maxLvl, phaseOrder);
        } else {
          levels.set(n.id, maxLvl + 1);
          maxLvl = Math.max(maxLvl, maxLvl + 1);
        }
      }
    });

    const levelGroups = new Map<number, string[]>();
    levels.forEach((level, id) => {
      if (!levelGroups.has(level)) levelGroups.set(level, []);
      levelGroups.get(level)!.push(id);
    });

    levelGroups.forEach((ids) => {
      ids.sort((a, b) => {
        const na = nodeMap.get(a);
        const nb = nodeMap.get(b);
        return (nb?.cvss_score || 0) - (na?.cvss_score || 0);
      });
    });

    let maxNodesInLevel = 0;
    levelGroups.forEach((ids) => { maxNodesInLevel = Math.max(maxNodesInLevel, ids.length); });

    const width = PADDING * 2 + (maxLvl + 1) * LEVEL_GAP_X;
    const height = Math.max(600, PADDING * 2 + maxNodesInLevel * NODE_GAP_Y);

    const positioned: CascadeNode[] = [];
    const phaseLabels: { phase: string; x: number }[] = [];

    levelGroups.forEach((nodeIds, level) => {
      const count = nodeIds.length;
      const totalHeight = (count - 1) * NODE_GAP_Y;
      const startY = (height - totalHeight) / 2;

      const phaseCounts = new Map<string, number>();
      nodeIds.forEach((id) => {
        const node = nodeMap.get(id);
        if (node?.cwe_ids) {
          const phase = getPrimaryPhase(node.cwe_ids);
          phaseCounts.set(phase, (phaseCounts.get(phase) || 0) + 1);
        }
      });

      let dominantPhase = "unknown";
      let maxCount = 0;
      phaseCounts.forEach((c, phase) => { if (c > maxCount) { maxCount = c; dominantPhase = phase; } });

      const x = PADDING + level * LEVEL_GAP_X;
      phaseLabels.push({ phase: dominantPhase, x });

      nodeIds.forEach((id, idx) => {
        const node = nodeMap.get(id);
        if (!node) return;
        const isMitigated = mitigatedNodes.has(id);
        const cascadePhase = node.cwe_ids ? getPrimaryPhase(node.cwe_ids) : "unknown";

        positioned.push({
          ...node,
          status: isMitigated ? ("mitigated" as const) : node.status,
          risk: isMitigated ? Math.max(5, (node.risk || 0) * 0.1) : node.risk || 0,
          position: { x, y: startY + idx * NODE_GAP_Y },
          level,
          children: children.get(id) || [],
          parents: parents.get(id) || [],
          cascadePhase,
        });
      });
    });

    const edgeList: Edge[] = [];
    const posMap = new Map(positioned.map((n) => [n.id, n.position]));

    positioned.forEach((node) => {
      if (!node.children) return;
      node.children.forEach((childId) => {
        const targetPos = posMap.get(childId);
        if (!targetPos) return;
        const targetNode = positioned.find((n) => n.id === childId);
        const edgeType = determineEdgeType(node, targetNode);

        // ── Real edge confidence scoring ──────────────────────────────
        // Priority order (highest confidence wins):
        //   confirmed     (95) = both CVEs on same confirmed asset
        //   high_inferred (85) = proven CWE chain relationship
        //   inferred      (65) = same vendor + exploit available
        //   weak          (45) = heuristic / phase order only
        let confidence = 45;
        let edgeConfirmation: "confirmed" | "high_inferred" | "inferred" | "weak" = "weak";

        const sharedVendor = (node.affected_vendors || []).some(
          (v) => (targetNode?.affected_vendors || []).includes(v)
        );
        const bothConfirmedOnAsset =
          node.confirmed_on_asset === true &&
          targetNode?.confirmed_on_asset === true &&
          sharedVendor;

        if (bothConfirmedOnAsset) {
          confidence = 95;
          edgeConfirmation = "confirmed";
        } else if (
          node.cwe_ids &&
          targetNode?.cwe_ids &&
          checkCWEChainRelationship(node.cwe_ids, targetNode.cwe_ids)
        ) {
          confidence = 85;
          edgeConfirmation = "high_inferred";
        } else if (sharedVendor && node.exploit_available) {
          confidence = 65;
          edgeConfirmation = "inferred";
        }

        // EPSS boost: high-probability source makes chain more credible
        if (node.epss_score != null && node.epss_score > 0.5) {
          confidence = Math.min(95, confidence + 10);
        }
        // ─────────────────────────────────────────────────────────────

        edgeList.push({
          id: `${node.id}--${childId}`,
          source: node.id,
          target: childId,
          sourcePos: node.position,
          targetPos,
          risk: Math.max(node.risk || 0, targetNode?.risk || 0),
          edgeType,
          confidence,
          edgeConfirmation,
          label: edgeType === "cwe_chain" ? "chain" : undefined,
        });
      });
    });

    return { cascadeNodes: positioned, edges: edgeList, dimensions: { width, height }, maxLevel: maxLvl, phaseLabels };
  } catch (error) {
    console.error("InfrastructureGraph: Error building cascade graph:", error);
    return emptyResult;
  }
}

function determineEdgeType(source: CascadeNode, target?: CascadeNode | null): Edge["edgeType"] {
  if (!target) return "cascade";
  if (source.type === "vendor" && target.type === "product") return "vendor";
  if (source.type === "product" && target.type === "vulnerability") return "product";
  if (source.type === "vulnerability" && target.type === "vulnerability") {
    if (source.cwe_ids && target.cwe_ids && checkCWEChainRelationship(source.cwe_ids, target.cwe_ids)) return "cwe_chain";
    if (source.exploit_available) return "exploit_path";
  }
  return "cascade";
}

// ═══════════════════════════════════════════════════════════════════════
// MITIGATION MODAL
// ═══════════════════════════════════════════════════════════════════════

function MitigationModal({
  isOpen, onClose, node, actions, onComplete,
}: {
  isOpen: boolean;
  onClose: () => void;
  node: CascadeNode | null;
  actions: MitigationAction[];
  onComplete: (nodeId: string, actionId: string) => void;
}) {
  const [step, setStep] = useState<"select" | "confirm" | "progress" | "success">("select");
  const [selectedAction, setSelectedAction] = useState<MitigationAction | null>(null);
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    if (isOpen) { setStep("select"); setSelectedAction(null); setProgress(0); }
  }, [isOpen]);

  const handleSelectAction = (action: MitigationAction) => { setSelectedAction(action); setStep("confirm"); };

  const handleConfirm = () => {
    if (!selectedAction || !node) return;
    setStep("progress");
    setProgress(0);
    const progressInterval = setInterval(() => {
      setProgress((prev) => { if (prev >= 100) { clearInterval(progressInterval); return 100; } return prev + Math.random() * 15 + 5; });
    }, 200);
    setTimeout(() => {
      clearInterval(progressInterval);
      setProgress(100);
      setTimeout(() => { setStep("success"); onComplete(node.id, selectedAction.id); }, 500);
    }, 2500);
  };

  if (!isOpen || !node) return null;
  const colors = getStatusColor(node.status);

  return createPortal(
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
        className="fixed inset-0 z-[9999] flex items-center justify-center p-4"
        style={{ backgroundColor: "rgba(9,9,11,0.78)", backdropFilter: "blur(12px)" }}
        onClick={onClose}
      >
        <motion.div
          initial={{ scale: 0.9, opacity: 0, y: 20 }} animate={{ scale: 1, opacity: 1, y: 0 }}
          exit={{ scale: 0.9, opacity: 0, y: 20 }} transition={{ type: "spring", damping: 25, stiffness: 300 }}
          className="w-full max-w-lg bg-[#0d0d12]/98 rounded-2xl border border-white/8 shadow-[0_32px_80px_-16px_rgba(0,0,0,0.7)] overflow-hidden"
          onClick={(e) => e.stopPropagation()}
        >
          <div className="p-5 border-b border-white/5 bg-gradient-to-r from-[#131318]/80 to-transparent">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl" style={{ backgroundColor: colors.bg, border: `2px solid ${colors.main}`, color: colors.main }}>
                  <Shield className="h-5 w-5" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-white">Mitigation Actions</h3>
                  <p className="text-xs text-[#52525B]">{node.name}</p>
                </div>
              </div>
              <button onClick={onClose} className="p-2 rounded-lg hover:bg-white/8 text-[#A1A1AA] hover:text-white transition-colors">
                <X className="h-5 w-5" />
              </button>
            </div>
            <div className="flex flex-wrap items-center gap-2 mt-3">
              {node.severity && (
                <span className="px-2.5 py-1 rounded-lg text-xs font-bold" style={{ backgroundColor: `${colors.main}20`, color: colors.main }}>{node.severity}</span>
              )}
              {node.cve_id && <span className="px-2.5 py-1 rounded-lg text-xs font-mono bg-[#131318] text-[#F87171] border border-white/8">{node.cve_id}</span>}
              {node.cvss_score != null && <span className="px-2.5 py-1 rounded-lg text-xs font-bold bg-[#131318] text-[#FBBF24] border border-white/8">CVSS {node.cvss_score.toFixed(1)}</span>}
              {node.cascadePhase && (
                <span className="px-2.5 py-1 rounded-lg text-xs font-bold" style={{ backgroundColor: (PHASE_COLORS[node.cascadePhase] || PHASE_COLORS.unknown).bg, color: (PHASE_COLORS[node.cascadePhase] || PHASE_COLORS.unknown).main }}>
                  {(PHASE_COLORS[node.cascadePhase] || PHASE_COLORS.unknown).label}
                </span>
              )}
            </div>
          </div>

          <div className="p-5 max-h-[60vh] overflow-y-auto">
            {step === "select" && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-3">
                <p className="text-sm text-[#A1A1AA] mb-4">Select a mitigation strategy for this vulnerability:</p>
                {(actions || []).map((action, index) => (
                  <motion.button key={action.id} initial={{ x: -20, opacity: 0 }} animate={{ x: 0, opacity: 1 }} transition={{ delay: index * 0.05 }}
                    onClick={() => handleSelectAction(action)}
                    className="w-full flex items-start gap-4 p-4 rounded-xl bg-[#131318]/30 hover:bg-white/8/60 border border-white/8/30 hover:border-white/12 transition-all text-left group"
                  >
                    <div className="p-2.5 rounded-lg bg-white/6 text-[#A1A1AA] group-hover:text-white group-hover:bg-white/8 transition-colors">{action.icon}</div>
                    <div className="flex-1">
                      <div className="flex items-center justify-between mb-1">
                        <p className="font-medium text-white">{action.label}</p>
                        <span className="text-xs text-[#4ADE80] font-bold">-{action.risk_reduction}% risk</span>
                      </div>
                      <p className="text-xs text-[#52525B] mb-2">{action.description}</p>
                      <div className="flex items-center gap-2 text-xs text-[#A1A1AA]"><Clock className="h-3 w-3" /><span>{action.time_estimate}</span></div>
                    </div>
                    <ChevronRight className="h-5 w-5 text-[#52525B] group-hover:text-white mt-2" />
                  </motion.button>
                ))}
              </motion.div>
            )}

            {step === "confirm" && selectedAction && (
              <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} className="space-y-4">
                <div className="p-4 rounded-xl bg-[#131318]/50 border border-white/8">
                  <div className="flex items-center gap-3 mb-3">
                    <div className="p-2 rounded-lg bg-white/6 text-white">{selectedAction.icon}</div>
                    <div>
                      <p className="font-medium text-white">{selectedAction.label}</p>
                      <p className="text-xs text-[#52525B]">{selectedAction.time_estimate}</p>
                    </div>
                  </div>
                  <p className="text-sm text-[#A1A1AA]">{selectedAction.description}</p>
                </div>
                <div className="p-4 rounded-xl bg-[#F59E0B]/10 border border-[#F59E0B]/25">
                  <div className="flex items-start gap-3">
                    <AlertTriangle className="h-5 w-5 text-[#FBBF24] flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-sm font-medium text-[#FBBF24]">Confirmation Required</p>
                      <p className="text-xs text-[#A1A1AA] mt-1">This will modify the cascade graph. Downstream vulnerabilities may also be affected.</p>
                    </div>
                  </div>
                </div>
                {node.children && node.children.length > 0 && (
                  <div className="p-4 rounded-xl bg-[#6366F1]/10 border border-[#6366F1]/25">
                    <div className="flex items-start gap-3">
                      <Workflow className="h-5 w-5 text-[#A78BFA] flex-shrink-0 mt-0.5" />
                      <div>
                        <p className="text-sm font-medium text-[#A78BFA]">Cascade Impact</p>
                        <p className="text-xs text-[#A1A1AA] mt-1">
                          Mitigating this will reduce propagation risk to <span className="text-white font-bold">{node.children.length}</span> downstream vulnerabilities
                        </p>
                      </div>
                    </div>
                  </div>
                )}
                <div className="flex gap-3 pt-2">
                  <button onClick={() => setStep("select")} className="flex-1 px-4 py-2.5 rounded-xl bg-[#131318] hover:bg-white/8 text-[#E4E4E7] font-medium transition-colors">Back</button>
                  <button onClick={handleConfirm} className="flex-1 px-4 py-2.5 rounded-xl bg-gradient-to-r from-[#3B82F6] to-[#6366F1] hover:from-[#2563EB] hover:to-[#4F46E5] text-white font-medium transition-all flex items-center justify-center gap-2 shadow-lg shadow-[#3B82F6]/25">
                    <PlayCircle className="h-4 w-4" /> Execute
                  </button>
                </div>
              </motion.div>
            )}

            {step === "progress" && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="py-8 text-center">
                <motion.div animate={{ rotate: 360 }} transition={{ duration: 2, repeat: Infinity, ease: "linear" }} className="inline-block mb-4">
                  <Loader2 className="h-12 w-12 text-[#FBBF24]" />
                </motion.div>
                <p className="text-lg font-medium text-white mb-2">Applying Mitigation...</p>
                <p className="text-sm text-[#52525B] mb-6">{selectedAction?.label}</p>
                <div className="max-w-xs mx-auto">
                  <div className="flex justify-between text-xs text-[#A1A1AA] mb-2"><span>Progress</span><span>{Math.min(100, Math.round(progress))}%</span></div>
                  <div className="h-2 bg-white/6 rounded-full overflow-hidden">
                    <motion.div className="h-full bg-gradient-to-r from-[#3B82F6] to-[#6366F1] rounded-full" initial={{ width: 0 }} animate={{ width: `${Math.min(100, progress)}%` }} />
                  </div>
                </div>
                <div className="mt-6 space-y-2 text-left max-w-xs mx-auto">
                  {[
                    { text: "Analyzing CWE chain...", done: progress > 15 },
                    { text: "Checking affected products...", done: progress > 35 },
                    { text: "Applying security patches...", done: progress > 55 },
                    { text: "Updating cascade graph...", done: progress > 75 },
                    { text: "Verifying mitigation...", done: progress >= 100 },
                  ].map((item, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs">
                      {item.done ? <Check className="h-3.5 w-3.5 text-[#4ADE80]" /> : progress > i * 20 ? <Loader2 className="h-3.5 w-3.5 text-[#FBBF24] animate-spin" /> : <div className="h-3.5 w-3.5 rounded-full border border-white/10" />}
                      <span className={item.done ? "text-[#4ADE80]" : "text-[#52525B]"}>{item.text}</span>
                    </div>
                  ))}
                </div>
              </motion.div>
            )}

            {step === "success" && (
              <motion.div initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} className="py-8 text-center">
                <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: "spring", delay: 0.1 }} className="inline-flex items-center justify-center w-20 h-20 rounded-full bg-[#22C55E]/15 mb-4">
                  <CheckCircle className="h-10 w-10 text-[#4ADE80]" />
                </motion.div>
                <h3 className="text-xl font-bold text-white mb-2">Mitigation Successful!</h3>
                <p className="text-sm text-[#A1A1AA] mb-6">Cascade propagation path has been interrupted.</p>
                <div className="p-4 rounded-xl bg-[#22C55E]/10 border border-[#22C55E]/25 max-w-xs mx-auto mb-6">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-[#A1A1AA]">Risk Reduced</span>
                    <span className="text-[#4ADE80] font-bold">-{selectedAction?.risk_reduction}%</span>
                  </div>
                </div>
                <button onClick={onClose} className="px-8 py-2.5 rounded-xl bg-[#22C55E] hover:bg-[#16A34A] text-white font-medium transition-colors">Done</button>
              </motion.div>
            )}
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>,
    document.body
  );
}

// ═══════════════════════════════════════════════════════════════════════
// LEGEND
// ═══════════════════════════════════════════════════════════════════════

function Legend({ onClose }: { onClose?: () => void }) {
  return (
    <div className="bg-[#0d0d12]/95 backdrop-blur-sm border border-white/8 rounded-xl p-4 shadow-2xl max-w-[200px]">
      {onClose && (
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-[#FAFAFA]">Legend</h3>
          <button onClick={onClose} className="p-1 rounded hover:bg-white/8 text-[#A1A1AA] hover:text-white"><X className="h-3 w-3" /></button>
        </div>
      )}
      {!onClose && <h3 className="text-sm font-semibold text-[#FAFAFA] mb-3">Status</h3>}
      <div className="space-y-2">
        {[
          { color: "bg-emerald-500", label: "Operational" },
          { color: "bg-yellow-500", label: "Warning" },
          { color: "bg-red-500", label: "Critical" },
          { color: "bg-pink-500 animate-pulse", label: "Exploited" },
          { color: "bg-cyan-500", label: "Mitigated" },
        ].map((item) => (
          <div key={item.label} className="flex items-center gap-2">
            <div className={`w-3 h-3 rounded-full ${item.color}`} />
            <span className="text-xs text-[#E4E4E7]">{item.label}</span>
          </div>
        ))}
      </div>
      <div className="mt-4 pt-3 border-t border-white/8">
        <h3 className="text-sm font-semibold text-[#FAFAFA] mb-2">Kill Chain Phase</h3>
        <div className="space-y-2">
          {Object.entries(PHASE_COLORS).filter(([k]) => k !== "unknown").map(([key, value]) => (
            <div key={key} className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full" style={{ backgroundColor: value.main }} />
              <span className="text-xs text-[#E4E4E7]">{value.label}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="mt-4 pt-3 border-t border-white/8">
        <h3 className="text-sm font-semibold text-[#FAFAFA] mb-2">Node Types</h3>
        <div className="space-y-2">
          {[
            { icon: <Globe className="w-3 h-3 text-[#60A5FA]" />, label: "Vendor" },
            { icon: <Server className="w-3 h-3 text-[#A78BFA]" />, label: "Product" },
            { icon: <Shield className="w-3 h-3 text-[#F87171]" />, label: "CVE" },
          ].map((item) => (
            <div key={item.label} className="flex items-center gap-2">{item.icon}<span className="text-xs text-[#E4E4E7]">{item.label}</span></div>
          ))}
        </div>
      </div>
      <div className="mt-4 pt-3 border-t border-white/8">
        <h3 className="text-sm font-semibold text-[#FAFAFA] mb-2">Badges</h3>
        <div className="space-y-2">
          {[
            { icon: <Skull className="w-3 h-3 text-[#EF4444]" />, label: "Exploit Available" },
            { icon: <CheckCircle className="w-3 h-3 text-green-500" />, label: "Patch Available" },
          ].map((item) => (
            <div key={item.label} className="flex items-center gap-2">{item.icon}<span className="text-xs text-[#E4E4E7]">{item.label}</span></div>
          ))}
        </div>
      </div>
      <div className="mt-4 pt-3 border-t border-white/8">
        <h3 className="text-sm font-semibold text-[#FAFAFA] mb-2">Chain Confidence</h3>
        <div className="space-y-2">
          {[
            { color: "#22C55E", label: "Confirmed (asset match)", dash: false },
            { color: "#6366F1", label: "High (CWE chain)",        dash: false },
            { color: "#F59E0B", label: "Inferred (same vendor)",  dash: true  },
            { color: "#52525B", label: "Weak (heuristic)",        dash: true  },
          ].map((item) => (
            <div key={item.label} className="flex items-center gap-2">
              <svg width="24" height="8" className="flex-shrink-0">
                <line
                  x1="0" y1="4" x2="24" y2="4"
                  stroke={item.color}
                  strokeWidth="2"
                  strokeDasharray={item.dash ? "4 2" : "none"}
                />
              </svg>
              <span className="text-xs text-[#E4E4E7]">{item.label}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// FILTER PANEL — Portaled so it escapes any overflow clipping
// ═══════════════════════════════════════════════════════════════════════

function FilterPanel({
  isOpen,
  anchorRef,
  filters,
  onFiltersChange,
  onClose,
}: {
  isOpen: boolean;
  anchorRef: React.RefObject<HTMLButtonElement | null>;
  filters: GraphFilters;
  onFiltersChange: (f: GraphFilters) => void;
  onClose: () => void;
}) {
  const [pos, setPos] = useState({ top: 0, left: 0 });

  useEffect(() => {
    if (isOpen && anchorRef.current) {
      const rect = anchorRef.current.getBoundingClientRect();
      setPos({ top: rect.bottom + 8, left: rect.left });
    }
  }, [isOpen, anchorRef]);

  const toggleSeverity = (sev: string) => {
    const next = new Set(filters.severity);
    next.has(sev) ? next.delete(sev) : next.add(sev);
    onFiltersChange({ ...filters, severity: next });
  };

  const togglePhase = (phase: string) => {
    const next = new Set(filters.phase);
    next.has(phase) ? next.delete(phase) : next.add(phase);
    onFiltersChange({ ...filters, phase: next });
  };

  const activeFilterCount =
    filters.severity.size + filters.phase.size +
    (filters.exploitOnly ? 1 : 0) + (filters.patchableOnly ? 1 : 0) +
    (filters.minCvss > 0 ? 1 : 0);

  if (!isOpen) return null;

  return createPortal(
    <>
      {/* Click-outside overlay */}
      <div className="fixed inset-0 z-[9990]" onClick={onClose} />

      <motion.div
        initial={{ opacity: 0, y: 8, scale: 0.95 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        exit={{ opacity: 0, y: 8, scale: 0.95 }}
        transition={{ duration: 0.15 }}
        style={{ position: "fixed", top: pos.top, left: pos.left, zIndex: 9991 }}
        className="w-72 bg-[#0d0d12] border border-white/8 rounded-xl shadow-2xl p-4 space-y-4"
      >
        <div className="flex items-center justify-between">
          <span className="text-sm font-semibold text-[#FAFAFA]">Filter Graph</span>
          {activeFilterCount > 0 && (
            <button
              onClick={() => onFiltersChange({ severity: new Set(), exploitOnly: false, patchableOnly: false, phase: new Set(), minCvss: 0 })}
              className="text-xs text-[#FBBF24] hover:text-[#FCD34D]"
            >
              Clear all
            </button>
          )}
        </div>

        <div>
          <p className="text-xs text-[#52525B] mb-2">Severity</p>
          <div className="flex flex-wrap gap-2">
            {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
              <button
                key={sev}
                onClick={() => toggleSeverity(sev)}
                className="px-2.5 py-1 rounded-lg text-xs font-bold border transition-all"
                style={filters.severity.has(sev)
                  ? { backgroundColor: `${getSeverityColor(sev)}25`, color: getSeverityColor(sev), borderColor: `${getSeverityColor(sev)}50` }
                  : { backgroundColor: "rgba(255,255,255,0.04)", color: "#A1A1AA", borderColor: "rgba(255,255,255,0.08)" }
                }
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        <div>
          <p className="text-xs text-[#52525B] mb-2">Kill Chain Phase</p>
          <div className="flex flex-wrap gap-2">
            {Object.entries(PHASE_COLORS).filter(([k]) => k !== "unknown").map(([key, val]) => (
              <button
                key={key}
                onClick={() => togglePhase(key)}
                className="px-2.5 py-1 rounded-lg text-xs font-medium border transition-all"
                style={filters.phase.has(key)
                  ? { backgroundColor: val.bg, color: val.main, borderColor: `${val.main}50` }
                  : { backgroundColor: "rgba(255,255,255,0.04)", color: "#A1A1AA", borderColor: "rgba(255,255,255,0.08)" }
                }
              >
                {val.label.split(" ").slice(1).join(" ")}
              </button>
            ))}
          </div>
        </div>

        <div className="flex gap-3">
          <button
            onClick={() => onFiltersChange({ ...filters, exploitOnly: !filters.exploitOnly })}
            className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border transition-all"
            style={filters.exploitOnly
              ? { backgroundColor: "rgba(239,68,68,0.2)", borderColor: "rgba(239,68,68,0.4)", color: "#f87171" }
              : { backgroundColor: "rgba(255,255,255,0.04)", borderColor: "rgba(255,255,255,0.08)", color: "#A1A1AA" }
            }
          >
            <Skull className="h-3.5 w-3.5" /> Exploitable
          </button>
          <button
            onClick={() => onFiltersChange({ ...filters, patchableOnly: !filters.patchableOnly })}
            className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border transition-all"
            style={filters.patchableOnly
              ? { backgroundColor: "rgba(34,197,94,0.15)", borderColor: "rgba(34,197,94,0.25)", color: "#4ADE80" }
              : { backgroundColor: "rgba(255,255,255,0.04)", borderColor: "rgba(255,255,255,0.08)", color: "#A1A1AA" }
            }
          >
            <CheckCircle className="h-3.5 w-3.5" /> Patchable
          </button>
        </div>

        <div>
          <div className="flex items-center justify-between mb-2">
            <p className="text-xs text-[#52525B]">Min CVSS</p>
            <span className="text-xs font-bold text-[#FBBF24]">{filters.minCvss.toFixed(1)}+</span>
          </div>
          <input
            type="range" min="0" max="10" step="0.5" value={filters.minCvss}
            onChange={(e) => onFiltersChange({ ...filters, minCvss: parseFloat(e.target.value) })}
            className="w-full accent-orange-500"
          />
          <div className="flex justify-between text-[10px] text-[#52525B] mt-1">
            <span>0</span><span>5</span><span>10</span>
          </div>
        </div>
      </motion.div>
    </>,
    document.body
  );
}

// ═══════════════════════════════════════════════════════════════════════
// GRAPH CONTROLS BAR
// ═══════════════════════════════════════════════════════════════════════

function GraphControls({
  zoom, onZoom, onReset, onFitToScreen,
  mode, onModeChange,
  filters, onFiltersChange,
  search, onSearchChange,
  showLegend, onToggleLegend,
}: {
  zoom: number;
  onZoom: (delta: number) => void;
  onReset: () => void;
  onFitToScreen: () => void;
  mode: GraphMode;
  onModeChange: (m: GraphMode) => void;
  filters: GraphFilters;
  onFiltersChange: (f: GraphFilters) => void;
  search: string;
  onSearchChange: (s: string) => void;
  showLegend: boolean;
  onToggleLegend: () => void;
  stats: Record<string, number>;
}) {
  const [showFilters, setShowFilters] = useState(false);
  const filterBtnRef = useRef<HTMLButtonElement | null>(null);

  const MODES: { id: GraphMode; label: string; icon: React.ReactNode; desc: string }[] = [
    { id: "cascade", label: "Cascade", icon: <GitBranch className="h-3.5 w-3.5" />, desc: "Kill chain attack flow" },
    { id: "blast_radius", label: "Blast Radius", icon: <Package className="h-3.5 w-3.5" />, desc: "Vendor → Product → CVE" },
    { id: "infrastructure", label: "Infrastructure", icon: <LayoutGrid className="h-3.5 w-3.5" />, desc: "Asset exposure view" },
  ];

  const activeFilterCount =
    filters.severity.size + filters.phase.size +
    (filters.exploitOnly ? 1 : 0) + (filters.patchableOnly ? 1 : 0) +
    (filters.minCvss > 0 ? 1 : 0);

  return (
    // FIX: removed overflow-hidden; use visible overflow so filters can escape
    <div className="flex-shrink-0 px-4 py-2 border-b border-white/5 bg-[#09090B]/90 backdrop-blur-sm">
      <div className="flex items-center gap-3 flex-wrap">

        {/* Mode switcher */}
        <div className="flex items-center gap-1 p-1 rounded-xl bg-[#131318]/60 border border-white/8">
          {MODES.map((m) => (
            <button
              key={m.id}
              onClick={() => onModeChange(m.id)}
              title={m.desc}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                mode === m.id
                  ? "bg-white/8 text-white shadow"
                  : "text-[#A1A1AA] hover:text-white"
              }`}
            >
              {m.icon}
              <span className="hidden sm:inline">{m.label}</span>
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-[#131318]/60 border border-white/8 flex-1 min-w-[140px] max-w-[240px]">
          <Search className="h-3.5 w-3.5 text-[#52525B] flex-shrink-0" />
          <input
            type="text"
            value={search}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search CVE, vendor..."
            className="bg-transparent text-xs text-[#E4E4E7] placeholder-slate-600 outline-none w-full"
          />
          {search && (
            <button onClick={() => onSearchChange("")} className="text-[#52525B] hover:text-[#E4E4E7]">
              <X className="h-3 w-3" />
            </button>
          )}
        </div>

        {/* Filters button — portaled panel */}
        <button
          ref={filterBtnRef}
          onClick={() => setShowFilters(!showFilters)}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium border transition-all ${
            activeFilterCount > 0
              ? "bg-[#F59E0B]/15 border-[#F59E0B]/25 text-[#FBBF24]"
              : "bg-[#131318]/60 border-white/8 text-[#A1A1AA] hover:text-white"
          }`}
        >
          <SlidersHorizontal className="h-3.5 w-3.5" />
          <span className="hidden sm:inline">Filters</span>
          {activeFilterCount > 0 && (
            <span className="flex items-center justify-center w-4 h-4 rounded-full bg-orange-500 text-white text-[10px] font-bold">
              {activeFilterCount}
            </span>
          )}
        </button>

        <AnimatePresence>
          {showFilters && (
            <FilterPanel
              isOpen={showFilters}
              anchorRef={filterBtnRef}
              filters={filters}
              onFiltersChange={onFiltersChange}
              onClose={() => setShowFilters(false)}
            />
          )}
        </AnimatePresence>

        <div className="flex-1" />

        {/* Zoom controls */}
        <div className="flex items-center gap-1">
          <button onClick={() => onZoom(-0.1)} className="p-1.5 rounded-lg bg-[#131318]/60 border border-white/8 text-[#A1A1AA] hover:text-white hover:bg-white/8 transition-all" title="Zoom out">
            <ZoomOut className="h-3.5 w-3.5" />
          </button>
          <span className="text-xs text-[#52525B] w-12 text-center">{Math.round(zoom * 100)}%</span>
          <button onClick={() => onZoom(0.1)} className="p-1.5 rounded-lg bg-[#131318]/60 border border-white/8 text-[#A1A1AA] hover:text-white hover:bg-white/8 transition-all" title="Zoom in">
            <ZoomIn className="h-3.5 w-3.5" />
          </button>
          <button onClick={onFitToScreen} className="p-1.5 rounded-lg bg-[#131318]/60 border border-white/8 text-[#A1A1AA] hover:text-white hover:bg-white/8 transition-all" title="Fit to screen">
            <Maximize2 className="h-3.5 w-3.5" />
          </button>
          <button onClick={onReset} className="p-1.5 rounded-lg bg-[#131318]/60 border border-white/8 text-[#A1A1AA] hover:text-white hover:bg-white/8 transition-all" title="Reset view">
            <Crosshair className="h-3.5 w-3.5" />
          </button>
          <button onClick={onToggleLegend} className={`p-1.5 rounded-lg border transition-all ${showLegend ? "bg-white/8 border-white/10 text-white" : "bg-[#131318]/60 border-white/8 text-[#A1A1AA] hover:text-white"}`} title="Toggle legend">
            <Info className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// MINIMAP
// ═══════════════════════════════════════════════════════════════════════

function Minimap({
  cascadeNodes, dimensions, viewport, selectedNode,
}: {
  cascadeNodes: CascadeNode[];
  dimensions: { width: number; height: number };
  viewport: { x: number; y: number; zoom: number; containerW: number; containerH: number };
  selectedNode: string | null;
}) {
  const MM_W = 160;
  const MM_H = 100;
  const scaleX = MM_W / dimensions.width;
  const scaleY = MM_H / dimensions.height;
  const scale = Math.min(scaleX, scaleY);

  return (
    <div className="bg-[#0d0d12]/90 backdrop-blur-sm border border-white/8/60 rounded-xl overflow-hidden shadow-xl" style={{ width: MM_W + 8, padding: 4 }}>
      <svg width={MM_W} height={MM_H} className="block">
        <rect width={MM_W} height={MM_H} fill="#09090B" rx={8} />
        {cascadeNodes.map((node) => {
          const colors = getStatusColor(node.status);
          const x = node.position.x * scale;
          const y = node.position.y * scale;
          return (
            <circle
              key={node.id}
              cx={x} cy={y} r={node.id === selectedNode ? 4 : 2.5}
              fill={colors.main}
              opacity={node.id === selectedNode ? 1 : 0.6}
            />
          );
        })}
        <rect
          x={(-viewport.x / viewport.zoom) * scale}
          y={(-viewport.y / viewport.zoom) * scale}
          width={(viewport.containerW / viewport.zoom) * scale}
          height={(viewport.containerH / viewport.zoom) * scale}
          fill="rgba(59,130,246,0.08)"
          stroke="#3b82f6"
          strokeWidth="1"
          rx={2}
        />
      </svg>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// MAIN COMPONENT
// ═══════════════════════════════════════════════════════════════════════

export default function InfrastructureGraph({
  nodes,
  rawCVEData,
  selectedNode,
  onNodeSelect,
  onMitigate,
  onNodesUpdate,
}: InfrastructureGraphProps) {
  const [activeLevel, setActiveLevel] = useState(0);
  const [flowingEdges, setFlowingEdges] = useState<Set<string>>(new Set());
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [showMitigationModal, setShowMitigationModal] = useState(false);
  const [mitigatingNodeId, setMitigatingNodeId] = useState<string | null>(null);
  const [mitigatedNodes, setMitigatedNodes] = useState<Set<string>>(new Set());
  const [copiedCVE, setCopiedCVE] = useState(false);

  const [graphMode, setGraphMode] = useState<GraphMode>("cascade");
  const [filters, setFilters] = useState<GraphFilters>({
    severity: new Set(),
    exploitOnly: false,
    patchableOnly: false,
    phase: new Set(),
    minCvss: 0,
  });
  const [search, setSearch] = useState("");
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [panStart, setPanStart] = useState({ x: 0, y: 0 });
  const [showLegend, setShowLegend] = useState(true);
  const [showMinimap, setShowMinimap] = useState(true);

  const containerRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  const processedNodes = useMemo(() => {
    if (rawCVEData && rawCVEData.length > 0) return transformCVEsToNodes(rawCVEData);
    return nodes;
  }, [rawCVEData, nodes]);

  const safeNodes = useMemo(() => {
    if (!processedNodes || !Array.isArray(processedNodes)) return [];
    return processedNodes.filter((n) => n && typeof n === "object" && n.id && n.name);
  }, [processedNodes]);

  const { cascadeNodes, edges, dimensions, maxLevel, phaseLabels } = useMemo(
    () => buildCascadeLayout(safeNodes, mitigatedNodes, graphMode, filters),
    [safeNodes, mitigatedNodes, graphMode, filters]
  );

  const searchMatchIds = useMemo(() => {
    if (!search.trim()) return new Set<string>();
    const q = search.toLowerCase();
    return new Set(
      cascadeNodes
        .filter((n) =>
          n.name.toLowerCase().includes(q) ||
          n.cve_id?.toLowerCase().includes(q) ||
          n.description?.toLowerCase().includes(q) ||
          n.affected_vendors?.some((v) => v.toLowerCase().includes(q)) ||
          n.affected_products?.some((p) => p.toLowerCase().includes(q))
        )
        .map((n) => n.id)
    );
  }, [search, cascadeNodes]);

  useEffect(() => {
    if (cascadeNodes.length === 0) return;
    const interval = setInterval(() => {
      setActiveLevel((prev) => {
        const next = prev >= maxLevel ? 0 : prev + 1;
        const newFlowing = new Set<string>();
        edges.forEach((edge) => {
          const sourceNode = cascadeNodes.find((n) => n.id === edge.source);
          if (sourceNode && sourceNode.level === next - 1) newFlowing.add(edge.id);
        });
        setFlowingEdges(newFlowing);
        return next;
      });
    }, 1800);
    return () => clearInterval(interval);
  }, [cascadeNodes, edges, maxLevel]);

  // ═══ Pan & Zoom — FIX: left mouse button always pans (no alt key required) ═══
  const handleZoom = useCallback((delta: number) => {
    setZoom((prev) => Math.min(3, Math.max(0.2, prev + delta)));
  }, []);

  const handleFitToScreen = useCallback(() => {
    if (!containerRef.current || dimensions.width === 0) return;
    const cw = containerRef.current.clientWidth;
    const ch = containerRef.current.clientHeight;
    const fitZoom = Math.min(cw / dimensions.width, ch / dimensions.height, 1) * 0.9;
    setZoom(fitZoom);
    setPan({ x: (cw - dimensions.width * fitZoom) / 2, y: (ch - dimensions.height * fitZoom) / 2 });
  }, [dimensions]);

  const handleReset = useCallback(() => { setZoom(1); setPan({ x: 0, y: 0 }); }, []);

  // FIX: Pan on left button drag when NOT clicking a node (handled by stopPropagation on nodes)
  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    // Left button drag to pan; middle button also works
    if (e.button !== 0 && e.button !== 1) return;
    setIsPanning(true);
    setPanStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    e.preventDefault();
  }, [pan]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!isPanning) return;
    setPan({ x: e.clientX - panStart.x, y: e.clientY - panStart.y });
  }, [isPanning, panStart]);

  const handleMouseUp = useCallback(() => setIsPanning(false), []);

  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    // Zoom toward cursor position
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;
    const delta = -e.deltaY * 0.001;
    const newZoom = Math.min(3, Math.max(0.2, zoom + delta));
    const zoomRatio = newZoom / zoom;
    setPan((prev) => ({
      x: mouseX - zoomRatio * (mouseX - prev.x),
      y: mouseY - zoomRatio * (mouseY - prev.y),
    }));
    setZoom(newZoom);
  }, [zoom]);

  const handleNodeClick = useCallback((e: React.MouseEvent, nodeId: string, isSelected: boolean) => {
    e.stopPropagation(); // prevent pan from triggering on node click
    if (!isPanning) {
      onNodeSelect(isSelected ? null : nodeId);
    }
  }, [isPanning, onNodeSelect]);

  const handleStartMitigation = useCallback((nodeId: string) => {
    setMitigatingNodeId(nodeId);
    setShowMitigationModal(true);
  }, []);

  const handleMitigationComplete = useCallback((nodeId: string, actionId: string) => {
    setMitigatedNodes((prev) => new Set([...prev, nodeId]));
    if (onMitigate) onMitigate(nodeId, actionId);
    if (onNodesUpdate) {
      const updatedNodes = safeNodes.map((n) =>
        n.id === nodeId ? { ...n, status: "mitigated" as const, risk: Math.max(5, (n.risk || 0) * 0.1) } : n
      );
      onNodesUpdate(updatedNodes);
    }
  }, [onMitigate, onNodesUpdate, safeNodes]);

  const handleCloseMitigationModal = useCallback(() => {
    setShowMitigationModal(false);
    setMitigatingNodeId(null);
  }, []);

  const handleCopyCVE = useCallback((cveId: string) => {
    navigator.clipboard.writeText(cveId);
    setCopiedCVE(true);
    setTimeout(() => setCopiedCVE(false), 2000);
  }, []);

  const selectedData = useMemo(() => cascadeNodes.find((n) => n.id === selectedNode) || null, [cascadeNodes, selectedNode]);
  const mitigatingNode = useMemo(() => cascadeNodes.find((n) => n.id === mitigatingNodeId) || null, [cascadeNodes, mitigatingNodeId]);

  const stats = useMemo(() => ({
    total: safeNodes.length,
    vendors: safeNodes.filter((n) => n.type === "vendor").length,
    products: safeNodes.filter((n) => n.type === "product").length,
    cves: safeNodes.filter((n) => n.type === "vulnerability").length,
    critical: cascadeNodes.filter((n) => n.severity === "CRITICAL" && !mitigatedNodes.has(n.id)).length,
    high: cascadeNodes.filter((n) => n.severity === "HIGH" && !mitigatedNodes.has(n.id)).length,
    exploited: cascadeNodes.filter((n) => n.status === "exploited").length,
    exploitable: cascadeNodes.filter((n) => n.exploit_available && !mitigatedNodes.has(n.id)).length,
    mitigated: mitigatedNodes.size,
    cascadeChains: new Set(edges.filter((e) => e.edgeType === "cwe_chain").map((e) => e.source)).size,
    visible: cascadeNodes.length,
  }), [safeNodes, cascadeNodes, mitigatedNodes, edges]);

  const getPath = useCallback((edge: Edge) => {
    const sx = edge.sourcePos.x + NODE_SIZE / 2 + 10;
    const sy = edge.sourcePos.y;
    const tx = edge.targetPos.x - NODE_SIZE / 2 - 10;
    const ty = edge.targetPos.y;
    const mx = (sx + tx) / 2;
    return `M ${sx} ${sy} C ${mx} ${sy}, ${mx} ${ty}, ${tx} ${ty}`;
  }, []);

  const getEdgeColor = useCallback((edge: Edge) => {
    const isMitigatedEdge = mitigatedNodes.has(edge.source) || mitigatedNodes.has(edge.target);
    if (isMitigatedEdge) return "#06B6D4";

    // ── Confirmation-based edge coloring ──────────────────────────
    // This makes the graph HONEST about what it knows vs infers.
    //
    // 🟢 Green  = confirmed chain (both CVEs on same real asset)
    // 🟣 Indigo = high inferred (CWE chain relationship proven)
    // 🟡 Amber  = inferred (same vendor + exploit available)
    // ⚫ Grey   = weak (heuristic / phase order only)
    switch (edge.edgeConfirmation) {
      case "confirmed":     return "#22C55E"; // green  = asset-confirmed
      case "high_inferred": return "#6366F1"; // indigo = CWE-proven
      case "inferred":      return "#F59E0B"; // amber  = probable
      case "weak":          return "#52525B"; // grey   = heuristic
      default: break;
    }
    // ─────────────────────────────────────────────────────────────

    // Fallback: original type-based coloring for non-CVE edges
    switch (edge.edgeType) {
      case "cwe_chain":    return "#6366F1";
      case "exploit_path": return "#EF4444";
      case "vendor":       return "#3b82f6";
      case "product":      return "#8B5CF6";
      default:
        return edge.risk >= 80 ? "#EF4444"
             : edge.risk >= 60 ? "#F59E0B"
             : "#52525B";
    }
  }, [mitigatedNodes]);

  if (safeNodes.length === 0) {
    return (
      <div className="w-full h-full bg-[#09090B] flex items-center justify-center overflow-hidden relative">
        <div className="absolute inset-0 opacity-30">
          <svg width="100%" height="100%">
            <defs>
              <pattern id="emptyGrid" width="60" height="60" patternUnits="userSpaceOnUse">
                <path d="M 60 0 L 0 0 0 60" fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="0.5" />
              </pattern>
            </defs>
            <rect width="100%" height="100%" fill="url(#emptyGrid)" />
          </svg>
        </div>
        {[...Array(15)].map((_, i) => (
          <motion.div key={i} className="absolute w-1 h-1 bg-[#6366F1]/40 rounded-full"
            style={{ left: `${10 + Math.random() * 80}%`, top: `${10 + Math.random() * 80}%` }}
            animate={{ y: [0, -20, 0], opacity: [0.3, 0.8, 0.3], scale: [1, 1.5, 1] }}
            transition={{ duration: 3 + Math.random() * 2, repeat: Infinity, delay: Math.random() * 2 }}
          />
        ))}
        <div className="relative z-10 text-center px-8">
          <motion.div initial={{ scale: 0.8, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} transition={{ duration: 0.5 }}>
            <div className="relative inline-block mb-8">
              <motion.div className="absolute inset-0 bg-gradient-to-r from-[#EF4444]/30 to-[#F59E0B]/30 blur-3xl rounded-full"
                animate={{ scale: [1, 1.2, 1], opacity: [0.4, 0.6, 0.4] }} transition={{ duration: 4, repeat: Infinity }} />
              <div className="relative p-8 rounded-3xl bg-[#0d0d12]/60 border border-white/8 backdrop-blur-sm">
                <GitBranch className="h-20 w-20 text-[#52525B] mx-auto" />
              </div>
            </div>
          </motion.div>
          <motion.h2 className="text-3xl font-bold text-white mb-3" initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.2 }}>
            CVE Cascade Flow
          </motion.h2>
          <motion.p className="text-[#A1A1AA] max-w-md mx-auto mb-10" initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.3 }}>
            Visualize how vulnerabilities chain together across vendors, products, and CWE kill chain phases
          </motion.p>
          <motion.div className="flex items-center justify-center gap-3 flex-wrap" initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.4 }}>
            {Object.entries(PHASE_COLORS).filter(([k]) => k !== "unknown").map(([key, val], i) => (
              <React.Fragment key={key}>
                {i > 0 && <ArrowRight className="h-4 w-4 text-[#52525B]" />}
                <div className="flex items-center gap-2 px-3 py-2 rounded-xl border" style={{ backgroundColor: val.bg, borderColor: `${val.main}50` }}>
                  <span className="text-xs font-medium" style={{ color: val.main }}>{val.label}</span>
                </div>
              </React.Fragment>
            ))}
          </motion.div>
          <motion.div className="mt-10 flex items-center justify-center gap-2 text-sm text-[#52525B]" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.6 }}>
            <Radio className="h-4 w-4 text-[#EF4444] animate-pulse" />
            <span>Waiting for CVE scan data...</span>
          </motion.div>
        </div>
      </div>
    );
  }

  return (
    <>
      <div className="w-full h-full bg-[#09090B] flex flex-col overflow-hidden relative">

        {/* Header */}
        <div className="flex-shrink-0 px-6 py-3.5 border-b border-white/5 bg-[#09090B]/80 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="p-2 rounded-xl bg-gradient-to-br from-[#EF4444]/20 to-[#F59E0B]/20 border border-[#EF4444]/20">
                <Activity className="h-5 w-5 text-[#F87171]" />
              </div>
              <div>
                <h1 className="text-lg font-bold text-white">CVE Cascade Graph</h1>
                <p className="text-xs text-[#52525B]">
                  {stats.visible}/{stats.cves} CVEs • {stats.vendors} Vendors • {stats.products} Products • {stats.cascadeChains} Chain Paths
                </p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="hidden lg:flex items-center gap-3">
                {[
                  { label: "Critical", value: stats.critical, color: "#EF4444" },
                  { label: "Exploitable", value: stats.exploitable, color: "#6366F1" },
                  { label: "High", value: stats.high, color: "#F59E0B" },
                  { label: "Mitigated", value: stats.mitigated, color: "#06B6D4" },
                ].map(({ label, value, color }) => (
                  <div key={label} className="flex items-center gap-1.5">
                    <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
                    <span className="text-xs text-[#A1A1AA]">
                      <span className="font-bold text-white">{value}</span> {label}
                    </span>
                  </div>
                ))}
              </div>
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#EF4444]/10 border border-[#EF4444]/20">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500" />
                </span>
                <span className="text-xs font-medium text-[#F87171]">LIVE</span>
              </div>
            </div>
          </div>
        </div>

        {/* Controls */}
        <GraphControls
          zoom={zoom}
          onZoom={handleZoom}
          onReset={handleReset}
          onFitToScreen={handleFitToScreen}
          mode={graphMode}
          onModeChange={setGraphMode}
          filters={filters}
          onFiltersChange={setFilters}
          search={search}
          onSearchChange={setSearch}
          showLegend={showLegend}
          onToggleLegend={() => setShowLegend(!showLegend)}
          stats={stats}
        />

        {/* Graph + Panel row */}
        <div className="flex flex-1 overflow-hidden">

          {/* Graph Area — scroll + pan/zoom both supported */}
          <div
            className="flex-1 relative bg-[#09090B] overflow-auto
              [&::-webkit-scrollbar]:w-2
              [&::-webkit-scrollbar]:h-2
              [&::-webkit-scrollbar-track]:bg-[#09090B]
              [&::-webkit-scrollbar-thumb]:bg-white/10
              [&::-webkit-scrollbar-thumb]:rounded-full
              [&::-webkit-scrollbar-thumb:hover]:bg-white/20
              [&::-webkit-scrollbar-corner]:bg-[#09090B]"
          >
          <div
            ref={containerRef}
            className="relative bg-[#09090B]"
            style={{
              cursor: "default",
              width: dimensions.width * zoom + Math.abs(pan.x) + 200,
              height: dimensions.height * zoom + Math.abs(pan.y) + 200,
              minWidth: "100%",
              minHeight: "100%",
            }}

            onWheel={handleWheel}
          >
            <svg
              ref={svgRef}
              width={dimensions.width}
              height={dimensions.height}
              style={{
                transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
                transformOrigin: "0 0",
                transition: isPanning ? "none" : "transform 0.05s ease",
                display: "block",
                userSelect: "none",
              }}
            >
              <defs>
                <pattern id="cascadeGrid" width="40" height="40" patternUnits="userSpaceOnUse">
                  <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="0.5" />
                </pattern>
                <filter id="nodeGlow" x="-100%" y="-100%" width="300%" height="300%">
                  <feGaussianBlur stdDeviation="8" result="blur" />
                  <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
                </filter>
                <filter id="nodeShadow" x="-50%" y="-50%" width="200%" height="200%">
                  <feDropShadow dx="0" dy="4" stdDeviation="6" floodOpacity="0.4" floodColor="#000" />
                </filter>
                <marker id="arrowCascade" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#A1A1AA" />
                </marker>
                <marker id="arrowChain" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#6366F1" />
                </marker>
                <marker id="arrowExploit" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#EF4444" />
                </marker>
              </defs>

              <rect width={dimensions.width} height={dimensions.height} fill="#09090B" />
              <rect width={dimensions.width} height={dimensions.height} fill="url(#cascadeGrid)" opacity="0.6" />

              {/* Phase column guides */}
              {phaseLabels.map((pl, i) => {
                const phaseInfo = PHASE_COLORS[pl.phase] || PHASE_COLORS.unknown;
                return (
                  <g key={`phase-${i}`}>
                    <line x1={pl.x} y1={50} x2={pl.x} y2={dimensions.height - 20}
                      stroke={phaseInfo.main} strokeWidth="1" strokeDasharray="6 6" opacity="0.2" />
                    <g transform={`translate(${pl.x}, 35)`}>
                      <rect x="-60" y="-14" width="120" height="28" rx="14" fill={phaseInfo.bg} stroke={phaseInfo.main} strokeWidth="1" opacity="0.8" />
                      <text textAnchor="middle" dominantBaseline="middle" fill={phaseInfo.main} fontSize="10" fontWeight="600">
                        {phaseInfo.label}
                      </text>
                    </g>
                  </g>
                );
              })}

              <text x={dimensions.width - 20} y={dimensions.height - 10} textAnchor="end" fill="rgba(255,255,255,0.04)" fontSize="11" fontWeight="600">
                {graphMode === "cascade" ? "KILL CHAIN CASCADE" : graphMode === "blast_radius" ? "BLAST RADIUS" : "INFRASTRUCTURE"}
              </text>

              {/* Edges */}
              {edges.map((edge) => {
                const path = getPath(edge);
                const isFlowing = flowingEdges.has(edge.id);
                const isConnectedToSelected = selectedNode === edge.source || selectedNode === edge.target;
                const isConnectedToHovered = hoveredNode === edge.source || hoveredNode === edge.target;
                const isHighlighted = isConnectedToSelected || isConnectedToHovered;
                const isMitigatedEdge = mitigatedNodes.has(edge.source) || mitigatedNodes.has(edge.target);
                const edgeColor = getEdgeColor(edge);

                const isDimmed = search.trim() !== "" && searchMatchIds.size > 0 &&
                  !searchMatchIds.has(edge.source) && !searchMatchIds.has(edge.target);

                return (
                  <g key={edge.id} opacity={isDimmed ? 0.07 : 1}>
                    {(isFlowing || isHighlighted) && !isMitigatedEdge && (
                      <motion.path d={path} fill="none" stroke={edgeColor} strokeWidth="10" opacity="0.15" filter="url(#nodeGlow)"
                        initial={{ pathLength: 0 }} animate={{ pathLength: 1 }} transition={{ duration: 0.6 }} />
                    )}
                    <motion.path
                      d={path} fill="none"
                      stroke={isHighlighted ? edgeColor : isMitigatedEdge ? "#06B6D4" : edgeColor}
                      strokeWidth={isHighlighted ? 3 : edge.edgeType === "cwe_chain" ? 2.5 : 1.5}
                      strokeLinecap="round"
                      strokeDasharray={isMitigatedEdge ? "8 4" : edge.edgeType === "exploit_path" ? "4 2" : "none"}
                      opacity={isHighlighted ? 1 : isMitigatedEdge ? 0.3 : 0.4}
                      initial={{ pathLength: 0 }} animate={{ pathLength: 1 }} transition={{ duration: 0.8, delay: 0.1 }}
                      markerEnd={edge.edgeType === "cwe_chain" ? "url(#arrowChain)" : edge.edgeType === "exploit_path" ? "url(#arrowExploit)" : "url(#arrowCascade)"}
                    />
                    {(isFlowing || isHighlighted) && !isMitigatedEdge && (
                      <>
                        <motion.circle r="5" fill={edgeColor} filter="url(#nodeGlow)"
                          initial={{ offsetDistance: "0%" }} animate={{ offsetDistance: "100%" }}
                          transition={{ duration: 1.2, repeat: Infinity, ease: "linear" }}
                          style={{ offsetPath: `path('${path}')` } as any} />
                        <motion.circle r="2.5" fill="white"
                          initial={{ offsetDistance: "0%" }} animate={{ offsetDistance: "100%" }}
                          transition={{ duration: 1.2, repeat: Infinity, ease: "linear" }}
                          style={{ offsetPath: `path('${path}')` } as any} />
                      </>
                    )}
                    {edge.edgeType === "cwe_chain" && isHighlighted && (
                      <text x={(edge.sourcePos.x + edge.targetPos.x) / 2} y={(edge.sourcePos.y + edge.targetPos.y) / 2 - 8}
                        textAnchor="middle" fill="#6366F1" fontSize="9" fontWeight="bold">CWE CHAIN</text>
                    )}
                    {edge.edgeType === "cwe_chain" && edge.confidence && isHighlighted && (
                      <text x={(edge.sourcePos.x + edge.targetPos.x) / 2} y={(edge.sourcePos.y + edge.targetPos.y) / 2 + 6}
                        textAnchor="middle" fill="#6366F170" fontSize="8">
                        {`${edge.confidence}% conf.`}
                      </text>
                    )}
                  </g>
                );
              })}

              {/* Nodes */}
              {cascadeNodes.map((node, index) => {
                const isMitigated = mitigatedNodes.has(node.id);
                const effectiveStatus = isMitigated ? "mitigated" : node.status;
                const colors = getStatusColor(effectiveStatus);
                const phaseColors = node.cascadePhase ? PHASE_COLORS[node.cascadePhase] || PHASE_COLORS.unknown : PHASE_COLORS.unknown;
                const isSelected = selectedNode === node.id;
                const isHovered = hoveredNode === node.id;
                const isActive = node.level <= activeLevel;
                const isOrigin = node.level === 0;

                const isSearchMatch = searchMatchIds.size > 0 && searchMatchIds.has(node.id);
                const isSearchDimmed = search.trim() !== "" && searchMatchIds.size > 0 && !isSearchMatch;

                return (
                  <motion.g
                    key={node.id}
                    initial={{ scale: 0, opacity: 0 }}
                    animate={{ scale: 1, opacity: isSearchDimmed ? 0.15 : 1 }}
                    transition={{ delay: index * 0.02, type: "spring", stiffness: 260, damping: 20 }}
                    onMouseEnter={() => setHoveredNode(node.id)}
                    onMouseLeave={() => setHoveredNode(null)}
                    onClick={(e) => handleNodeClick(e as unknown as React.MouseEvent, node.id, isSelected)}
                    style={{ cursor: "pointer" }}
                  >
                    {!isMitigated && (node.status === "exploited" || node.status === "critical" || isOrigin) && (
                      <>
                        <motion.circle cx={node.position.x} cy={node.position.y} r={NODE_SIZE / 2 + 15}
                          fill="none" stroke={colors.main} strokeWidth="2"
                          initial={{ scale: 1, opacity: 0.5 }} animate={{ scale: 1.6, opacity: 0 }} transition={{ duration: 2, repeat: Infinity }} />
                        <motion.circle cx={node.position.x} cy={node.position.y} r={NODE_SIZE / 2 + 8}
                          fill="none" stroke={colors.main} strokeWidth="1"
                          initial={{ scale: 1, opacity: 0.3 }} animate={{ scale: 1.4, opacity: 0 }} transition={{ duration: 2, repeat: Infinity, delay: 0.4 }} />
                      </>
                    )}

                    {isMitigated && (
                      <motion.circle cx={node.position.x} cy={node.position.y} r={NODE_SIZE / 2 + 8}
                        fill="none" stroke="#06B6D4" strokeWidth="2" strokeDasharray="4 2"
                        initial={{ rotate: 0 }} animate={{ rotate: 360 }} transition={{ duration: 20, repeat: Infinity, ease: "linear" }} />
                    )}

                    {isSearchMatch && (
                      <motion.circle cx={node.position.x} cy={node.position.y} r={NODE_SIZE / 2 + 12}
                        fill="none" stroke="#fbbf24" strokeWidth="2" strokeDasharray="4 2"
                        initial={{ rotate: 0 }} animate={{ rotate: -360 }} transition={{ duration: 6, repeat: Infinity, ease: "linear" }} />
                    )}

                    {isSelected && (
                      <motion.circle cx={node.position.x} cy={node.position.y} r={NODE_SIZE / 2 + 6}
                        fill="none" stroke="#3b82f6" strokeWidth="3" strokeDasharray="6 4"
                        initial={{ rotate: 0 }} animate={{ rotate: 360 }} transition={{ duration: 8, repeat: Infinity, ease: "linear" }} />
                    )}

                    {node.type === "vulnerability" && !isMitigated && (
                      <circle cx={node.position.x} cy={node.position.y} r={NODE_SIZE / 2 + 2}
                        fill="none" stroke={phaseColors.main} strokeWidth="1.5" opacity="0.4" />
                    )}

                    <circle cx={node.position.x} cy={node.position.y} r={NODE_SIZE / 2 + 3}
                      fill={colors.main} opacity={isHovered || isSelected || isSearchMatch ? 0.35 : isActive ? 0.15 : 0.08}
                      filter="url(#nodeGlow)" />

                    <motion.circle cx={node.position.x} cy={node.position.y} r={NODE_SIZE / 2}
                      fill="#09090B" stroke={colors.main} strokeWidth={isSelected || isHovered ? 4 : 3}
                      filter="url(#nodeShadow)" whileHover={{ scale: 1.08 }} transition={{ duration: 0.15 }} />

                    <circle cx={node.position.x} cy={node.position.y} r={NODE_SIZE / 2 - 5}
                      fill="none" stroke={colors.bg} strokeWidth="6" />
                    <motion.circle cx={node.position.x} cy={node.position.y} r={NODE_SIZE / 2 - 5}
                      fill="none" stroke={colors.main} strokeWidth="3" strokeLinecap="round"
                      strokeDasharray={`${((isMitigated ? 100 - (node.risk || 0) : node.risk || 0) / 100) * Math.PI * (NODE_SIZE - 10)} ${Math.PI * (NODE_SIZE - 10)}`}
                      transform={`rotate(-90 ${node.position.x} ${node.position.y})`}
                      initial={{ strokeDasharray: `0 ${Math.PI * (NODE_SIZE - 10)}` }}
                      animate={{ strokeDasharray: `${((isMitigated ? 100 - (node.risk || 0) : node.risk || 0) / 100) * Math.PI * (NODE_SIZE - 10)} ${Math.PI * (NODE_SIZE - 10)}` }}
                      transition={{ duration: 1, delay: index * 0.03 }} />

                    <foreignObject x={node.position.x - 12} y={node.position.y - 12} width="24" height="24">
                      <div className="flex items-center justify-center w-full h-full" style={{ color: colors.main }}>
                        {isMitigated ? <ShieldCheck className="h-[22px] w-[22px]" /> : <NodeIcon type={node.type} severity={node.severity} size={22} />}
                      </div>
                    </foreignObject>

                    {node.cvss_score != null && !isMitigated && node.type === "vulnerability" && (
                      <g>
                        <circle cx={node.position.x + NODE_SIZE / 2 - 6} cy={node.position.y - NODE_SIZE / 2 + 6} r="13"
                          fill="#09090B" stroke={getSeverityColor(node.severity)} strokeWidth="2" />
                        <text x={node.position.x + NODE_SIZE / 2 - 6} y={node.position.y - NODE_SIZE / 2 + 10}
                          textAnchor="middle" fill={getSeverityColor(node.severity)} fontSize="9" fontWeight="bold">
                          {node.cvss_score.toFixed(1)}
                        </text>
                      </g>
                    )}

                    {isMitigated && (
                      <g>
                        <circle cx={node.position.x + NODE_SIZE / 2 - 6} cy={node.position.y - NODE_SIZE / 2 + 6} r="13" fill="#06B6D4" />
                        <foreignObject x={node.position.x + NODE_SIZE / 2 - 13} y={node.position.y - NODE_SIZE / 2 - 1} width="14" height="14">
                          <Check className="h-3.5 w-3.5 text-white" />
                        </foreignObject>
                      </g>
                    )}

                    {node.exploit_available && !isMitigated && (
                      <g>
                        <motion.circle cx={node.position.x - NODE_SIZE / 2 + 6} cy={node.position.y - NODE_SIZE / 2 + 6} r="11" fill="#EF4444"
                          animate={{ scale: [1, 1.15, 1] }} transition={{ duration: 1.5, repeat: Infinity }} />
                        <foreignObject x={node.position.x - NODE_SIZE / 2} y={node.position.y - NODE_SIZE / 2} width="12" height="12">
                          <Skull className="h-3 w-3 text-white" />
                        </foreignObject>
                      </g>
                    )}

                    {node.patch_available && !isMitigated && (
                      <g>
                        <circle cx={node.position.x + NODE_SIZE / 2 - 6} cy={node.position.y + NODE_SIZE / 2 - 6} r="11" fill="#059669" />
                        <foreignObject x={node.position.x + NODE_SIZE / 2 - 12} y={node.position.y + NODE_SIZE / 2 - 12} width="12" height="12">
                          <CheckCircle className="h-3 w-3 text-white" />
                        </foreignObject>
                      </g>
                    )}

                    {node.children && node.children.length > 2 && !isMitigated && (
                      <g>
                        <circle cx={node.position.x - NODE_SIZE / 2 + 6} cy={node.position.y + NODE_SIZE / 2 - 6} r="11" fill="#7c3aed" />
                        <text x={node.position.x - NODE_SIZE / 2 + 6} y={node.position.y + NODE_SIZE / 2 - 2}
                          textAnchor="middle" fill="white" fontSize="9" fontWeight="bold">{node.children.length}</text>
                      </g>
                    )}

                    <text x={node.position.x} y={node.position.y + NODE_SIZE / 2 + 18}
                      textAnchor="middle" fill="#e2e8f0" fontSize="10" fontWeight="600">
                      {node.name.length > 18 ? node.name.slice(0, 18) + "…" : node.name}
                    </text>

                    <text x={node.position.x} y={node.position.y + NODE_SIZE / 2 + 31}
                      textAnchor="middle" fill={colors.main} fontSize="9" fontWeight="bold">
                      {isMitigated ? "✓ Mitigated"
                        : node.type === "vulnerability" ? `${Math.round(node.risk || 0)}% Risk`
                        : node.type === "vendor" ? `${node.connections?.length || 0} products`
                        : `${node.connections?.length || 0} CVEs`}
                    </text>
                  </motion.g>
                );
              })}
            </svg>

            {/* Overlays */}
            <div className="absolute bottom-4 left-4 flex flex-col gap-2 pointer-events-none">
              {showMinimap && cascadeNodes.length > 0 && (
                <div className="pointer-events-auto">
                  <Minimap
                    cascadeNodes={cascadeNodes}
                    dimensions={dimensions}
                    viewport={{ x: pan.x, y: pan.y, zoom, containerW: containerRef.current?.clientWidth || 800, containerH: containerRef.current?.clientHeight || 600 }}
                    selectedNode={selectedNode}
                  />
                </div>
              )}
            </div>

            {/* Legend overlay */}
            <AnimatePresence>
              {showLegend && (
                <motion.div
                  initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 20 }}
                  className={`absolute top-4 z-50 pointer-events-auto transition-all duration-300 ${selectedNode ? "right-[380px]" : "right-4"}`}
                >
                  <Legend onClose={() => setShowLegend(false)} />
                </motion.div>
              )}
            </AnimatePresence>

            {/* Pan/zoom hint */}
            <div className="absolute bottom-4 right-4 text-[10px] text-[#3F3F46] pointer-events-none">
              Scroll to pan • Pinch/wheel to zoom
            </div>
          </div>
          </div>

          {/* Side Panel */}
          <AnimatePresence>
            {selectedNode && selectedData && (
              <motion.div
                initial={{ x: 400, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: 400, opacity: 0 }}
                transition={{ type: "spring", damping: 28, stiffness: 220 }}
                className="w-[360px] h-full bg-[#09090B] border-l border-white/5 overflow-y-auto flex-shrink-0 shadow-[-20px_0_60px_-20px_rgba(0,0,0,0.5)]"
              >
                {/* ── STICKY HEADER ──────────────────────────────── */}
                <div className="sticky top-0 z-10 bg-[#09090B]/95 backdrop-blur-xl border-b border-white/5 p-5">
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <motion.div
                        className="p-2.5 rounded-xl ring-1 ring-white/10"
                        style={{
                          backgroundColor: getStatusColor(mitigatedNodes.has(selectedData.id) ? "mitigated" : selectedData.status).bg,
                          border: `2px solid ${getStatusColor(mitigatedNodes.has(selectedData.id) ? "mitigated" : selectedData.status).main}`,
                          color: getStatusColor(mitigatedNodes.has(selectedData.id) ? "mitigated" : selectedData.status).main,
                        }}
                        initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: "spring" }}
                      >
                        {mitigatedNodes.has(selectedData.id) ? <ShieldCheck className="h-6 w-6" /> : <NodeIcon type={selectedData.type} severity={selectedData.severity} size={24} />}
                      </motion.div>
                      <div>
                        <h2 className="text-base font-semibold tracking-tight text-[#FAFAFA]">{selectedData.name}</h2>
                        <p className="text-xs text-[#52525B] capitalize mt-0.5">{selectedData.type} • Level {selectedData.level}</p>
                      </div>
                    </div>
                    <button onClick={() => onNodeSelect(null)} className="p-2 rounded-lg bg-white/3 hover:bg-white/8 text-[#52525B] hover:text-white border border-white/5 hover:border-white/10 transition-all duration-200">
                      <X className="h-4 w-4" />
                    </button>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {mitigatedNodes.has(selectedData.id) ? (
                      <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[#06B6D4]/10 text-[#22D3EE] text-xs font-semibold border border-[#06B6D4]/20">
                        <ShieldCheck className="h-3 w-3" /> Mitigated
                      </span>
                    ) : (
                      <>
                        {selectedData.severity && (
                          <span className="px-2.5 py-1 rounded-full text-xs font-semibold"
                            style={{ backgroundColor: `${getSeverityColor(selectedData.severity)}18`, color: getSeverityColor(selectedData.severity), border: `1px solid ${getSeverityColor(selectedData.severity)}30` }}>
                            {selectedData.severity}
                          </span>
                        )}
                        <span className="px-2.5 py-1 rounded-full text-xs font-semibold capitalize"
                          style={{ backgroundColor: getStatusColor(selectedData.status).bg, color: getStatusColor(selectedData.status).main, border: `1px solid ${getStatusColor(selectedData.status).main}30` }}>
                          {selectedData.status}
                        </span>
                        {selectedData.exploit_available && (
                          <span className="flex items-center gap-1 px-2.5 py-1 rounded-full bg-[#EF4444]/10 text-[#F87171] text-xs font-semibold border border-[#EF4444]/20">
                            <Skull className="h-3 w-3" /> Exploitable
                          </span>
                        )}
                        {selectedData.patch_available && (
                          <span className="flex items-center gap-1 px-2.5 py-1 rounded-full bg-[#22C55E]/10 text-[#4ADE80] text-xs font-semibold border border-[#22C55E]/20">
                            <CheckCircle className="h-3 w-3" /> Patch Ready
                          </span>
                        )}
                      </>
                    )}
                    {selectedData.cascadePhase && (
                      <span className="px-2.5 py-1 rounded-full text-xs font-semibold"
                        style={{ backgroundColor: (PHASE_COLORS[selectedData.cascadePhase] || PHASE_COLORS.unknown).bg, color: (PHASE_COLORS[selectedData.cascadePhase] || PHASE_COLORS.unknown).main, border: `1px solid ${(PHASE_COLORS[selectedData.cascadePhase] || PHASE_COLORS.unknown).main}30` }}>
                        {(PHASE_COLORS[selectedData.cascadePhase] || PHASE_COLORS.unknown).label}
                      </span>
                    )}
                  </div>
                </div>

                {/* ── BODY ───────────────────────────────────────── */}
                <div className="p-5 space-y-4">

                  {/* CVE ID row */}
                  {selectedData.cve_id && (
                    <motion.div className="flex items-center justify-between p-3 rounded-xl bg-white/2 border border-white/6"
                      initial={{ y: 10, opacity: 0 }} animate={{ y: 0, opacity: 1 }}>
                      <code className="text-sm font-mono text-[#F87171]">{selectedData.cve_id}</code>
                      <div className="flex items-center gap-1">
                        <button onClick={() => handleCopyCVE(selectedData.cve_id!)}
                          className="p-1.5 rounded-lg bg-white/3 hover:bg-white/8 text-[#71717A] hover:text-white border border-white/5 transition-all duration-200">
                          {copiedCVE ? <Check className="h-3.5 w-3.5 text-[#4ADE80]" /> : <Copy className="h-3.5 w-3.5" />}
                        </button>
                        <a href={`https://nvd.nist.gov/vuln/detail/${selectedData.cve_id}`} target="_blank" rel="noopener noreferrer"
                          className="p-1.5 rounded-lg bg-white/3 hover:bg-white/8 text-[#71717A] hover:text-white border border-white/5 transition-all duration-200">
                          <ExternalLink className="h-3.5 w-3.5" />
                        </a>
                      </div>
                    </motion.div>
                  )}

                  {/* Description */}
                  {selectedData.description && (
                    <motion.div className="p-4 rounded-xl bg-white/2 border border-white/5"
                      initial={{ y: 10, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.05 }}>
                      <p className="text-xs text-[#71717A] leading-relaxed line-clamp-6">{selectedData.description}</p>
                    </motion.div>
                  )}

                  {/* CVSS Score card */}
                  {selectedData.cvss_score != null && (
                    <motion.div className="relative overflow-hidden p-5 rounded-xl bg-[#0d0d12] border border-white/6 shadow-[0_4px_20px_-6px_rgba(0,0,0,0.4)]"
                      initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.1 }}>
                      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,rgba(99,102,241,0.06),transparent_60%)]" />
                      <div className="relative flex justify-between mb-3">
                        <span className="text-xs font-medium text-[#71717A] uppercase tracking-wide">CVSS Score</span>
                        <span className="text-xs text-[#3F3F46] bg-white/3 px-2 py-0.5 rounded-full border border-white/5">v3.1</span>
                      </div>
                      <div className="relative flex items-baseline gap-2 mb-4">
                        <motion.span className="text-5xl font-bold tracking-tight"
                          style={{ color: mitigatedNodes.has(selectedData.id) ? "#06B6D4" : getSeverityColor(selectedData.severity) }}
                          initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: "spring", delay: 0.2 }}>
                          {mitigatedNodes.has(selectedData.id) ? "0.0" : selectedData.cvss_score.toFixed(1)}
                        </motion.span>
                        <span className="text-[#3F3F46] text-sm">/10</span>
                        {mitigatedNodes.has(selectedData.id) && (
                          <span className="text-xs text-[#22D3EE] ml-1 bg-[#06B6D4]/10 px-2 py-0.5 rounded-full border border-[#06B6D4]/20">was {selectedData.cvss_score.toFixed(1)}</span>
                        )}
                      </div>
                      <div className="relative h-1.5 bg-white/5 rounded-full overflow-hidden ring-1 ring-white/5">
                        <motion.div className="h-full rounded-full"
                          style={{ backgroundColor: mitigatedNodes.has(selectedData.id) ? "#06B6D4" : getSeverityColor(selectedData.severity), boxShadow: `0 0 10px ${mitigatedNodes.has(selectedData.id) ? "#06B6D4" : getSeverityColor(selectedData.severity)}60` }}
                          initial={{ width: `${(selectedData.cvss_score / 10) * 100}%` }}
                          animate={{ width: mitigatedNodes.has(selectedData.id) ? "0%" : `${(selectedData.cvss_score / 10) * 100}%` }}
                          transition={{ duration: 0.8 }} />
                      </div>
                    </motion.div>
                  )}

                  {/* EPSS Score Card */}
                  {selectedData.epss_score != null && (
                    <motion.div
                      className="relative overflow-hidden p-4 rounded-xl bg-[#0d0d12] border border-white/6"
                      initial={{ y: 20, opacity: 0 }}
                      animate={{ y: 0, opacity: 1 }}
                      transition={{ delay: 0.13 }}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <TrendingUp className="h-3.5 w-3.5 text-[#F59E0B]" />
                          <span className="text-xs font-medium text-[#71717A] uppercase tracking-wide">
                            EPSS Score
                          </span>
                        </div>
                        <span className="text-[10px] text-[#3F3F46] bg-white/3 px-2 py-0.5 rounded-full border border-white/5">
                          FIRST.org
                        </span>
                      </div>
                      <div className="flex items-baseline gap-2 mb-1">
                        <span
                          className="text-3xl font-bold"
                          style={{
                            color:
                              (selectedData.epss_score ?? 0) > 0.7 ? "#EF4444"
                              : (selectedData.epss_score ?? 0) > 0.3 ? "#F59E0B"
                              : "#22C55E",
                          }}
                        >
                          {((selectedData.epss_score ?? 0) * 100).toFixed(1)}%
                        </span>
                        <span className="text-xs text-[#52525B]">
                          chance exploited in 30 days
                        </span>
                      </div>
                      {selectedData.epss_percentile != null && (
                        <p className="text-xs text-[#52525B] mb-3">
                          Riskier than{" "}
                          <span className="text-[#A1A1AA] font-medium">
                            {((selectedData.epss_percentile ?? 0) * 100).toFixed(0)}%
                          </span>{" "}
                          of all scored CVEs
                        </p>
                      )}
                      <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
                        <motion.div
                          className="h-full rounded-full"
                          style={{
                            backgroundColor:
                              (selectedData.epss_score ?? 0) > 0.7 ? "#EF4444"
                              : (selectedData.epss_score ?? 0) > 0.3 ? "#F59E0B"
                              : "#22C55E",
                          }}
                          initial={{ width: 0 }}
                          animate={{
                            width: `${(selectedData.epss_score ?? 0) * 100}%`,
                          }}
                          transition={{ duration: 0.8, delay: 0.2 }}
                        />
                      </div>
                      <div className="flex justify-between mt-1.5 text-[10px] text-[#3F3F46]">
                        <span>Low risk</span>
                        <span>High risk</span>
                      </div>
                      {selectedData.cisa_kev && (
                        <div className="mt-3 flex items-center gap-2 px-3 py-2 rounded-lg bg-[#EF4444]/10 border border-[#EF4444]/20">
                          <Skull className="h-3.5 w-3.5 text-[#F87171] flex-shrink-0" />
                          <span className="text-xs font-semibold text-[#F87171]">
                            CISA Known Exploited Vulnerability
                          </span>
                        </div>
                      )}
                    </motion.div>
                  )}

                  {/* Asset Confirmation Badge */}
                  {(selectedData.asset_match_count ?? 0) > 0 && (
                    <motion.div
                      className="flex items-center gap-2 px-3 py-2 rounded-xl bg-[#22C55E]/8 border border-[#22C55E]/20"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: 0.15 }}
                    >
                      <CheckCircle className="h-4 w-4 text-[#4ADE80] flex-shrink-0" />
                      <span className="text-xs text-[#4ADE80] font-medium">
                        Confirmed on {selectedData.asset_match_count} asset
                        {(selectedData.asset_match_count ?? 0) > 1 ? "s" : ""}{" "}
                        in your inventory
                      </span>
                    </motion.div>
                  )}

                  {/* Attack vector grid */}
                  {selectedData.attack_vector && (
                    <motion.div className="grid grid-cols-2 gap-2"
                      initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.15 }}>
                      {[
                        { label: "Vector", value: selectedData.attack_vector, icon: <Target className="h-3.5 w-3.5" /> },
                        { label: "Complexity", value: selectedData.attack_complexity, icon: <Layers className="h-3.5 w-3.5" /> },
                        { label: "Privileges", value: selectedData.privileges_required, icon: <Lock className="h-3.5 w-3.5" /> },
                        { label: "Status", value: selectedData.vuln_status, icon: <Eye className="h-3.5 w-3.5" /> },
                      ].filter((item) => item.value).map((item) => (
                        <div key={item.label} className="p-3 rounded-xl bg-white/2 border border-white/5 hover:border-white/8 transition-colors">
                          <div className="flex items-center gap-1.5 mb-1.5 text-[#3F3F46]">{item.icon}<span className="text-xs uppercase tracking-wide">{item.label}</span></div>
                          <p className="text-xs font-medium text-[#E4E4E7] capitalize">{item.value?.toLowerCase().replace(/_/g, " ")}</p>
                        </div>
                      ))}
                    </motion.div>
                  )}

                  {/* CWE Classifications */}
                  {selectedData.cwe_ids && selectedData.cwe_ids.length > 0 && (
                    <motion.div className="p-4 rounded-xl bg-white/2 border border-white/5"
                      initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.2 }}>
                      <div className="flex items-center gap-2 mb-3">
                        <div className="p-1.5 rounded-lg bg-[#8B5CF6]/10"><Code className="h-3.5 w-3.5 text-[#A78BFA]" /></div>
                        <span className="text-xs font-medium text-[#E4E4E7] uppercase tracking-wide">CWE Classifications</span>
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {selectedData.cwe_ids.map((cwe) => {
                          const cweInfo = CWE_PHASE_MAP[cwe];
                          const phaseColor = cweInfo ? PHASE_COLORS[cweInfo.phase] || PHASE_COLORS.unknown : PHASE_COLORS.unknown;
                          return (
                            <a key={cwe} href={`https://cwe.mitre.org/data/definitions/${cwe.replace("CWE-", "")}.html`}
                              target="_blank" rel="noopener noreferrer"
                              className="group flex items-center gap-1.5 px-2.5 py-1 rounded-full border transition-all duration-200 hover:scale-[1.02]"
                              style={{ backgroundColor: phaseColor.bg, borderColor: `${phaseColor.main}25` }}>
                              <span className="text-xs font-mono font-bold" style={{ color: phaseColor.main }}>{cwe}</span>
                              {cweInfo && <span className="text-xs text-[#52525B] group-hover:text-[#A1A1AA] transition-colors">{cweInfo.label}</span>}
                              <ExternalLink className="h-3 w-3 text-[#3F3F46] group-hover:text-[#A1A1AA] transition-colors" />
                            </a>
                          );
                        })}
                      </div>
                    </motion.div>
                  )}

                  {/* Affected Products */}
                  {selectedData.affected_products && selectedData.affected_products.length > 0 && (
                    <motion.div className="p-4 rounded-xl bg-white/2 border border-white/5"
                      initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.25 }}>
                      <div className="flex items-center gap-2 mb-3">
                        <div className="p-1.5 rounded-lg bg-[#3B82F6]/10"><Server className="h-3.5 w-3.5 text-[#60A5FA]" /></div>
                        <span className="text-xs font-medium text-[#E4E4E7] uppercase tracking-wide">Affected Products</span>
                      </div>
                      <div className="space-y-1.5">
                        {selectedData.affected_products.map((product) => (
                          <div key={product} className="flex items-center gap-2.5 px-3 py-2 rounded-lg bg-[#09090B]/80 border border-white/5">
                            <div className="w-1.5 h-1.5 rounded-full bg-[#3B82F6]/60 flex-shrink-0" />
                            <span className="text-xs text-[#A1A1AA] font-mono truncate">{product}</span>
                          </div>
                        ))}
                      </div>
                    </motion.div>
                  )}

                  {/* Risk + Stability */}
                  <div className="grid grid-cols-2 gap-3">
                    <motion.div className="relative overflow-hidden p-4 rounded-xl bg-[#EF4444]/6 border border-[#EF4444]/15 shadow-[0_0_20px_-8px_rgba(239,68,68,0.15)]"
                      initial={{ x: -20, opacity: 0 }} animate={{ x: 0, opacity: 1 }} transition={{ delay: 0.3 }}>
                      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top_left,rgba(239,68,68,0.08),transparent_60%)]" />
                      <div className="relative flex items-center gap-1.5 mb-2">
                        <AlertTriangle className="h-3.5 w-3.5 text-[#F87171]" />
                        <span className="text-xs text-[#71717A] uppercase tracking-wide">Risk</span>
                      </div>
                      <p className="relative text-2xl font-bold" style={{ color: mitigatedNodes.has(selectedData.id) ? "#06B6D4" : "#EF4444" }}>
                        {mitigatedNodes.has(selectedData.id) ? Math.round((selectedData.risk || 0) * 0.1) : Math.round(selectedData.risk || 0)}%
                      </p>
                    </motion.div>
                    <motion.div className="relative overflow-hidden p-4 rounded-xl bg-[#3B82F6]/6 border border-[#3B82F6]/15 shadow-[0_0_20px_-8px_rgba(59,130,246,0.15)]"
                      initial={{ x: 20, opacity: 0 }} animate={{ x: 0, opacity: 1 }} transition={{ delay: 0.35 }}>
                      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,rgba(59,130,246,0.08),transparent_60%)]" />
                      <div className="relative flex items-center gap-1.5 mb-2">
                        <Activity className="h-3.5 w-3.5 text-[#60A5FA]" />
                        <span className="text-xs text-[#71717A] uppercase tracking-wide">Stability</span>
                      </div>
                      <p className="relative text-2xl font-bold text-[#60A5FA]">
                        {mitigatedNodes.has(selectedData.id) ? "98" : Math.round(selectedData.stability || 0)}%
                      </p>
                    </motion.div>
                  </div>

                  {/* Cascade Position */}
                  <motion.div className="relative overflow-hidden p-4 rounded-xl bg-[#6366F1]/6 border border-[#6366F1]/15"
                    initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.4 }}>
                    <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_bottom_right,rgba(99,102,241,0.08),transparent_60%)]" />
                    <div className="relative flex items-center gap-2 mb-3">
                      <div className="p-1.5 rounded-lg bg-[#6366F1]/10"><GitBranch className="h-3.5 w-3.5 text-[#818CF8]" /></div>
                      <span className="text-xs font-medium text-[#E4E4E7] uppercase tracking-wide">Cascade Position</span>
                    </div>
                    <div className="relative flex items-center gap-3">
                      <span className="text-4xl font-bold text-[#A78BFA] tracking-tight">{selectedData.level}</span>
                      <div>
                        <p className="text-sm font-medium text-[#E4E4E7]">{selectedData.level === 0 ? "Origin Point" : `Level ${selectedData.level}`}</p>
                        <p className="text-xs text-[#52525B] mt-0.5">{selectedData.parents.length} upstream • {selectedData.children.length} downstream</p>
                      </div>
                    </div>
                  </motion.div>

                  {/* Propagated From */}
                  {selectedData.parents && selectedData.parents.length > 0 && (
                    <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.45 }}>
                      <div className="flex items-center gap-2 mb-2">
                        <ChevronRight className="h-3.5 w-3.5 rotate-180 text-[#52525B]" />
                        <span className="text-xs font-medium text-[#52525B] uppercase tracking-wide">Propagated From ({selectedData.parents.length})</span>
                      </div>
                      <div className="space-y-1.5 max-h-32 overflow-y-auto">
                        {selectedData.parents.map((pId) => {
                          const parent = cascadeNodes.find((n) => n.id === pId);
                          if (!parent) return null;
                          const isParentMitigated = mitigatedNodes.has(pId);
                          return (
                            <button key={pId} onClick={() => onNodeSelect(pId)}
                              className="w-full flex items-center gap-3 p-3 rounded-xl bg-white/2 hover:bg-white/5 border border-white/5 hover:border-white/10 transition-all duration-200 group">
                              <div className="p-1.5 rounded-lg ring-1 ring-white/10" style={{ backgroundColor: getStatusColor(isParentMitigated ? "mitigated" : parent.status).bg, color: getStatusColor(isParentMitigated ? "mitigated" : parent.status).main }}>
                                {isParentMitigated ? <ShieldCheck className="h-3.5 w-3.5" /> : <NodeIcon type={parent.type} severity={parent.severity} size={14} />}
                              </div>
                              <div className="flex-1 text-left">
                                <p className="text-xs font-medium text-[#A1A1AA] group-hover:text-white truncate transition-colors">{parent.name}</p>
                                <p className="text-[10px] text-[#3F3F46] mt-0.5">Level {parent.level}</p>
                              </div>
                              <ChevronRight className="h-3.5 w-3.5 text-[#3F3F46] group-hover:text-[#818CF8] transition-colors" />
                            </button>
                          );
                        })}
                      </div>
                    </motion.div>
                  )}

                  {/* Propagates To */}
                  {selectedData.children && selectedData.children.length > 0 && (
                    <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.5 }}>
                      <div className="flex items-center gap-2 mb-2">
                        <ChevronRight className="h-3.5 w-3.5 text-[#52525B]" />
                        <span className="text-xs font-medium text-[#52525B] uppercase tracking-wide">Propagates To ({selectedData.children.length})</span>
                      </div>
                      <div className="space-y-1.5 max-h-40 overflow-y-auto">
                        {selectedData.children.map((cId) => {
                          const child = cascadeNodes.find((n) => n.id === cId);
                          if (!child) return null;
                          const isChildMitigated = mitigatedNodes.has(cId);
                          return (
                            <button key={cId} onClick={() => onNodeSelect(cId)}
                              className="w-full flex items-center gap-3 p-3 rounded-xl bg-white/2 hover:bg-white/5 border border-white/5 hover:border-white/10 transition-all duration-200 group">
                              <div className="p-1.5 rounded-lg ring-1 ring-white/10" style={{ backgroundColor: getStatusColor(isChildMitigated ? "mitigated" : child.status).bg, color: getStatusColor(isChildMitigated ? "mitigated" : child.status).main }}>
                                {isChildMitigated ? <ShieldCheck className="h-3.5 w-3.5" /> : <NodeIcon type={child.type} severity={child.severity} size={14} />}
                              </div>
                              <div className="flex-1 text-left">
                                <p className="text-xs font-medium text-[#A1A1AA] group-hover:text-white truncate transition-colors">{child.name}</p>
                                <p className="text-[10px] text-[#3F3F46] capitalize mt-0.5">{child.type}</p>
                              </div>
                              <span className="text-xs font-bold px-2 py-0.5 rounded-full border" style={{
                                color: isChildMitigated ? "#22D3EE" : (child.risk || 0) >= 80 ? "#F87171" : (child.risk || 0) >= 60 ? "#FBBF24" : "#4ADE80",
                                backgroundColor: isChildMitigated ? "rgba(6,182,212,0.10)" : (child.risk || 0) >= 80 ? "rgba(239,68,68,0.10)" : (child.risk || 0) >= 60 ? "rgba(245,158,11,0.10)" : "rgba(34,197,94,0.10)",
                                borderColor: isChildMitigated ? "rgba(6,182,212,0.20)" : (child.risk || 0) >= 80 ? "rgba(239,68,68,0.20)" : (child.risk || 0) >= 60 ? "rgba(245,158,11,0.20)" : "rgba(34,197,94,0.20)",
                              }}>
                                {isChildMitigated ? "✓" : `${Math.round(child.risk || 0)}%`}
                              </span>
                            </button>
                          );
                        })}
                      </div>
                    </motion.div>
                  )}

                  {/* References */}
                  {selectedData.references && selectedData.references.length > 0 && (
                    <motion.div className="p-4 rounded-xl bg-white/2 border border-white/5"
                      initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.55 }}>
                      <div className="flex items-center gap-2 mb-3">
                        <div className="p-1.5 rounded-lg bg-[#3B82F6]/10"><Link2 className="h-3.5 w-3.5 text-[#60A5FA]" /></div>
                        <span className="text-xs font-medium text-[#E4E4E7] uppercase tracking-wide">References</span>
                      </div>
                      <div className="space-y-1.5 max-h-32 overflow-y-auto">
                        {selectedData.references.slice(0, 5).map((ref, i) => (
                          <a key={i} href={ref.url} target="_blank" rel="noopener noreferrer"
                            className="flex items-start gap-2 p-2.5 rounded-lg bg-[#09090B]/60 hover:bg-white/4 border border-white/4 hover:border-white/8 transition-all duration-200 group">
                            <ExternalLink className="h-3 w-3 text-[#3F3F46] group-hover:text-[#60A5FA] mt-0.5 flex-shrink-0 transition-colors" />
                            <div className="flex-1 min-w-0">
                              <p className="text-xs text-[#71717A] group-hover:text-[#60A5FA] truncate transition-colors">
                                {ref.url.replace(/https?:\/\//, "").split("/").slice(0, 3).join("/")}
                              </p>
                              {ref.tags && ref.tags.length > 0 && (
                                <div className="flex gap-1 mt-1 flex-wrap">
                                  {ref.tags.slice(0, 3).map((tag, j) => (
                                    <span key={j} className="px-1.5 py-0.5 rounded-full text-[10px] bg-white/4 text-[#3F3F46] border border-white/5">{tag}</span>
                                  ))}
                                </div>
                              )}
                            </div>
                          </a>
                        ))}
                      </div>
                    </motion.div>
                  )}

                  {/* Mitigate button */}
                  <motion.div className="pt-2 pb-4 space-y-2" initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.6 }}>
                    {mitigatedNodes.has(selectedData.id) ? (
                      <div className="p-4 rounded-xl bg-[#06B6D4]/8 border border-[#06B6D4]/18 text-center shadow-[0_0_20px_-8px_rgba(6,182,212,0.15)]">
                        <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-[#06B6D4]/10 ring-1 ring-[#06B6D4]/20 mb-3">
                          <ShieldCheck className="h-6 w-6 text-[#22D3EE]" />
                        </div>
                        <p className="text-sm font-semibold text-[#22D3EE]">Successfully Mitigated</p>
                        <p className="text-xs text-[#52525B] mt-1">Cascade propagation from this node has been interrupted</p>
                      </div>
                    ) : (
                      <button onClick={() => handleStartMitigation(selectedData.id)}
                        className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-gradient-to-r from-[#3B82F6] to-[#6366F1] hover:from-[#2563EB] hover:to-[#4F46E5] text-white font-medium transition-all duration-200 shadow-[0_0_0_1px_rgba(255,255,255,0.1)_inset,0_8px_24px_-6px_rgba(59,130,246,0.35)] hover:shadow-[0_0_0_1px_rgba(255,255,255,0.14)_inset,0_14px_36px_-6px_rgba(59,130,246,0.5)] hover:-translate-y-px">
                        <Zap className="h-4 w-4" /> Mitigate Vulnerability
                      </button>
                    )}
                  </motion.div>

                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>

      <MitigationModal
        isOpen={showMitigationModal}
        onClose={handleCloseMitigationModal}
        node={mitigatingNode}
        actions={MITIGATION_ACTIONS}
        onComplete={handleMitigationComplete}
      />
    </>
  );
}