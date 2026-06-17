import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Server, Plus, Trash2, RefreshCw, Globe, Lock,
  Shield, AlertTriangle, ChevronRight, X, Check,
  Database, Monitor, Wifi, HardDrive, Search,
  ShieldAlert, Activity, Eye, Terminal
} from "lucide-react";

// ── Types ──────────────────────────────────────────────────
interface Service {
  name: string;
  product: string;
  version: string;
  port?: number;
}

interface Asset {
  id: string;
  hostname: string;
  ip_address: string;
  os_type: string;
  os_version: string;
  criticality: "critical" | "high" | "medium" | "low";
  environment: string;
  internet_facing: boolean;
  behind_firewall: boolean;
  requires_vpn: boolean;
  services: Service[];
  last_scanned: string;
  cve_count?: number;
}

interface AssetManagerPanelProps {
  apiFetch: <T = any>(path: string, options?: RequestInit) => Promise<T>;
  onAssetChange?: () => void;
}

// ── Constants ──────────────────────────────────────────────
const CRITICALITY_CONFIG = {
  critical: { label: "Critical", color: "text-[#F87171]", bg: "bg-[#EF4444]/10", border: "border-[#EF4444]/25", dot: "bg-[#EF4444]" },
  high:     { label: "High",     color: "text-[#FBBF24]", bg: "bg-[#F59E0B]/10", border: "border-[#F59E0B]/25", dot: "bg-[#F59E0B]" },
  medium:   { label: "Medium",   color: "text-[#60A5FA]", bg: "bg-[#3B82F6]/10", border: "border-[#3B82F6]/25", dot: "bg-[#3B82F6]" },
  low:      { label: "Low",      color: "text-[#34D399]", bg: "bg-[#10B981]/10", border: "border-[#10B981]/25", dot: "bg-[#10B981]" },
};

const ENV_CONFIG: Record<string, { label: string; color: string }> = {
  production:  { label: "Production",  color: "text-[#F87171]" },
  staging:     { label: "Staging",     color: "text-[#FBBF24]" },
  development: { label: "Development", color: "text-[#34D399]" },
};

const OS_ICONS: Record<string, string> = {
  linux: "🐧", windows: "🪟", macos: "🍎",
  freebsd: "👿", aix: "💻", unknown: "🖥️",
};

// ── Service Icon ───────────────────────────────────────────
function ServiceIcon({ name }: { name: string }) {
  const n = name.toLowerCase();
  if (n.includes("postgres") || n.includes("mysql") || n.includes("mongo") || n.includes("redis"))
    return <Database className="h-3.5 w-3.5 text-[#818CF8]" />;
  if (n.includes("nginx") || n.includes("apache") || n.includes("http"))
    return <Globe className="h-3.5 w-3.5 text-[#60A5FA]" />;
  if (n.includes("ssh"))
    return <Terminal className="h-3.5 w-3.5 text-[#34D399]" />;
  return <Activity className="h-3.5 w-3.5 text-[#71717A]" />;
}

// ── Add Asset Modal ────────────────────────────────────────
function AddAssetModal({
  onClose,
  onSave,
  saving,
}: {
  onClose: () => void;
  onSave: (data: any) => void;
  saving: boolean;
}) {
  const [form, setForm] = useState({
    hostname: "",
    ip_address: "",
    os_type: "Linux",
    os_version: "",
    criticality: "medium",
    environment: "production",
    data_classification: "internal",
    internet_facing: false,
    behind_firewall: true,
    requires_vpn: false,
  });

  const [services, setServices] = useState<{ product: string; version: string; port: string }[]>([
    { product: "", version: "", port: "" },
  ]);

  const addService = () =>
    setServices((s) => [...s, { product: "", version: "", port: "" }]);

  const removeService = (i: number) =>
    setServices((s) => s.filter((_, idx) => idx !== i));

  const updateService = (i: number, field: string, value: string) =>
    setServices((s) => s.map((svc, idx) => (idx === i ? { ...svc, [field]: value } : svc)));

  const handleSubmit = () => {
    const payload = {
      ...form,
      services: services
        .filter((s) => s.product.trim())
        .map((s) => ({
          name: s.product.toLowerCase(),
          product: s.product,
          version: s.version,
          port: s.port ? parseInt(s.port) : undefined,
        })),
    };
    onSave(payload);
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
    >
      <motion.div
        initial={{ scale: 0.95, opacity: 0, y: 16 }}
        animate={{ scale: 1, opacity: 1, y: 0 }}
        exit={{ scale: 0.95, opacity: 0 }}
        transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
        className="w-full max-w-2xl bg-[#0d0d12] border border-white/10 rounded-2xl shadow-2xl overflow-hidden"
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-white/8">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-[#3B82F6]/10">
              <Server className="h-5 w-5 text-[#60A5FA]" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-white">Add Infrastructure Asset</h2>
              <p className="text-[12px] text-[#52525B]">Register a server or device for CVE matching</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg hover:bg-white/5 text-[#52525B] hover:text-white transition"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="p-6 space-y-5 overflow-y-auto max-h-[70vh]">
          {/* Identity */}
          <div>
            <p className="text-[11px] font-semibold text-[#52525B] uppercase tracking-widest mb-3">
              Identity
            </p>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-[12px] text-[#A1A1AA] mb-1.5 block">Hostname *</label>
                <input
                  type="text"
                  placeholder="web-prod-01"
                  value={form.hostname}
                  onChange={(e) => setForm((f) => ({ ...f, hostname: e.target.value }))}
                  className="w-full px-3 py-2 rounded-lg bg-white/[0.04] border border-white/10 text-white text-sm placeholder:text-[#3F3F46] focus:outline-none focus:border-[#3B82F6]/50 transition"
                />
              </div>
              <div>
                <label className="text-[12px] text-[#A1A1AA] mb-1.5 block">IP Address *</label>
                <input
                  type="text"
                  placeholder="192.168.1.10"
                  value={form.ip_address}
                  onChange={(e) => setForm((f) => ({ ...f, ip_address: e.target.value }))}
                  className="w-full px-3 py-2 rounded-lg bg-white/[0.04] border border-white/10 text-white text-sm placeholder:text-[#3F3F46] focus:outline-none focus:border-[#3B82F6]/50 transition"
                />
              </div>
            </div>
          </div>

          {/* OS */}
          <div>
            <p className="text-[11px] font-semibold text-[#52525B] uppercase tracking-widest mb-3">
              Operating System
            </p>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-[12px] text-[#A1A1AA] mb-1.5 block">OS Type</label>
                <select
                  value={form.os_type}
                  onChange={(e) => setForm((f) => ({ ...f, os_type: e.target.value }))}
                  className="w-full px-3 py-2 rounded-lg bg-white/[0.04] border border-white/10 text-white text-sm focus:outline-none focus:border-[#3B82F6]/50 transition"
                >
                  {["Linux", "Windows", "macOS", "FreeBSD", "AIX", "Other"].map((o) => (
                    <option key={o} value={o} className="bg-[#0d0d12]">{o}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-[12px] text-[#A1A1AA] mb-1.5 block">OS Version</label>
                <input
                  type="text"
                  placeholder="Ubuntu 22.04 LTS"
                  value={form.os_version}
                  onChange={(e) => setForm((f) => ({ ...f, os_version: e.target.value }))}
                  className="w-full px-3 py-2 rounded-lg bg-white/[0.04] border border-white/10 text-white text-sm placeholder:text-[#3F3F46] focus:outline-none focus:border-[#3B82F6]/50 transition"
                />
              </div>
            </div>
          </div>

          {/* Risk Context */}
          <div>
            <p className="text-[11px] font-semibold text-[#52525B] uppercase tracking-widest mb-3">
              Risk Context
            </p>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-[12px] text-[#A1A1AA] mb-1.5 block">Criticality</label>
                <select
                  value={form.criticality}
                  onChange={(e) => setForm((f) => ({ ...f, criticality: e.target.value }))}
                  className="w-full px-3 py-2 rounded-lg bg-white/[0.04] border border-white/10 text-white text-sm focus:outline-none focus:border-[#3B82F6]/50 transition"
                >
                  {["critical", "high", "medium", "low"].map((c) => (
                    <option key={c} value={c} className="bg-[#0d0d12] capitalize">{c.charAt(0).toUpperCase() + c.slice(1)}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-[12px] text-[#A1A1AA] mb-1.5 block">Environment</label>
                <select
                  value={form.environment}
                  onChange={(e) => setForm((f) => ({ ...f, environment: e.target.value }))}
                  className="w-full px-3 py-2 rounded-lg bg-white/[0.04] border border-white/10 text-white text-sm focus:outline-none focus:border-[#3B82F6]/50 transition"
                >
                  {["production", "staging", "development"].map((e) => (
                    <option key={e} value={e} className="bg-[#0d0d12] capitalize">{e.charAt(0).toUpperCase() + e.slice(1)}</option>
                  ))}
                </select>
              </div>
            </div>
          </div>

          {/* Network Exposure */}
          <div>
            <p className="text-[11px] font-semibold text-[#52525B] uppercase tracking-widest mb-3">
              Network Exposure
            </p>
            <div className="flex flex-wrap gap-3">
              {[
                { key: "internet_facing", label: "Internet Facing", icon: Globe },
                { key: "behind_firewall", label: "Behind Firewall", icon: Shield },
                { key: "requires_vpn", label: "Requires VPN", icon: Lock },
              ].map(({ key, label, icon: Icon }) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => setForm((f) => ({ ...f, [key]: !f[key as keyof typeof f] }))}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-sm transition ${
                    form[key as keyof typeof form]
                      ? "bg-[#3B82F6]/15 border-[#3B82F6]/40 text-[#60A5FA]"
                      : "bg-white/[0.03] border-white/10 text-[#52525B] hover:text-white"
                  }`}
                >
                  <Icon className="h-3.5 w-3.5" />
                  {label}
                  {form[key as keyof typeof form] && <Check className="h-3 w-3" />}
                </button>
              ))}
            </div>
          </div>

          {/* Services */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <p className="text-[11px] font-semibold text-[#52525B] uppercase tracking-widest">
                Software & Services
              </p>
              <button
                type="button"
                onClick={addService}
                className="flex items-center gap-1 text-[12px] text-[#60A5FA] hover:text-blue-300 transition"
              >
                <Plus className="h-3.5 w-3.5" />
                Add service
              </button>
            </div>
            <div className="space-y-2">
              {services.map((svc, i) => (
                <div key={i} className="flex gap-2 items-center">
                  <input
                    type="text"
                    placeholder="nginx"
                    value={svc.product}
                    onChange={(e) => updateService(i, "product", e.target.value)}
                    className="flex-1 px-3 py-2 rounded-lg bg-white/[0.04] border border-white/10 text-white text-sm placeholder:text-[#3F3F46] focus:outline-none focus:border-[#3B82F6]/50 transition"
                  />
                  <input
                    type="text"
                    placeholder="1.18.0"
                    value={svc.version}
                    onChange={(e) => updateService(i, "version", e.target.value)}
                    className="w-28 px-3 py-2 rounded-lg bg-white/[0.04] border border-white/10 text-white text-sm placeholder:text-[#3F3F46] focus:outline-none focus:border-[#3B82F6]/50 transition"
                  />
                  <input
                    type="text"
                    placeholder="80"
                    value={svc.port}
                    onChange={(e) => updateService(i, "port", e.target.value)}
                    className="w-20 px-3 py-2 rounded-lg bg-white/[0.04] border border-white/10 text-white text-sm placeholder:text-[#3F3F46] focus:outline-none focus:border-[#3B82F6]/50 transition"
                  />
                  {services.length > 1 && (
                    <button
                      type="button"
                      onClick={() => removeService(i)}
                      className="p-2 rounded-lg hover:bg-red-500/10 text-[#52525B] hover:text-red-400 transition"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  )}
                </div>
              ))}
              <p className="text-[11px] text-[#3F3F46]">
                Product name · Version · Port (optional)
              </p>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-white/8">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-sm text-[#71717A] hover:text-white hover:bg-white/5 transition"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={saving || !form.hostname || !form.ip_address}
            className="flex items-center gap-2 px-5 py-2 rounded-lg bg-gradient-to-r from-[#3B82F6] to-[#6366F1] text-white text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-[#3B82F6]/25 hover:shadow-[#3B82F6]/35 transition"
          >
            {saving ? (
              <><span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />Saving...</>
            ) : (
              <><Plus className="h-4 w-4" />Add Asset</>
            )}
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
}

// ── Asset Card ─────────────────────────────────────────────
function AssetCard({
  asset,
  onDelete,
  onSelect,
  selected,
}: {
  asset: Asset;
  onDelete: (id: string) => void;
  onSelect: (asset: Asset) => void;
  selected: boolean;
}) {
  const cfg = CRITICALITY_CONFIG[asset.criticality] || CRITICALITY_CONFIG.medium;
  const envCfg = ENV_CONFIG[asset.environment] || { label: asset.environment, color: "text-[#A1A1AA]" };
  const osIcon = OS_ICONS[asset.os_type?.toLowerCase() || "unknown"] || "🖥️";

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      className={`relative p-4 rounded-xl border cursor-pointer transition-all duration-200 min-h-[180px] flex flex-col ${
        selected
          ? "border-[#3B82F6]/50 bg-[#3B82F6]/8 shadow-[0_0_20px_rgba(59,130,246,0.1)]"
          : `${cfg.border} ${cfg.bg} hover:border-white/20`
      }`}
      onClick={() => onSelect(asset)}
    >
      {/* Criticality dot */}
      <div className={`absolute top-3 right-3 w-2 h-2 rounded-full ${cfg.dot}`} />

      {/* Header */}
      <div className="flex items-start gap-3 mb-3">
        <div className="p-2 rounded-lg bg-white/[0.04] border border-white/8 text-lg">
          {osIcon}
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold text-white truncate">{asset.hostname}</p>
          <p className="text-[12px] text-[#52525B] font-mono">{asset.ip_address}</p>
        </div>
      </div>

      {/* Badges */}
      <div className="flex flex-wrap gap-1.5 mb-3">
        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${cfg.color} ${cfg.bg} border ${cfg.border}`}>
          {cfg.label}
        </span>
        <span className={`px-2 py-0.5 rounded text-[10px] ${envCfg.color} bg-white/[0.04] border border-white/8`}>
          {envCfg.label}
        </span>
        {asset.internet_facing && (
          <span className="px-2 py-0.5 rounded text-[10px] text-[#F87171] bg-[#EF4444]/8 border border-[#EF4444]/20 flex items-center gap-1">
            <Globe className="h-2.5 w-2.5" /> Internet
          </span>
        )}
        {asset.requires_vpn && (
          <span className="px-2 py-0.5 rounded text-[10px] text-[#818CF8] bg-[#6366F1]/8 border border-[#6366F1]/20 flex items-center gap-1">
            <Lock className="h-2.5 w-2.5" /> VPN
          </span>
        )}
      </div>

      {/* Services */}
      <div className="flex-1">
      {asset.services && asset.services.length > 0 ? (
        <div className="flex flex-wrap gap-1 mb-3">
          {asset.services.slice(0, 3).map((svc, i) => (
            <span key={i} className="flex items-center gap-1 px-2 py-0.5 rounded bg-white/[0.04] border border-white/8 text-[11px] text-[#A1A1AA]">
              <ServiceIcon name={svc.name || svc.product || ""} />
              {svc.product}
              {svc.version && <span className="text-[#52525B]">{svc.version}</span>}
            </span>
          ))}
          {asset.services.length > 3 && (
            <span className="px-2 py-0.5 rounded bg-white/[0.04] border border-white/8 text-[11px] text-[#52525B]">
              +{asset.services.length - 3} more
            </span>
          )}
        </div>
      ) : (
        <div className="flex items-center gap-1 mb-3 text-[11px] text-[#3F3F46]">
          No services registered
        </div>
      )}
      </div>

      {/* Footer */}
      <div className="flex items-center justify-between">
        <p className="text-[11px] text-[#3F3F46]">
          {asset.os_type} {asset.os_version}
        </p>
        <button
          onClick={(e) => { e.stopPropagation(); onDelete(asset.id); }}
          className="p-1.5 rounded-lg hover:bg-red-500/10 text-[#3F3F46] hover:text-red-400 transition opacity-0 group-hover:opacity-100"
          title="Delete asset"
        >
          <Trash2 className="h-3.5 w-3.5" />
        </button>
      </div>
    </motion.div>
  );
}

// ── Main Component ─────────────────────────────────────────
export function AssetManagerPanel({ apiFetch, onAssetChange }: AssetManagerPanelProps) {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [search, setSearch] = useState("");
  const [filterCriticality, setFilterCriticality] = useState<string>("all");
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const fetchAssets = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiFetch<{ assets: Asset[]; total: number }>("/assets/?limit=500");
      setAssets(data.assets || []);
    } catch (e) {
      setError("Failed to load assets");
    } finally {
      setLoading(false);
    }
  }, [apiFetch]);

  useEffect(() => { fetchAssets(); }, [fetchAssets]);

  const handleAddAsset = async (formData: any) => {
    setSaving(true);
    setError(null);
    try {
      const result = await apiFetch<{ success: boolean; error?: string }>("/assets/", {
        method: "POST",
        body: JSON.stringify(formData),
      });
      if (!result.success) {
        setError(result.error || "Failed to add asset");
        return;
      }
      setShowAddModal(false);
      setSuccessMsg("Asset added successfully");
      setTimeout(() => setSuccessMsg(null), 3000);
      fetchAssets();
      onAssetChange?.();
    } catch (e) {
      setError("Network error — could not save asset");
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteAsset = async (id: string) => {
    if (!confirm("Delete this asset? This cannot be undone.")) return;
    setDeleting(id);
    try {
      await apiFetch(`/assets/${id}/`, { method: "DELETE" });
      setAssets((a) => a.filter((asset) => asset.id !== id));
      if (selectedAsset?.id === id) setSelectedAsset(null);
      setSuccessMsg("Asset deleted");
      setTimeout(() => setSuccessMsg(null), 3000);
      onAssetChange?.();
    } catch {
      setError("Failed to delete asset");
    } finally {
      setDeleting(null);
    }
  };

  // Filter assets
  const filtered = assets.filter((a) => {
    const matchSearch =
      !search ||
      a.hostname.toLowerCase().includes(search.toLowerCase()) ||
      a.ip_address.includes(search);
    const matchCriticality =
      filterCriticality === "all" || a.criticality === filterCriticality;
    return matchSearch && matchCriticality;
  });

  // Stats
  const stats = {
    total: assets.length,
    critical: assets.filter((a) => a.criticality === "critical").length,
    high: assets.filter((a) => a.criticality === "high").length,
    internet: assets.filter((a) => a.internet_facing).length,
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold text-white flex items-center gap-2">
            <Server className="h-5 w-5 text-[#60A5FA]" />
            Infrastructure Assets
          </h2>
          <p className="text-sm text-[#52525B] mt-0.5">
            Register your infrastructure for personalized CVE matching
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={fetchAssets}
            className="p-2 rounded-lg hover:bg-white/5 text-[#52525B] hover:text-white transition"
            title="Refresh"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-[#3B82F6] to-[#6366F1] text-white text-sm font-medium shadow-lg shadow-[#3B82F6]/25 hover:shadow-[#3B82F6]/35 hover:-translate-y-px transition-all"
          >
            <Plus className="h-4 w-4" />
            Add Asset
          </button>
        </div>
      </div>

      {/* Stats Bar */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: "Total Assets", value: stats.total, icon: Server, color: "text-[#60A5FA]", bg: "bg-[#3B82F6]/10" },
          { label: "Critical", value: stats.critical, icon: ShieldAlert, color: "text-[#F87171]", bg: "bg-[#EF4444]/10" },
          { label: "High Risk", value: stats.high, icon: AlertTriangle, color: "text-[#FBBF24]", bg: "bg-[#F59E0B]/10" },
          { label: "Internet Facing", value: stats.internet, icon: Globe, color: "text-[#F87171]", bg: "bg-[#EF4444]/10" },
        ].map(({ label, value, icon: Icon, color, bg }) => (
          <div key={label} className="p-4 rounded-xl border border-white/8 bg-white/[0.02]">
            <div className="flex items-center gap-2 mb-2">
              <div className={`p-1.5 rounded-lg ${bg}`}>
                <Icon className={`h-4 w-4 ${color}`} />
              </div>
              <span className="text-[12px] text-[#52525B]">{label}</span>
            </div>
            <p className="text-2xl font-bold text-white">{value}</p>
          </div>
        ))}
      </div>

      {/* Notifications */}
      <AnimatePresence>
        {successMsg && (
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="flex items-center gap-2 px-4 py-3 rounded-xl bg-emerald-500/10 border border-emerald-500/25 text-emerald-300 text-sm"
          >
            <Check className="h-4 w-4" /> {successMsg}
          </motion.div>
        )}
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="flex items-center gap-2 px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/25 text-red-300 text-sm"
          >
            <AlertTriangle className="h-4 w-4" /> {error}
            <button onClick={() => setError(null)} className="ml-auto">
              <X className="h-3.5 w-3.5" />
            </button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Search + Filter */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[#52525B]" />
          <input
            type="text"
            placeholder="Search by hostname or IP..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg bg-white/[0.04] border border-white/10 text-white text-sm placeholder:text-[#3F3F46] focus:outline-none focus:border-[#3B82F6]/50 transition"
          />
        </div>
        <div className="flex items-center gap-1.5">
          {["all", "critical", "high", "medium", "low"].map((c) => (
            <button
              key={c}
              onClick={() => setFilterCriticality(c)}
              className={`px-3 py-1.5 rounded-lg text-[12px] font-medium transition ${
                filterCriticality === c
                  ? "bg-[#3B82F6]/15 text-[#60A5FA] border border-[#3B82F6]/30"
                  : "bg-white/[0.03] text-[#52525B] border border-white/8 hover:text-white"
              }`}
            >
              {c.charAt(0).toUpperCase() + c.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      {loading ? (
        <div className="flex items-center justify-center py-24">
          <div className="flex flex-col items-center gap-3">
            <RefreshCw className="h-8 w-8 text-[#3B82F6] animate-spin" />
            <p className="text-sm text-[#52525B]">Loading assets...</p>
          </div>
        </div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-24 text-center">
          <div className="p-4 rounded-2xl bg-white/[0.03] border border-white/8 mb-4">
            <Server className="h-12 w-12 text-[#27272A] mx-auto" />
          </div>
          <h3 className="text-base font-semibold text-white mb-2">
            {search || filterCriticality !== "all" ? "No assets match your filter" : "No assets registered yet"}
          </h3>
          <p className="text-sm text-[#52525B] max-w-sm mb-6">
            {search || filterCriticality !== "all"
              ? "Try adjusting your search or filter."
              : "Add your infrastructure assets to get personalized CVE matching and risk scoring."}
          </p>
          {!search && filterCriticality === "all" && (
            <button
              onClick={() => setShowAddModal(true)}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-gradient-to-r from-[#3B82F6] to-[#6366F1] text-white text-sm font-medium shadow-lg shadow-[#3B82F6]/25"
            >
              <Plus className="h-4 w-4" />
              Add Your First Asset
            </button>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          <AnimatePresence>
            {filtered.map((asset) => (
              <div key={asset.id} className="group relative">
                {deleting === asset.id && (
                  <div className="absolute inset-0 z-10 rounded-xl bg-black/50 flex items-center justify-center">
                    <RefreshCw className="h-5 w-5 text-white animate-spin" />
                  </div>
                )}
                <AssetCard
                  asset={asset}
                  onDelete={handleDeleteAsset}
                  onSelect={setSelectedAsset}
                  selected={selectedAsset?.id === asset.id}
                />

              </div>
            ))}
          </AnimatePresence>
        </div>
      )}

      {/* Add Asset Modal */}
      <AnimatePresence>
        {showAddModal && (
          <AddAssetModal
            onClose={() => setShowAddModal(false)}
            onSave={handleAddAsset}
            saving={saving}
          />
        )}
      </AnimatePresence>
    </div>
  );
}
