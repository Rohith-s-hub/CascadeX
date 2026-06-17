import { Activity, AlertTriangle, Bell, Bug, Download, FileText, Network, RefreshCw, Search, Shield, Zap } from "lucide-react";

/**
 * High-fidelity replica of the actual CascadeX Intelligence dashboard
 * (matches the user's real product UI, retuned to the blue/violet brand).
 */
export function DashboardMockup({ compact = false }: { compact?: boolean }) {
  return (
    <div className="relative w-full">
      {/* Browser chrome */}
      <div className="rounded-t-xl bg-[#1a1a1d] border border-white/[0.08] border-b-0 px-4 py-2.5 flex items-center gap-2">
        <div className="flex gap-1.5">
          <div className="w-2.5 h-2.5 rounded-full bg-[#ff5f57]" />
          <div className="w-2.5 h-2.5 rounded-full bg-[#febc2e]" />
          <div className="w-2.5 h-2.5 rounded-full bg-[#28c840]" />
        </div>
        <div className="flex-1 flex justify-center">
          <div className="px-3 py-1 rounded-md bg-black/40 text-[10.5px] text-white/50 font-mono flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            cascadex.app/intelligence
          </div>
        </div>
        <div className="w-10" />
      </div>

      {/* App body */}
      <div className="rounded-b-xl bg-[#0b0b0e] border border-white/[0.08] overflow-hidden">
        {/* Top header bar */}
        <div className="px-5 py-4 border-b border-white/[0.06] flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-brand flex items-center justify-center">
              <Shield className="w-4.5 h-4.5 text-white" strokeWidth={2.4} />
            </div>
            <div>
              <div className="text-[15px] font-semibold text-gradient-brand leading-tight">CascadeX Intelligence</div>
              <div className="text-[10.5px] text-white/40">v4.0 — Full-spectrum vulnerability management</div>
            </div>
          </div>
          {!compact && (
            <div className="hidden lg:flex items-center gap-1.5">
              <Pill icon={<Activity className="w-3 h-3 text-emerald-400" />} label="Connected" />
              <Pill icon={<span className="w-1.5 h-1.5 rounded-full bg-white/30" />} label="MONITOR OFF" />
              <Pill icon={<Bell className="w-3 h-3 text-blue-400" />} label="7" tone="brand" />
              <Pill icon={<Activity className="w-3 h-3 text-blue-400" />} label="Risk: 30/100" tone="brand" />
              <Pill icon={<Download className="w-3 h-3" />} label="Export" />
              <Pill icon={<RefreshCw className="w-3 h-3" />} label="Reset" />
              <button className="px-2.5 py-1.5 text-[11px] font-medium text-white bg-gradient-brand rounded-md flex items-center gap-1">
                <Search className="w-3 h-3" /> Scan CVEs
              </button>
            </div>
          )}
        </div>

        {/* Tabs */}
        <div className="px-5 pt-3 flex items-center gap-1.5 border-b border-white/[0.04]">
          <Tab icon={<Network className="w-3.5 h-3.5" />} label="Intelligence" active />
          <Tab icon={<FileText className="w-3.5 h-3.5" />} label="Compliance" />
          <Tab icon={<Search className="w-3.5 h-3.5" />} label="Active Scan" />
          <Tab icon={<Activity className="w-3.5 h-3.5" />} label="Trending" />
        </div>

        <div className="p-4 sm:p-5 space-y-4">
          {/* Hero panel */}
          <div className="grid grid-cols-12 gap-3">
            {/* Release readiness */}
            <div className="col-span-12 lg:col-span-5 rounded-xl bg-gradient-to-br from-blue-500/[0.08] via-violet-500/[0.05] to-transparent border border-white/[0.06] p-4">
              <div className="inline-flex items-center gap-1.5 text-[10px] font-semibold tracking-wider uppercase text-blue-300 px-2 py-0.5 rounded-md bg-blue-500/10 border border-blue-500/20">
                <Zap className="w-3 h-3" /> Release Readiness
              </div>
              <h3 className="mt-3 text-lg sm:text-xl font-semibold text-white leading-snug tracking-tight">
                Operational clarity for high-risk exposure before release.
              </h3>
              <p className="mt-2 text-[11.5px] text-white/55 leading-relaxed">
                Review attack chains, asset relevance, mitigations, and live alerting in one place.
              </p>
              <div className="mt-3 flex flex-wrap gap-1.5">
                <Chip>Posture: <b className="ml-1 text-blue-300">Critical</b></Chip>
                <Chip>Assets in scope: <b className="ml-1 text-white">19</b></Chip>
              </div>
            </div>

            {/* KPI 3-up */}
            <div className="col-span-12 lg:col-span-4 grid grid-cols-3 gap-2.5">
              <Stat label="Critical findings" value="50" tone="rose" />
              <Stat label="Exploitable CVEs" value="2" tone="amber" />
              <Stat label="Asset-matched" value="0" tone="cyan" />
            </div>

            {/* Scan control */}
            <div className="col-span-12 lg:col-span-3 rounded-xl bg-white/[0.02] border border-white/[0.06] p-3.5">
              <div className="flex items-center justify-between">
                <div className="text-[10px] tracking-wider font-semibold text-white/40 uppercase">Scan Control</div>
                <button className="px-2 py-1 text-[10px] font-medium text-white bg-gradient-brand rounded-md">Run Scan</button>
              </div>
              <div className="mt-2 text-[12px] font-medium text-white">Tune coverage</div>
              <div className="mt-2.5 grid grid-cols-2 gap-1.5 text-[10px]">
                <Field label="Severity" value="All" />
                <Field label="Window" value="30d" />
                <Field label="Cap" value="50" />
                <Field label="Keywords" value="apache..." />
              </div>
              <div className="mt-2 flex gap-1 flex-wrap">
                <Mini label="All" active /><Mini label="Asset" /><Mini label="Exploit" />
              </div>
            </div>
          </div>

          {/* KPI strip */}
          <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
            <KPI icon={<Bug className="w-3.5 h-3.5" />} value="50" label="Total CVEs" tint="violet" />
            <KPI icon={<Activity className="w-3.5 h-3.5" />} value="30" label="Avg Risk" tint="indigo" />
            <KPI icon={<AlertTriangle className="w-3.5 h-3.5" />} value="2" label="Exploitable" tint="rose" />
            <KPI icon={<Network className="w-3.5 h-3.5" />} value="0" label="Attack Chains" tint="amber" />
            <KPI icon={<Shield className="w-3.5 h-3.5" />} value="10%" label="Patch" tint="emerald" />
            <KPI icon={<FileText className="w-3.5 h-3.5" />} value="8%" label="Compliance" tint="blue" />
          </div>

          {/* Intelligence graph */}
          <div className="rounded-xl bg-white/[0.02] border border-white/[0.06] overflow-hidden">
            <div className="px-4 py-3 flex items-center justify-between border-b border-white/[0.04]">
              <div className="flex items-center gap-2.5">
                <div className="w-7 h-7 rounded-md bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
                  <Network className="w-3.5 h-3.5 text-blue-300" />
                </div>
                <div>
                  <div className="text-[12.5px] font-semibold text-white">CVE Cascade Graph</div>
                  <div className="text-[10px] text-white/40">178/50 CVEs · 38 vendors · 90 products</div>
                </div>
              </div>
              <div className="hidden sm:flex items-center gap-1.5">
                <LegendDot color="bg-rose-500" label="178 Critical" />
                <LegendDot color="bg-amber-400" label="2 Exploit" />
                <span className="px-1.5 py-0.5 text-[9.5px] font-semibold text-blue-300 bg-blue-500/15 rounded border border-blue-500/30 flex items-center gap-1">
                  <span className="w-1 h-1 rounded-full bg-blue-400 animate-pulse" /> LIVE
                </span>
              </div>
            </div>
            <CascadeGraph />
          </div>
        </div>
      </div>
    </div>
  );
}

function Pill({ icon, label, tone }: { icon: React.ReactNode; label: string; tone?: "brand" }) {
  return (
    <div
      className={`px-2 py-1 rounded-md text-[10.5px] flex items-center gap-1 border ${
        tone === "brand"
          ? "bg-blue-500/10 border-blue-500/25 text-blue-200"
          : "bg-white/[0.03] border-white/10 text-white/65"
      }`}
    >
      {icon}
      <span>{label}</span>
    </div>
  );
}

function Tab({ icon, label, active }: { icon: React.ReactNode; label: string; active?: boolean }) {
  return (
    <div
      className={`flex items-center gap-1.5 px-3 py-2 text-[11.5px] rounded-t-md border-b-2 ${
        active
          ? "text-blue-300 border-blue-500 bg-blue-500/[0.06]"
          : "text-white/55 border-transparent hover:text-white/80"
      }`}
    >
      {icon}
      {label}
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: string; tone: "rose" | "amber" | "cyan" }) {
  const colors = {
    rose: "text-rose-400",
    amber: "text-amber-300",
    cyan: "text-cyan-300",
  };
  return (
    <div className="rounded-xl bg-white/[0.02] border border-white/[0.06] p-3 flex flex-col justify-between min-h-[88px]">
      <div className="text-[9.5px] tracking-wider font-semibold uppercase text-white/40 leading-tight">{label}</div>
      <div className={`text-3xl font-light ${colors[tone]}`}>{value}</div>
    </div>
  );
}

function Chip({ children }: { children: React.ReactNode }) {
  return (
    <div className="px-2 py-1 text-[10.5px] text-white/65 bg-white/[0.03] border border-white/[0.07] rounded-md flex items-center">
      {children}
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="px-2 py-1.5 rounded-md bg-black/30 border border-white/[0.05]">
      <div className="text-[8.5px] uppercase tracking-wide text-white/35">{label}</div>
      <div className="text-[10.5px] text-white/80 mt-0.5 truncate">{value}</div>
    </div>
  );
}

function Mini({ label, active }: { label: string; active?: boolean }) {
  return (
    <span
      className={`px-1.5 py-0.5 text-[9.5px] rounded-md border ${
        active
          ? "bg-blue-500/15 border-blue-500/30 text-blue-200"
          : "bg-white/[0.03] border-white/10 text-white/55"
      }`}
    >
      {label}
    </span>
  );
}

function KPI({
  icon,
  value,
  label,
  tint,
}: {
  icon: React.ReactNode;
  value: string;
  label: string;
  tint: "violet" | "indigo" | "rose" | "amber" | "emerald" | "blue";
}) {
  const tints: Record<string, string> = {
    violet: "from-violet-500/30 to-fuchsia-500/20 text-violet-200",
    indigo: "from-indigo-500/30 to-blue-500/20 text-indigo-200",
    rose: "from-rose-500/30 to-pink-500/20 text-rose-200",
    amber: "from-amber-500/30 to-yellow-500/20 text-amber-200",
    emerald: "from-emerald-500/30 to-teal-500/20 text-emerald-200",
    blue: "from-blue-500/30 to-cyan-500/20 text-blue-200",
  };
  return (
    <div className="rounded-lg bg-white/[0.02] border border-white/[0.06] p-2.5">
      <div className={`w-7 h-7 rounded-md bg-gradient-to-br ${tints[tint]} flex items-center justify-center mb-1.5`}>
        {icon}
      </div>
      <div className="text-lg font-light text-white leading-none">{value}</div>
      <div className="text-[9.5px] text-white/45 mt-1">{label}</div>
    </div>
  );
}

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <div className="flex items-center gap-1 text-[10px] text-white/55">
      <span className={`w-1.5 h-1.5 rounded-full ${color}`} />
      {label}
    </div>
  );
}

function CascadeGraph() {
  const nodes = [
    { x: 50, y: 30, label: "Vendor", r: 6 },
    { x: 50, y: 70, label: "Apache", r: 8 },
    { x: 130, y: 50, label: "OpenSSL", r: 9 },
    { x: 130, y: 100, label: "Qwik", r: 7 },
    { x: 220, y: 40, label: "CVE", r: 5, crit: true },
    { x: 230, y: 90, label: "CVE", r: 6, crit: true },
    { x: 240, y: 130, label: "CVE", r: 7, crit: true },
    { x: 320, y: 60, label: "Asset", r: 6 },
    { x: 330, y: 130, label: "Asset", r: 6 },
    { x: 410, y: 95, label: "Impact", r: 8, crit: true },
  ];
  const edges = [
    [0, 1], [1, 2], [1, 3], [2, 4], [2, 5], [3, 5], [3, 6],
    [4, 7], [5, 7], [5, 8], [6, 8], [7, 9], [8, 9],
  ];
  return (
    <div className="relative h-[180px] sm:h-[220px] bg-[radial-gradient(ellipse_at_center,rgba(99,102,241,0.07),transparent_70%)]">
      <svg viewBox="0 0 460 180" className="absolute inset-0 w-full h-full" preserveAspectRatio="xMidYMid meet">
        <defs>
          <linearGradient id="edge" x1="0" x2="1" y1="0" y2="0">
            <stop offset="0%" stopColor="#3B82F6" stopOpacity="0.1" />
            <stop offset="50%" stopColor="#8B5CF6" stopOpacity="0.6" />
            <stop offset="100%" stopColor="#3B82F6" stopOpacity="0.1" />
          </linearGradient>
          <radialGradient id="nodeGrad" cx="50%" cy="50%">
            <stop offset="0%" stopColor="#A78BFA" />
            <stop offset="100%" stopColor="#3B82F6" />
          </radialGradient>
        </defs>
        {edges.map(([a, b], i) => (
          <line
            key={i}
            x1={nodes[a].x}
            y1={nodes[a].y}
            x2={nodes[b].x}
            y2={nodes[b].y}
            stroke="url(#edge)"
            strokeWidth="1"
            strokeDasharray="4 3"
            className="animate-data-flow"
            style={{ animationDelay: `${i * 0.15}s` }}
          />
        ))}
        {nodes.map((n, i) => (
          <g key={i}>
            <circle cx={n.x} cy={n.y} r={n.r + 4} fill="url(#nodeGrad)" opacity={n.crit ? 0.3 : 0.12} />
            <circle
              cx={n.x}
              cy={n.y}
              r={n.r}
              fill={n.crit ? "url(#nodeGrad)" : "#27272a"}
              stroke={n.crit ? "#6366F1" : "rgba(255,255,255,0.2)"}
              strokeWidth="1"
            />
          </g>
        ))}
      </svg>
      <div className="absolute bottom-2 right-3 px-1.5 py-0.5 text-[9px] font-mono text-white/40 bg-black/40 rounded border border-white/10">
        100% · live
      </div>
    </div>
  );
}
