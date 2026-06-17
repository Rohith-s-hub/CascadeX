import { motion } from "framer-motion";
import { Activity, AlertTriangle, FileCheck, Network, Search, Shield, TrendingUp, Zap } from "lucide-react";

export function Features() {
  return (
    <section id="features" className="relative py-24 sm:py-32">
      <div className="max-w-7xl mx-auto px-5 sm:px-8">
        <SectionHeader
          eyebrow="Platform"
          title={
            <>
              Everything you need for{" "}
              <span className="text-gradient-brand">vulnerability intelligence</span>
            </>
          }
          subtitle="Eight purpose-built modules wired to the NVD, your asset inventory, and the compliance frameworks your auditors care about."
        />

        <div className="mt-14 grid grid-cols-1 md:grid-cols-3 gap-4 auto-rows-[minmax(220px,auto)]">
          {/* Cascade Graph - 2 col tall */}
          <Card className="md:col-span-2 md:row-span-2 p-7" gradient>
            <FeatureHeader
              icon={<Network className="w-4 h-4" />}
              title="CVE Cascade Graph"
              desc="Visualize how vulnerabilities chain across vendors, products and assets. See blast radius, kill-chain phase and infrastructure dependencies in one interactive graph."
            />
            <div className="mt-6 flex-1 min-h-[220px] relative rounded-xl bg-black/40 border border-white/[0.06] overflow-hidden">
              <CascadeMini />
            </div>
          </Card>

          {/* Compliance */}
          <Card className="p-6">
            <FeatureHeader
              icon={<FileCheck className="w-4 h-4" />}
              title="Compliance Assessment"
              desc="Continuous posture scoring for SOC 2, PCI DSS v4.0, HIPAA and NIST 800-53 Rev 5."
            />
            <div className="mt-5 grid grid-cols-2 gap-1.5 text-[10.5px]">
              {[
                ["SOC 2", "10%", "blue"],
                ["PCI DSS", "6%", "blue"],
                ["HIPAA", "14%", "violet"],
                ["NIST", "0%", "blue"],
              ].map(([k, v, t]) => (
                <div key={k} className="px-2.5 py-2 rounded-md bg-white/[0.03] border border-white/[0.06] flex justify-between">
                  <span className="text-white/60">{k}</span>
                  <span className={t === "blue" ? "text-blue-300" : "text-violet-300"}>{v}</span>
                </div>
              ))}
            </div>
          </Card>

          {/* Active Scan */}
          <Card className="p-6">
            <FeatureHeader
              icon={<Search className="w-4 h-4" />}
              title="Active CVE Scan"
              desc="Tune severity, lookback window and keyword targeting. Smart caching keeps the NVD happy."
            />
            <div className="mt-5 space-y-1.5 font-mono text-[10.5px]">
              {[
                { id: "CVE-2024-3094", sev: "10.0", t: "blue" },
                { id: "CVE-2024-21413", sev: "9.8", t: "blue" },
                { id: "CVE-2024-1086", sev: "7.8", t: "violet" },
              ].map((r) => (
                <div key={r.id} className="flex items-center justify-between px-2.5 py-1.5 bg-white/[0.03] border border-white/[0.06] rounded">
                  <span className="text-white/75">{r.id}</span>
                  <span className={`px-1.5 py-0.5 rounded text-[9.5px] font-semibold ${r.t === "blue" ? "bg-blue-500/15 text-blue-300" : "bg-violet-500/15 text-violet-300"}`}>
                    {r.sev}
                  </span>
                </div>
              ))}
            </div>
          </Card>

          {/* Real-time alerts */}
          <Card className="p-6">
            <FeatureHeader
              icon={<AlertTriangle className="w-4 h-4" />}
              title="Real-time Alerts"
              desc="Get notified the moment a critical CVE drops. Slack, email, webhook or PagerDuty."
            />
            <div className="mt-5 flex items-center gap-2">
              <span className="relative flex h-2.5 w-2.5">
                <span className="absolute inset-0 rounded-full bg-blue-500 animate-ping-slow opacity-75" />
                <span className="relative w-2.5 h-2.5 rounded-full bg-blue-500" />
              </span>
              <span className="text-[12px] text-white/70">7 active critical alerts</span>
            </div>
          </Card>

          {/* CPE Matching - wide */}
          <Card className="md:col-span-2 p-6">
            <FeatureHeader
              icon={<Shield className="w-4 h-4" />}
              title="CPE Asset Matching"
              desc="Map every CVE to the exact software and hardware in your fleet using CPE 2.3 matching."
            />
            <div className="mt-5 flex flex-wrap gap-1.5 font-mono text-[10.5px]">
              {[
                "cpe:2.3:a:apache:log4j:2.14.1",
                "cpe:2.3:o:linux:kernel:6.1.0",
                "cpe:2.3:a:openssl:openssl:3.0.7",
                "cpe:2.3:a:nginx:nginx:1.24.0",
              ].map((c) => (
                <span key={c} className="px-2 py-1 bg-white/[0.03] border border-white/[0.06] rounded text-white/60">
                  {c}
                </span>
              ))}
            </div>
          </Card>

          {/* Trend */}
          <Card className="p-6">
            <FeatureHeader
              icon={<TrendingUp className="w-4 h-4" />}
              title="Trend Analytics"
              desc="Visualize vulnerability velocity, MTTR and risk drift over time."
            />
            <div className="mt-5 h-16">
              <TrendMini />
            </div>
          </Card>

          {/* API */}
          <Card className="md:col-span-2 p-6">
            <FeatureHeader
              icon={<Zap className="w-4 h-4" />}
              title="REST API & Integrations"
              desc="A clean RESTful API with smart caching, NVD rate-limit handling and first-class CI/CD integrations."
            />
            <div className="mt-5 rounded-lg bg-black/50 border border-white/[0.06] overflow-hidden">
              <div className="px-3 py-1.5 border-b border-white/[0.06] flex items-center gap-2 text-[10px] text-white/40 font-mono">
                <Activity className="w-3 h-3" /> POST /v1/cascade/scan
              </div>
              <pre className="p-3 text-[11px] font-mono leading-relaxed text-white/80 overflow-x-auto">
{`{
  "asset": "prod-edge-01",
  "cpe": "cpe:2.3:a:nginx:nginx:1.24.0",
  "lookback": "30d",
  "frameworks": ["soc2", "pci-dss"]
}`}
              </pre>
            </div>
          </Card>
        </div>
      </div>
    </section>
  );
}

export function SectionHeader({
  eyebrow,
  title,
  subtitle,
}: {
  eyebrow: string;
  title: React.ReactNode;
  subtitle: string;
}) {
  return (
    <div className="max-w-3xl mx-auto text-center">
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, amount: 0.6 }}
        transition={{ duration: 0.6 }}
        className="text-[11px] font-semibold tracking-[0.2em] uppercase text-blue-300/90"
      >
        {eyebrow}
      </motion.div>
      <motion.h2
        initial={{ opacity: 0, y: 16 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, amount: 0.6 }}
        transition={{ duration: 0.7, delay: 0.05 }}
        className="mt-3 text-3xl sm:text-5xl font-semibold tracking-tight text-gradient leading-tight"
      >
        {title}
      </motion.h2>
      <motion.p
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        viewport={{ once: true, amount: 0.6 }}
        transition={{ duration: 0.7, delay: 0.15 }}
        className="mt-5 text-[15px] sm:text-[16.5px] text-white/55 leading-relaxed"
      >
        {subtitle}
      </motion.p>
    </div>
  );
}

function Card({
  children,
  className = "",
  gradient = false,
}: {
  children: React.ReactNode;
  className?: string;
  gradient?: boolean;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 24 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.2 }}
      transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
      className={`card-hover relative rounded-2xl border border-white/[0.07] flex flex-col ${
        gradient
          ? "bg-gradient-to-br from-blue-500/[0.06] via-white/[0.02] to-violet-500/[0.06]"
          : "bg-white/[0.02]"
      } ${className}`}
    >
      {children}
    </motion.div>
  );
}

function FeatureHeader({
  icon,
  title,
  desc,
}: {
  icon: React.ReactNode;
  title: string;
  desc: string;
}) {
  return (
    <div>
      <div className="flex items-center gap-2.5">
        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500/25 to-violet-500/20 border border-blue-500/25 flex items-center justify-center text-blue-200">
          {icon}
        </div>
        <h3 className="text-[15px] font-semibold text-white">{title}</h3>
      </div>
      <p className="mt-3 text-[13.5px] text-white/55 leading-relaxed">{desc}</p>
    </div>
  );
}

function CascadeMini() {
  // Decorative larger graph
  const nodes = [
    { x: 60, y: 60, r: 9 }, { x: 60, y: 140, r: 8 }, { x: 60, y: 220, r: 7 },
    { x: 180, y: 100, r: 11, c: true }, { x: 180, y: 200, r: 10, c: true },
    { x: 320, y: 60, r: 9, c: true }, { x: 320, y: 150, r: 13, c: true }, { x: 320, y: 240, r: 9, c: true },
    { x: 460, y: 100, r: 10 }, { x: 460, y: 200, r: 11, c: true },
    { x: 600, y: 150, r: 14, c: true },
  ];
  const edges = [
    [0, 3], [1, 3], [1, 4], [2, 4],
    [3, 5], [3, 6], [4, 6], [4, 7],
    [5, 8], [6, 8], [6, 9], [7, 9],
    [8, 10], [9, 10],
  ];
  return (
    <>
      <div className="absolute inset-0 dot-bg opacity-30" />
      <svg viewBox="0 0 660 300" className="absolute inset-0 w-full h-full" preserveAspectRatio="xMidYMid meet">
        <defs>
          <linearGradient id="e2" x1="0" x2="1">
            <stop offset="0%" stopColor="#3B82F6" stopOpacity="0.1" />
            <stop offset="50%" stopColor="#8B5CF6" stopOpacity="0.75" />
            <stop offset="100%" stopColor="#3B82F6" stopOpacity="0.1" />
          </linearGradient>
          <radialGradient id="n2">
            <stop offset="0%" stopColor="#A78BFA" />
            <stop offset="100%" stopColor="#3B82F6" />
          </radialGradient>
        </defs>
        {edges.map(([a, b], i) => (
          <line
            key={i}
            x1={nodes[a].x} y1={nodes[a].y}
            x2={nodes[b].x} y2={nodes[b].y}
            stroke="url(#e2)" strokeWidth="1.2"
            strokeDasharray="5 4"
            className="animate-data-flow"
            style={{ animationDelay: `${i * 0.12}s` }}
          />
        ))}
        {nodes.map((n, i) => (
          <g key={i}>
            <circle cx={n.x} cy={n.y} r={n.r + 6} fill="url(#n2)" opacity={n.c ? 0.2 : 0.08} />
            <circle cx={n.x} cy={n.y} r={n.r}
              fill={n.c ? "url(#n2)" : "#27272a"}
              stroke={n.c ? "#6366F1" : "rgba(255,255,255,0.18)"}
              strokeWidth="1"
            />
          </g>
        ))}
      </svg>
      <div className="absolute top-2.5 left-3 px-1.5 py-0.5 text-[9.5px] font-mono text-blue-200 bg-blue-500/15 border border-blue-500/30 rounded">
        178 critical chains
      </div>
      <div className="absolute bottom-2.5 right-3 flex gap-1.5">
        {["Vendor", "Product", "CVE", "Asset"].map((l) => (
          <span key={l} className="px-1.5 py-0.5 text-[9px] font-mono text-white/50 bg-black/40 border border-white/10 rounded">
            {l}
          </span>
        ))}
      </div>
    </>
  );
}

function TrendMini() {
  const points = [38, 42, 35, 50, 48, 60, 55, 72, 68, 80, 75, 88];
  const max = 100;
  const path = points
    .map((p, i) => {
      const x = (i / (points.length - 1)) * 100;
      const y = 100 - (p / max) * 100;
      return `${i === 0 ? "M" : "L"} ${x} ${y}`;
    })
    .join(" ");
  return (
    <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="w-full h-full">
      <defs>
        <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#6366F1" stopOpacity="0.45" />
          <stop offset="100%" stopColor="#3B82F6" stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={`${path} L 100 100 L 0 100 Z`} fill="url(#trendFill)" />
      <path d={path} stroke="#A78BFA" strokeWidth="1.6" fill="none" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}
