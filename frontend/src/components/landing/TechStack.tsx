import { motion } from "framer-motion";
import { Cpu, Database, Globe, Network } from "lucide-react";
import { SectionHeader } from "./Features";

const BADGES = [
  "Python 3.12",
  "FastAPI",
  "PostgreSQL",
  "Redis",
  "NVD API v2.0",
  "CVSS v3.1",
  "CPE 2.3",
  "WebSockets",
  "React 18",
  "TypeScript",
];

export function TechStack() {
  return (
    <section id="api" className="relative py-24 sm:py-32 border-y border-white/[0.05] bg-[#0b0b0e]">
      <div aria-hidden className="absolute inset-0 grid-bg opacity-[0.25] [mask-image:radial-gradient(ellipse_at_center,black_30%,transparent_70%)]" />
      <div className="relative max-w-7xl mx-auto px-5 sm:px-8">
        <SectionHeader
          eyebrow="Architecture"
          title={<>Built on <span className="text-gradient-brand">battle-tested foundations</span></>}
          subtitle="A pragmatic stack: smart caching layer in front of the NVD, a real-time graph engine, and a reactive frontend."
        />

        {/* Architecture diagram */}
        <motion.div
          initial={{ opacity: 0, y: 24 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.3 }}
          transition={{ duration: 0.8 }}
          className="mt-14 relative"
        >
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 relative">
            <ArchNode
              icon={<Database className="w-5 h-5" />}
              title="NVD API v2.0"
              subtitle="National Vulnerability Database"
              meta="240k+ CVEs · live"
            />
            <ArchNode
              icon={<Cpu className="w-5 h-5" />}
              title="Cascade Engine"
              subtitle="Graph correlation + CVSS + CPE matching"
              meta="38ms p50 · stateless"
              center
            />
            <ArchNode
              icon={<Globe className="w-5 h-5" />}
              title="Intelligence Console"
              subtitle="Real-time WebSocket dashboard"
              meta="React · TypeScript"
            />

            {/* Animated connecting lines (desktop only) */}
            <svg
              aria-hidden
              className="hidden md:block absolute inset-0 w-full h-full pointer-events-none"
              viewBox="0 0 100 30"
              preserveAspectRatio="none"
            >
              <defs>
                <linearGradient id="archLine" x1="0" x2="1">
                  <stop offset="0%" stopColor="#3B82F6" stopOpacity="0" />
                  <stop offset="50%" stopColor="#8B5CF6" stopOpacity="0.9" />
                  <stop offset="100%" stopColor="#3B82F6" stopOpacity="0" />
                </linearGradient>
              </defs>
              <line
                x1="33" y1="15" x2="67" y2="15"
                stroke="url(#archLine)" strokeWidth="0.4"
                strokeDasharray="1.5 1"
                className="animate-data-flow"
              />
            </svg>
          </div>

          {/* Tech badges */}
          <div className="mt-10 flex flex-wrap items-center justify-center gap-2">
            {BADGES.map((b, i) => (
              <motion.span
                key={b}
                initial={{ opacity: 0, y: 8 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.4, delay: i * 0.04 }}
                className="px-3 py-1.5 text-[11.5px] font-mono text-white/65 bg-white/[0.03] border border-white/[0.08] rounded-full hover:text-white hover:border-white/20 transition"
              >
                {b}
              </motion.span>
            ))}
          </div>

          {/* Sample API trace */}
          <div className="mt-12 max-w-3xl mx-auto rounded-xl bg-black/50 border border-white/[0.08] overflow-hidden">
            <div className="px-4 py-2.5 border-b border-white/[0.06] flex items-center gap-2 text-[11px] text-white/55 font-mono">
              <Network className="w-3.5 h-3.5 text-blue-300" />
              <span className="text-white/80">trace</span>
              <span className="text-white/30">·</span>
              <span>cascade.scan</span>
              <span className="ml-auto px-1.5 py-0.5 text-[9.5px] font-semibold text-emerald-300 bg-emerald-500/15 border border-emerald-500/25 rounded">
                200 OK · 41ms
              </span>
            </div>
            <pre className="px-4 py-3 text-[11.5px] font-mono leading-relaxed text-white/75 overflow-x-auto">
{`→ GET    nvd.nist.gov/rest/json/cves/2.0    [cache HIT, 0ms]
→ MATCH  cpe:2.3:a:nginx:nginx:1.24.0       [12 CVEs]
→ SCORE  CVSS v3.1                          [median 7.4]
→ GRAPH  build cascade across 3 assets       [178 chains]
✓ EMIT   178 critical · 2 exploitable        [ws://broadcast]`}
            </pre>
          </div>
        </motion.div>
      </div>
    </section>
  );
}

function ArchNode({
  icon,
  title,
  subtitle,
  meta,
  center = false,
}: {
  icon: React.ReactNode;
  title: string;
  subtitle: string;
  meta: string;
  center?: boolean;
}) {
  return (
    <div className={`relative rounded-2xl p-6 border ${center ? "bg-gradient-to-br from-blue-500/[0.1] via-violet-500/[0.07] to-transparent border-blue-500/25" : "bg-white/[0.02] border-white/[0.07]"}`}>
      <div className={`w-11 h-11 rounded-xl flex items-center justify-center ${center ? "bg-gradient-brand text-white" : "bg-white/[0.04] border border-white/10 text-blue-200"}`}>
        {icon}
      </div>
      <div className="mt-4 text-[15px] font-semibold text-white">{title}</div>
      <div className="text-[12.5px] text-white/55 mt-1">{subtitle}</div>
      <div className="mt-3 inline-block px-2 py-0.5 text-[10px] font-mono text-white/50 bg-black/40 border border-white/10 rounded">
        {meta}
      </div>
      {center && (
        <div className="absolute top-3 right-3 flex items-center gap-1 text-[9.5px] font-semibold text-blue-300">
          <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
          CORE
        </div>
      )}
    </div>
  );
}
