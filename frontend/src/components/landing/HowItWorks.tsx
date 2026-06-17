import { motion } from "framer-motion";
import { Plug, Radar, Target } from "lucide-react";
import { SectionHeader } from "./Features";

const STEPS = [
  {
    icon: <Plug className="w-5 h-5" />,
    title: "Connect",
    desc: "Plug into the NVD API and your asset inventory in under a minute. Smart caching, automatic rate-limit handling, zero infra to manage.",
    code: "$ cascadex connect --source nvd",
  },
  {
    icon: <Radar className="w-5 h-5" />,
    title: "Scan",
    desc: "We continuously fetch new CVEs, score them via CVSS v3.1, match them against your CPE inventory and chain them into attack paths.",
    code: "→ 240,184 CVEs · 38 vendors · 90 products",
  },
  {
    icon: <Target className="w-5 h-5" />,
    title: "Act",
    desc: "Prioritize by exploitability and blast radius. Open tickets, trigger workflows, and prove compliance — all from one console.",
    code: "✓ 3 mitigations applied · SOC 2 +6%",
  },
];

export function HowItWorks() {
  return (
    <section id="how" className="relative py-24 sm:py-32 border-y border-white/[0.05] bg-[#0b0b0e]">
      <div aria-hidden className="absolute inset-0 dot-bg opacity-[0.5] [mask-image:radial-gradient(ellipse_at_center,black_30%,transparent_70%)]" />
      <div className="relative max-w-7xl mx-auto px-5 sm:px-8">
        <SectionHeader
          eyebrow="Workflow"
          title={<>From CVE to mitigation <span className="text-gradient-brand">in three steps</span></>}
          subtitle="A pragmatic workflow built for security engineers, DevOps leads and compliance auditors."
        />

        <div className="mt-16 relative">
          {/* Connecting line */}
          <div aria-hidden className="hidden md:block absolute top-7 left-[8%] right-[8%] h-px">
            <svg className="w-full h-full" viewBox="0 0 100 1" preserveAspectRatio="none">
              <line x1="0" y1="0.5" x2="100" y2="0.5" stroke="url(#lineGrad)" strokeWidth="1" strokeDasharray="3 3" />
              <defs>
                <linearGradient id="lineGrad" x1="0" x2="1">
                  <stop offset="0%" stopColor="#3B82F6" stopOpacity="0" />
                  <stop offset="50%" stopColor="#8B5CF6" stopOpacity="0.85" />
                  <stop offset="100%" stopColor="#3B82F6" stopOpacity="0" />
                </linearGradient>
              </defs>
            </svg>
          </div>

          <div className="grid md:grid-cols-3 gap-6 md:gap-8">
            {STEPS.map((s, i) => (
              <motion.div
                key={s.title}
                initial={{ opacity: 0, y: 24 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.4 }}
                transition={{ duration: 0.6, delay: i * 0.12, ease: [0.16, 1, 0.3, 1] }}
                className="relative"
              >
                {/* Number badge */}
                <div className="relative z-10 flex justify-center md:justify-start">
                  <div className="relative w-14 h-14 rounded-2xl bg-[#0b0b0e] border border-white/10 flex items-center justify-center text-blue-300">
                    {s.icon}
                    <div className="absolute -top-1.5 -right-1.5 w-5 h-5 rounded-full bg-gradient-brand text-[10px] font-bold text-white flex items-center justify-center">
                      {i + 1}
                    </div>
                  </div>
                </div>
                <div className="mt-6 text-center md:text-left">
                  <h3 className="text-xl font-semibold text-white">{s.title}</h3>
                  <p className="mt-2.5 text-[14px] text-white/55 leading-relaxed">{s.desc}</p>
                  <div className="mt-4 inline-flex items-center px-3 py-2 rounded-md bg-black/40 border border-white/[0.06] font-mono text-[11px] text-white/65">
                    {s.code}
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
