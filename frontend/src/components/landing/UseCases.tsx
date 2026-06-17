import { motion } from "framer-motion";
import { SectionHeader } from "./Features";

const TESTIMONIALS = [
  {
    quote:
      "The cascade graph changed how we triage. We can finally show execs which CVEs actually chain into a breach — not just a wall of CVSS scores.",
    name: "Priya Raman",
    role: "Staff Security Engineer",
    org: "FinTech · Series D",
  },
  {
    quote:
      "We dropped Tenable for CascadeX. The compliance module alone shaved two weeks off our SOC 2 renewal. Asset-relevant scoring is the killer feature.",
    name: "Marcus Lévesque",
    role: "Head of DevSecOps",
    org: "B2B SaaS · 1,200 hosts",
  },
  {
    quote:
      "Clean API, smart NVD caching, no rate-limit headaches. We piped it into our CI in an afternoon. Our PR checks now block builds with exploitable deps.",
    name: "Aiyana Whitehorse",
    role: "Platform Lead",
    org: "Healthcare · HIPAA",
  },
];

const USE_CASES = [
  "Enterprise security teams",
  "Bug bounty hunters",
  "Compliance auditors",
  "DevSecOps pipelines",
  "Pentest reporting",
  "Vulnerability research",
];

export function UseCases() {
  return (
    <section className="relative py-24 sm:py-32">
      <div className="max-w-7xl mx-auto px-5 sm:px-8">
        <SectionHeader
          eyebrow="Customers"
          title={<>Trusted by teams that <span className="text-gradient-brand">can't afford to miss a CVE</span></>}
          subtitle="From SOC 2 readiness to live production triage — CascadeX scales from your laptop to the SOC."
        />

        <div className="mt-14 grid md:grid-cols-3 gap-4">
          {TESTIMONIALS.map((t, i) => (
            <motion.figure
              key={t.name}
              initial={{ opacity: 0, y: 24 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.3 }}
              transition={{ duration: 0.6, delay: i * 0.1 }}
              className="card-hover relative rounded-2xl bg-white/[0.02] border border-white/[0.07] p-7"
            >
              <svg className="w-7 h-7 text-blue-400/60" viewBox="0 0 24 24" fill="currentColor" aria-hidden>
                <path d="M9.6 8C5.4 8 4 11.5 4 14v6h6v-6H7c0-2 1.2-3 2.6-3V8zm10 0c-4.2 0-5.6 3.5-5.6 6v6h6v-6h-3c0-2 1.2-3 2.6-3V8z" />
              </svg>
              <blockquote className="mt-4 text-[14.5px] text-white/80 leading-relaxed">
                "{t.quote}"
              </blockquote>
              <figcaption className="mt-6 pt-5 border-t border-white/[0.06]">
                <div className="text-[13px] font-semibold text-white">{t.name}</div>
                <div className="text-[12px] text-white/50 mt-0.5">
                  {t.role} · <span className="text-white/35">{t.org}</span>
                </div>
              </figcaption>
            </motion.figure>
          ))}
        </div>

        {/* Use case pills */}
        <div className="mt-14 text-center">
          <div className="text-[11px] uppercase tracking-[0.2em] text-white/35 font-medium">Built for</div>
          <div className="mt-5 flex flex-wrap items-center justify-center gap-2">
            {USE_CASES.map((u) => (
              <span
                key={u}
                className="px-3.5 py-1.5 text-[12.5px] text-white/70 bg-white/[0.03] border border-white/[0.08] rounded-full hover:text-white hover:border-blue-500/40 hover:bg-blue-500/[0.06] transition"
              >
                {u}
              </span>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
