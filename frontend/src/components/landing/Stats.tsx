import { animate, motion, useInView, useMotionValue, useTransform } from "framer-motion";
import { useEffect, useRef } from "react";

const STATS = [
  { value: 240000, suffix: "+", label: "CVEs indexed", note: "live NVD sync" },
  { value: 99.99, suffix: "%", label: "API uptime", note: "last 90 days", decimals: 2 },
  { value: 38, suffix: "ms", label: "Median query", note: "p50 globally" },
  { value: 4, suffix: "", label: "Compliance frameworks", note: "SOC 2, PCI, HIPAA, NIST" },
];

const LOGOS = ["NIST", "MITRE", "CVE", "CWE", "OWASP", "FIRST", "CISA", "ENISA", "NVD"];

export function Stats() {
  return (
    <section className="relative py-20 sm:py-28">
      <div className="max-w-7xl mx-auto px-5 sm:px-8">
        {/* Counter row */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-px rounded-2xl overflow-hidden border border-white/[0.06] bg-white/[0.02]">
          {STATS.map((s, i) => (
            <Counter key={i} {...s} />
          ))}
        </div>

        {/* Logo marquee */}
        <div className="mt-16">
          <p className="text-center text-[11.5px] tracking-[0.2em] uppercase text-white/35 font-medium">
            Aligned with the security standards that matter
          </p>
          <div className="relative mt-6 overflow-hidden [mask-image:linear-gradient(90deg,transparent,#000_15%,#000_85%,transparent)]">
            <div className="flex gap-14 animate-marquee w-max">
              {[...LOGOS, ...LOGOS, ...LOGOS].map((l, i) => (
                <div key={i} className="text-[22px] sm:text-[26px] font-bold tracking-tight text-white/40 hover:text-white/70 transition">
                  {l}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function Counter({
  value,
  suffix,
  label,
  note,
  decimals = 0,
}: {
  value: number;
  suffix: string;
  label: string;
  note: string;
  decimals?: number;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, amount: 0.6 });
  const mv = useMotionValue(0);
  const display = useTransform(mv, (v) => {
    if (v >= 1000) return Math.round(v).toLocaleString();
    return v.toFixed(decimals);
  });

  useEffect(() => {
    if (!inView) return;
    const controls = animate(mv, value, { duration: 2.2, ease: [0.16, 1, 0.3, 1] });
    return controls.stop;
  }, [inView, mv, value]);

  return (
    <div ref={ref} className="bg-[#09090B] p-7 sm:p-8">
      <div className="flex items-baseline gap-1">
        <motion.span className="text-3xl sm:text-5xl font-light tracking-tight text-gradient-brand">
          {display}
        </motion.span>
        <span className="text-2xl sm:text-3xl font-light text-gradient-brand">{suffix}</span>
      </div>
      <div className="mt-3 text-[13px] font-medium text-white">{label}</div>
      <div className="text-[11.5px] text-white/40 mt-0.5">{note}</div>
    </div>
  );
}
