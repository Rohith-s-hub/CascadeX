import { motion } from "framer-motion";
import { ArrowRight, Play, Sparkles } from "lucide-react";
import { Link } from "react-router-dom";
import { DashboardMockup } from "./DashboardMockup";

export function Hero() {
  return (
    <section className="relative pt-32 pb-16 sm:pt-40 sm:pb-24 overflow-hidden">
      {/* Background mesh */}
      <div aria-hidden className="absolute inset-0 -z-10">
        <div className="absolute inset-0 grid-bg opacity-[0.35] [mask-image:radial-gradient(ellipse_at_center,black_30%,transparent_75%)]" />
        <div className="absolute top-[-10%] left-[10%] w-[520px] h-[520px] rounded-full bg-blue-500/15 blur-[140px] animate-float-slow" />
        <div className="absolute top-[20%] right-[5%] w-[420px] h-[420px] rounded-full bg-violet-500/15 blur-[140px] animate-float-slower" />
        <div className="absolute top-[50%] left-[40%] w-[380px] h-[380px] rounded-full bg-indigo-500/12 blur-[140px] animate-float-slow" />
        <div className="absolute inset-0 noise opacity-[0.025]" />
      </div>

      <div className="max-w-7xl mx-auto px-5 sm:px-8">
        {/* Badge */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
          className="flex justify-center"
        >
          <a
            href="#features"
            className="group inline-flex items-center gap-2 pl-1.5 pr-3 py-1.5 text-[12px] glass rounded-full hover:border-white/20 transition"
          >
            <span className="px-2 py-0.5 text-[10px] font-semibold text-blue-200 bg-blue-500/15 border border-blue-500/25 rounded-full flex items-center gap-1">
              <Sparkles className="w-2.5 h-2.5" /> NEW
            </span>
            <span className="shimmer-text font-medium">v4.0 · Cascade Graph + Compliance Engine</span>
            <ArrowRight className="w-3 h-3 text-white/50 group-hover:translate-x-0.5 transition" />
          </a>
        </motion.div>

        {/* Headline */}
        <motion.h1
          initial={{ opacity: 0, y: 24 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.05, ease: [0.16, 1, 0.3, 1] }}
          className="mt-6 text-center font-semibold tracking-tight leading-[1.02] text-[44px] sm:text-[64px] lg:text-[80px]"
        >
          <span className="text-gradient block">See the chain.</span>
          <span className="block">
            <span className="text-gradient-brand">Break</span>{" "}
            <span className="text-gradient">the breach.</span>
          </span>
        </motion.h1>

        {/* Subheadline */}
        <motion.p
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.15 }}
          className="mt-6 max-w-2xl mx-auto text-center text-[15px] sm:text-[17px] text-white/60 leading-relaxed"
        >
          Full-spectrum vulnerability management. Visualize attack chains across vendors, products and assets —
          assess SOC 2, PCI DSS, HIPAA & NIST compliance — and remediate critical CVEs before attackers chain them.
        </motion.p>

        {/* CTAs */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.25 }}
          className="mt-9 flex flex-col sm:flex-row items-center justify-center gap-3"
        >
          <Link
            to="/register"
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-5 py-3 text-[14px] font-medium text-white bg-gradient-brand rounded-xl btn-primary-glow"
          >
            Start free <ArrowRight className="w-4 h-4" />
          </Link>
          <Link
            to="/dashboard"
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-5 py-3 text-[14px] font-medium text-white/85 bg-white/[0.04] border border-white/10 hover:bg-white/[0.07] hover:border-white/20 rounded-xl transition"
          >
            <Play className="w-3.5 h-3.5 fill-white/85" /> View Live Demo
          </Link>
        </motion.div>

        {/* Trust indicators */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.7, delay: 0.4 }}
          className="mt-7 flex flex-wrap items-center justify-center gap-x-5 gap-y-2 text-[12px] text-white/45"
        >
          {["Real-time NVD sync", "CVSS v3.1 scoring", "SOC 2 · PCI DSS · HIPAA · NIST", "Zero config"].map((t) => (
            <span key={t} className="flex items-center gap-1.5">
              <svg className="w-3 h-3 text-emerald-400" viewBox="0 0 12 12" fill="none">
                <path d="M2 6.5l2.5 2.5L10 3.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              {t}
            </span>
          ))}
        </motion.div>

        {/* Dashboard mockup */}
        <motion.div
          initial={{ opacity: 0, y: 60 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 1.1, delay: 0.45, ease: [0.16, 1, 0.3, 1] }}
          className="relative mt-16 sm:mt-20"
        >
          <div
            aria-hidden
            className="absolute -inset-x-10 -top-10 -bottom-20 -z-10"
            style={{
              background:
                "radial-gradient(ellipse 60% 50% at 50% 40%, rgba(59,130,246,0.28), transparent 70%), radial-gradient(ellipse 60% 50% at 50% 60%, rgba(139,92,246,0.2), transparent 70%)",
              filter: "blur(40px)",
            }}
          />
          <div
            className="rounded-2xl overflow-hidden border border-white/[0.08] shadow-[0_40px_120px_-20px_rgba(99,102,241,0.45)]"
            style={{ transform: "perspective(2400px) rotateX(2deg)" }}
          >
            <DashboardMockup />
          </div>

          {/* Floating chips */}
          <FloatingChip
            className="hidden md:flex absolute -left-4 lg:-left-12 top-1/4"
            color="blue"
            title="CVE-2024-3094"
            sub="CVSS 10.0 · Critical"
            delay={0.7}
          />
          <FloatingChip
            className="hidden md:flex absolute -right-4 lg:-right-10 top-12"
            color="violet"
            title="Compliance"
            sub="SOC 2 · 8% · drift detected"
            delay={0.9}
          />
          <FloatingChip
            className="hidden md:flex absolute -right-2 lg:-right-8 bottom-16"
            color="emerald"
            title="Auto-mitigation"
            sub="3 patches applied"
            delay={1.1}
          />
        </motion.div>
      </div>
    </section>
  );
}

function FloatingChip({
  className,
  color,
  title,
  sub,
  delay,
}: {
  className?: string;
  color: "blue" | "violet" | "emerald";
  title: string;
  sub: string;
  delay: number;
}) {
  const tone = {
    blue: "bg-blue-500",
    violet: "bg-violet-400",
    emerald: "bg-emerald-400",
  }[color];
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.7, delay }}
      className={`${className} items-center gap-2.5 glass rounded-xl px-3 py-2.5 shadow-[0_10px_40px_-10px_rgba(0,0,0,0.6)]`}
    >
      <span className="relative flex h-2 w-2">
        <span className={`absolute inset-0 rounded-full ${tone} animate-ping-slow opacity-75`} />
        <span className={`relative w-2 h-2 rounded-full ${tone}`} />
      </span>
      <div>
        <div className="text-[11.5px] font-mono text-white/90">{title}</div>
        <div className="text-[10px] text-white/45">{sub}</div>
      </div>
    </motion.div>
  );
}
