import { motion } from "framer-motion";
import { ArrowRight, Activity, FileCheck, Shield } from "lucide-react";
import { Link } from "react-router-dom";
import { DashboardMockup } from "./DashboardMockup";
import { SectionHeader } from "./Features";

export function DashboardSection() {
  return (
    <section id="dashboard" className="relative py-24 sm:py-32">
      <div className="max-w-7xl mx-auto px-5 sm:px-8">
        <SectionHeader
          eyebrow="Live Demo"
          title={<>The console your <span className="text-gradient-brand">security team will live in</span></>}
          subtitle="Every CVE, every chain, every compliance gap — surfaced with operational clarity. No tab-hopping required."
        />

        <motion.div
          initial={{ opacity: 0, y: 40 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.15 }}
          transition={{ duration: 0.9, ease: [0.16, 1, 0.3, 1] }}
          className="relative mt-14"
        >
          <div
            aria-hidden
            className="absolute -inset-x-12 -top-10 -bottom-16 -z-10"
            style={{
              background:
                "radial-gradient(ellipse 60% 50% at 50% 50%, rgba(59,130,246,0.22), transparent 65%), radial-gradient(ellipse 60% 50% at 50% 70%, rgba(139,92,246,0.18), transparent 70%)",
              filter: "blur(40px)",
            }}
          />
          <div className="rounded-2xl overflow-hidden border border-white/[0.08] shadow-[0_40px_120px_-20px_rgba(99,102,241,0.4)]">
            <DashboardMockup />
          </div>

          {/* Floating chips */}
          <FloatChip
            className="hidden lg:flex absolute -left-10 top-32"
            icon={<Activity className="w-3.5 h-3.5 text-blue-300" />}
            title="CVE-2024-21413"
            subtitle="CVSS 9.8 · Outlook RCE"
            tag="Critical"
            tagColor="blue"
          />
          <FloatChip
            className="hidden lg:flex absolute -right-12 top-44"
            icon={<FileCheck className="w-3.5 h-3.5 text-amber-300" />}
            title="SOC 2 — CC7.1"
            subtitle="100% degraded · 296 CVEs"
            tag="Drift"
            tagColor="amber"
          />
          <FloatChip
            className="hidden lg:flex absolute -left-8 bottom-40"
            icon={<Shield className="w-3.5 h-3.5 text-emerald-300" />}
            title="3 mitigations applied"
            subtitle="Risk score −12 pts"
            tag="Auto"
            tagColor="emerald"
          />
        </motion.div>

        <div className="mt-12 flex justify-center">
          <Link
            to="/login"
            className="inline-flex items-center gap-2 px-5 py-3 text-[14px] font-medium text-white bg-gradient-brand rounded-xl btn-primary-glow"
          >
            Explore Full Dashboard <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      </div>
    </section>
  );
}

function FloatChip({
  className,
  icon,
  title,
  subtitle,
  tag,
  tagColor,
}: {
  className?: string;
  icon: React.ReactNode;
  title: string;
  subtitle: string;
  tag: string;
  tagColor: "blue" | "amber" | "emerald";
}) {
  const tone = {
    blue: "bg-blue-500/15 text-blue-200 border-blue-500/30",
    amber: "bg-amber-500/15 text-amber-200 border-amber-500/30",
    emerald: "bg-emerald-500/15 text-emerald-200 border-emerald-500/30",
  }[tagColor];
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.92 }}
      whileInView={{ opacity: 1, scale: 1 }}
      viewport={{ once: true }}
      transition={{ duration: 0.7, delay: 0.4 }}
      className={`${className} items-center gap-3 glass rounded-xl px-3.5 py-3 shadow-[0_20px_60px_-15px_rgba(0,0,0,0.7)]`}
    >
      <div className="w-8 h-8 rounded-lg bg-white/[0.04] border border-white/10 flex items-center justify-center">
        {icon}
      </div>
      <div>
        <div className="flex items-center gap-2">
          <div className="text-[12px] font-medium text-white">{title}</div>
          <span className={`px-1.5 py-0.5 text-[9px] font-semibold rounded border ${tone}`}>{tag}</span>
        </div>
        <div className="text-[10.5px] text-white/45 mt-0.5">{subtitle}</div>
      </div>
    </motion.div>
  );
}
