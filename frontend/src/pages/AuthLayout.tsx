import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { Logo } from "../components/landing/Logo";

export function AuthLayout({
  children,
  side,
}: {
  children: React.ReactNode;
  side: "login" | "register";
}) {
  return (
    <div className="relative min-h-screen flex flex-col lg:flex-row bg-[#09090B] text-white overflow-hidden">
      {/* Background mesh */}
      <div aria-hidden className="absolute inset-0 -z-10">
        <div className="absolute inset-0 grid-bg opacity-[0.3] [mask-image:radial-gradient(ellipse_at_center,black_30%,transparent_75%)]" />
        <div className="absolute -top-32 -left-32 w-[520px] h-[520px] rounded-full bg-blue-500/15 blur-[140px] animate-float-slow" />
        <div className="absolute top-1/3 -right-32 w-[420px] h-[420px] rounded-full bg-violet-500/15 blur-[140px] animate-float-slower" />
        <div className="absolute bottom-0 left-1/3 w-[380px] h-[380px] rounded-full bg-indigo-500/12 blur-[140px] animate-float-slow" />
        <div className="absolute inset-0 noise opacity-[0.025]" />
      </div>

      {/* Top bar */}
      <div className="absolute top-0 left-0 right-0 z-20 px-5 sm:px-8 h-16 flex items-center justify-between">
        <Link to="/" className="flex items-center" aria-label="Back to home">
          <Logo size="sm" />
        </Link>
        <Link
          to={side === "login" ? "/register" : "/login"}
          className="text-[13px] text-white/60 hover:text-white transition flex items-center gap-1.5"
        >
          {side === "login" ? "Don't have an account?" : "Already have an account?"}
          <span className="text-blue-400 font-medium">
            {side === "login" ? "Sign up" : "Sign in"}
          </span>
        </Link>
      </div>

      {/* Form column */}
      <div className="relative flex-1 flex items-center justify-center px-5 sm:px-8 py-24">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
          className="w-full max-w-[420px]"
        >
          {children}
        </motion.div>
      </div>

      {/* Side panel — preview */}
      <aside className="relative hidden lg:flex flex-1 items-center justify-center border-l border-white/[0.05] bg-[#0b0b10] overflow-hidden">
        <div aria-hidden className="absolute inset-0 dot-bg opacity-[0.5] [mask-image:radial-gradient(ellipse_at_center,black_30%,transparent_70%)]" />
        <div aria-hidden className="absolute -top-40 -left-40 w-[560px] h-[560px] rounded-full bg-blue-500/10 blur-[160px]" />
        <div aria-hidden className="absolute -bottom-40 -right-40 w-[560px] h-[560px] rounded-full bg-violet-500/10 blur-[160px]" />

        <motion.div
          initial={{ opacity: 0, scale: 0.96 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.9, delay: 0.2, ease: [0.16, 1, 0.3, 1] }}
          className="relative max-w-md px-10"
        >
          <div className="inline-flex items-center gap-1.5 px-2.5 py-1 text-[10.5px] font-semibold text-blue-200 bg-blue-500/15 border border-blue-500/25 rounded-full">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" /> LIVE INTELLIGENCE
          </div>
          <h2 className="mt-6 text-3xl xl:text-4xl font-semibold tracking-tight leading-[1.1]">
            <span className="text-gradient">See the chain.</span>
            <br />
            <span className="text-gradient-brand">Break the breach.</span>
          </h2>
          <p className="mt-5 text-[14.5px] text-white/55 leading-relaxed">
            Full-spectrum vulnerability management for teams that can't afford
            to miss a CVE. Visualize attack chains, prove compliance, and
            remediate critical CVEs before attackers chain them.
          </p>

          <div className="mt-8 space-y-3">
            <FeatureRow title="CVE Cascade Graph" sub="Visualize attack chains across vendors and assets" />
            <FeatureRow title="Compliance Engine" sub="SOC 2 · PCI DSS · HIPAA · NIST 800-53" />
            <FeatureRow title="Real-time NVD sync" sub="240k+ CVEs · CVSS v3.1 · CPE 2.3 matching" />
          </div>

          <div className="mt-10 flex items-center gap-3 text-[12px] text-white/45">
            <div className="flex -space-x-2">
              <Avatar i={0} />
              <Avatar i={1} />
              <Avatar i={2} />
              <Avatar i={3} />
            </div>
            <div>Trusted by <b className="text-white/80">3,200+</b> security engineers</div>
          </div>
        </motion.div>
      </aside>
    </div>
  );
}

function FeatureRow({ title, sub }: { title: string; sub: string }) {
  return (
    <div className="flex items-start gap-3">
      <div className="mt-0.5 w-5 h-5 rounded-md bg-gradient-brand flex items-center justify-center flex-shrink-0">
        <svg className="w-3 h-3 text-white" viewBox="0 0 12 12" fill="none">
          <path d="M2 6.5l2.5 2.5L10 3.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </div>
      <div>
        <div className="text-[13.5px] font-medium text-white">{title}</div>
        <div className="text-[12.5px] text-white/50 mt-0.5">{sub}</div>
      </div>
    </div>
  );
}

function Avatar({ i }: { i: number }) {
  const palettes = [
    "from-blue-500 to-indigo-500",
    "from-violet-500 to-fuchsia-500",
    "from-cyan-500 to-blue-500",
    "from-indigo-500 to-violet-500",
  ];
  const initials = ["AK", "MR", "JS", "RP"];
  return (
    <div
      className={`w-7 h-7 rounded-full bg-gradient-to-br ${palettes[i]} border-2 border-[#0b0b10] flex items-center justify-center text-[9px] font-bold text-white shadow-sm`}
      aria-hidden
    >
      {initials[i]}
    </div>
  );
}
