import { motion } from "framer-motion";
import { ArrowRight } from "lucide-react";
import { Link } from "react-router-dom";

export function CTA() {
  return (
    <section id="compliance" className="relative py-24 sm:py-32">
      <div className="max-w-6xl mx-auto px-5 sm:px-8">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.3 }}
          transition={{ duration: 0.8 }}
          className="relative overflow-hidden rounded-3xl border border-white/[0.08] bg-gradient-to-br from-blue-500/[0.08] via-[#0d0d12] to-violet-500/[0.08] px-6 py-16 sm:px-16 sm:py-24"
        >
          {/* Background effects */}
          <div aria-hidden className="absolute inset-0 grid-bg opacity-[0.3] [mask-image:radial-gradient(ellipse_at_center,black_30%,transparent_75%)]" />
          <div aria-hidden className="absolute -top-32 -left-32 w-[420px] h-[420px] rounded-full bg-blue-500/20 blur-[120px] animate-float-slow" />
          <div aria-hidden className="absolute -bottom-32 -right-32 w-[420px] h-[420px] rounded-full bg-violet-500/20 blur-[120px] animate-float-slower" />

          <div className="relative text-center">
            <div className="inline-flex items-center gap-2 px-3 py-1 text-[11px] glass rounded-full">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-white/70 font-medium">Free tier · No credit card</span>
            </div>
            <h2 className="mt-6 text-4xl sm:text-6xl font-semibold tracking-tight leading-[1.05]">
              <span className="text-gradient">Stay ahead of the next</span>
              <br />
              <span className="text-gradient-brand">critical vulnerability.</span>
            </h2>
            <p className="mt-6 max-w-xl mx-auto text-[15px] sm:text-[17px] text-white/60 leading-relaxed">
              Start tracking, chaining and remediating CVEs in real time.
              Zero setup. Production-ready in under five minutes.
            </p>
            <div className="mt-9 flex flex-col sm:flex-row items-center justify-center gap-3">
              <Link
                to="/register"
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3.5 text-[15px] font-medium text-white bg-gradient-brand rounded-xl btn-primary-glow"
              >
                Create your free account <ArrowRight className="w-4 h-4" />
              </Link>
              <a
                href="#api"
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3.5 text-[15px] font-medium text-white/85 bg-white/[0.04] border border-white/10 hover:bg-white/[0.07] hover:border-white/20 rounded-xl transition"
              >
                Read API Docs
              </a>
            </div>
            <div className="mt-8 flex flex-wrap items-center justify-center gap-x-5 gap-y-2 text-[12px] text-white/40">
              <span>✓ Free tier forever</span>
              <span>✓ SOC 2 ready in days</span>
              <span>✓ Open API · open source SDKs</span>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
