import { Logo } from "./Logo";
import { DASHBOARD_URL } from "../../constants";

const GithubIcon = (p: React.SVGProps<SVGSVGElement>) => (
  <svg viewBox="0 0 24 24" fill="currentColor" {...p}>
    <path d="M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.56v-2c-3.2.7-3.87-1.37-3.87-1.37-.52-1.34-1.28-1.69-1.28-1.69-1.05-.71.08-.7.08-.7 1.16.08 1.77 1.19 1.77 1.19 1.03 1.77 2.7 1.26 3.36.96.1-.74.4-1.26.73-1.55-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.29 1.18-3.1-.12-.29-.51-1.46.11-3.05 0 0 .97-.31 3.18 1.19a11 11 0 015.78 0c2.21-1.5 3.18-1.19 3.18-1.19.62 1.59.23 2.76.11 3.05.74.81 1.18 1.84 1.18 3.1 0 4.42-2.7 5.39-5.27 5.68.41.36.78 1.06.78 2.13v3.16c0 .31.21.68.8.56C20.22 21.39 23.5 17.07 23.5 12 23.5 5.65 18.35.5 12 .5z" />
  </svg>
);
const TwitterIcon = (p: React.SVGProps<SVGSVGElement>) => (
  <svg viewBox="0 0 24 24" fill="currentColor" {...p}>
    <path d="M18.244 2H21.5l-7.36 8.41L23 22h-6.844l-5.36-6.93L4.5 22H1.244l7.86-8.99L1 2h6.99l4.84 6.39L18.244 2zm-2.4 18h1.9L7.27 4H5.27l10.574 16z" />
  </svg>
);

const COLS = [
  {
    title: "Product",
    links: [
      { label: "Features", href: "#features" },
      { label: "Dashboard", href: "#dashboard" },
      { label: "Compliance", href: "#compliance" },
      { label: "API Docs", href: "#api" },
    ],
  },
  {
    title: "Resources",
    links: [
      { label: "NVD Database", href: "https://nvd.nist.gov/", ext: true },
      { label: "CVE Program", href: "https://www.cve.org/", ext: true },
      { label: "MITRE ATT&CK", href: "https://attack.mitre.org/", ext: true },
      { label: "OWASP Top 10", href: "https://owasp.org/Top10/", ext: true },
    ],
  },
  {
    title: "Company",
    links: [
      { label: "About", href: "#" },
      { label: "Changelog", href: "#" },
      { label: "Contact", href: "#" },
      { label: "Status", href: "#" },
    ],
  },
];

export function Footer() {
  return (
    <footer className="relative border-t border-white/[0.06] bg-[#08080a]">
      <div className="max-w-7xl mx-auto px-5 sm:px-8 py-16">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-10">
          <div className="col-span-2">
            <Logo />
            <p className="mt-4 text-[13.5px] text-white/55 leading-relaxed max-w-xs">
              Full-spectrum vulnerability management. See the chain. Break the breach.
            </p>
            <div className="mt-5 flex items-center gap-2">
              <a
                href="#"
                className="w-9 h-9 rounded-lg bg-white/[0.03] border border-white/10 flex items-center justify-center text-white/55 hover:text-white hover:border-white/25 transition"
                aria-label="GitHub"
              >
                <GithubIcon className="w-4 h-4" />
              </a>
              <a
                href="#"
                className="w-9 h-9 rounded-lg bg-white/[0.03] border border-white/10 flex items-center justify-center text-white/55 hover:text-white hover:border-white/25 transition"
                aria-label="Twitter"
              >
                <TwitterIcon className="w-4 h-4" />
              </a>
            </div>
            <div className="mt-5 inline-flex items-center gap-2 px-2.5 py-1.5 text-[11px] glass rounded-full">
              <span className="relative flex h-1.5 w-1.5">
                <span className="absolute inset-0 rounded-full bg-emerald-400 animate-ping-slow opacity-75" />
                <span className="relative w-1.5 h-1.5 rounded-full bg-emerald-400" />
              </span>
              <span className="text-white/65">All systems operational</span>
            </div>
          </div>

          {COLS.map((c) => (
            <div key={c.title}>
              <div className="text-[11px] font-semibold tracking-[0.2em] uppercase text-white/40">{c.title}</div>
              <ul className="mt-4 space-y-2.5">
                {c.links.map((l) => (
                  <li key={l.label}>
                    <a
                      href={l.href}
                      {...("ext" in l && l.ext ? { target: "_blank", rel: "noopener noreferrer" } : {})}
                      className="text-[13px] text-white/60 hover:text-white transition"
                    >
                      {l.label}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        <div className="mt-14 pt-7 border-t border-white/[0.06] flex flex-col sm:flex-row items-center justify-between gap-4 text-[12px] text-white/40">
          <div>© 2026 CascadeX Intelligence · Built with ❤️ on the NVD API v2.0</div>
          <div className="flex items-center gap-5">
            <a href="#" className="hover:text-white transition">Privacy</a>
            <a href="#" className="hover:text-white transition">Terms</a>
            <a href="#" className="hover:text-white transition">Security</a>
            <a href={DASHBOARD_URL} className="hover:text-white transition">
              Dashboard ↗
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}
