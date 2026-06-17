import { PRODUCT_NAME, PRODUCT_TAGLINE } from "../../constants";

export function Logo({ size = "md" }: { size?: "sm" | "md" | "lg" }) {
  const dim = size === "sm" ? 22 : size === "lg" ? 36 : 28;
  const text = size === "sm" ? "text-base" : size === "lg" ? "text-2xl" : "text-lg";
  return (
    <div className="flex items-center gap-2.5">
      <div className="relative" style={{ width: dim, height: dim }}>
        <div className="absolute inset-0 rounded-lg bg-gradient-brand opacity-90" />
        <div className="absolute inset-0 rounded-lg bg-gradient-to-br from-white/20 to-transparent" />
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="white"
          strokeWidth="2.2"
          strokeLinecap="round"
          strokeLinejoin="round"
          className="absolute inset-0 m-auto"
          style={{ width: dim * 0.6, height: dim * 0.6 }}
        >
          {/* Stylized cascade / shield */}
          <path d="M12 2 L4 5 v6 c0 5 3.5 9 8 11 c4.5-2 8-6 8-11 V5 z" opacity="0.95" />
          <path d="M9 11 l2 2 l4-4" />
        </svg>
        <div className="absolute -inset-1 rounded-lg bg-gradient-brand opacity-30 blur-md -z-10" />
      </div>
      <div className="flex items-baseline gap-1.5">
        <span className={`${text} font-semibold tracking-tight text-white`}>{PRODUCT_NAME}</span>
        <span className={`${text} font-light tracking-tight text-white/60 hidden sm:inline`}>{PRODUCT_TAGLINE}</span>
      </div>
    </div>
  );
}
