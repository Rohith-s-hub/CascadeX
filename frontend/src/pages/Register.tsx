import { useMemo, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowRight, Building2, Eye, EyeOff, Lock, Mail, User } from "lucide-react";
import { AuthLayout } from "./AuthLayout";
import { apiRegister } from "../services/auth";
import { useAuth } from "../services/AuthContext";
import { DASHBOARD_URL } from "../constants";

export function Register() {
  const navigate = useNavigate();
  const { login } = useAuth();
  const [showPwd, setShowPwd] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({
    name: "", company: "", email: "", password: "", accept: false,
  });

  const strength = useMemo(() => scorePassword(form.password), [form.password]);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!form.name || !form.email || !form.password) {
      setError("Please fill in all required fields.");
      return;
    }
    if (form.password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    if (!form.accept) {
      setError("Please accept the Terms and Privacy Policy.");
      return;
    }

    // Split full name into first + last
    const parts = form.name.trim().split(' ');
    const first_name = parts[0] || '';
    const last_name = parts.slice(1).join(' ') || '';

    // Use email prefix as username
    const username = form.email.split('@')[0].replace(/[^a-zA-Z0-9]/g, '_');

    setLoading(true);
    try {
      const data = await apiRegister({
        username,
        email: form.email,
        password: form.password,
        password_confirm: form.password,
        first_name,
        last_name,
        organization: form.company,
      });

      if (!data.success) {
        const backendDetail =
          typeof (data as any)?.detail === 'string'
            ? (data as any).detail
            : null;

        const firstError = Object.values(data.errors || {})[0];
        setError(
          backendDetail ||
          (Array.isArray(firstError) ? firstError[0] : 'Registration failed.')
        );
        return;
      }

      login(data.user, data.tokens);
      window.location.href = DASHBOARD_URL;
    } catch (err) {
      setError("Network error. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout side="register">
      <header>
        <h1 className="text-3xl sm:text-[34px] font-semibold tracking-tight text-white leading-tight">
          Create your account
        </h1>
        <p className="mt-2 text-[14px] text-white/55">
          Free forever for individuals. No credit card required.
        </p>
      </header>

      <div className="mt-8 grid grid-cols-2 gap-2.5">
        <SSOButton provider="google" />
        <SSOButton provider="github" />
      </div>

      <div className="mt-6 flex items-center gap-3 text-[11px] text-white/35 uppercase tracking-[0.18em] font-medium">
        <span className="flex-1 h-px bg-white/[0.08]" />
        or with email
        <span className="flex-1 h-px bg-white/[0.08]" />
      </div>

      <form onSubmit={onSubmit} className="mt-6 space-y-4" noValidate>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <Field label="Full name" icon={<User className="w-4 h-4" />} type="text"
            autoComplete="name" placeholder="Ada Lovelace" value={form.name}
            onChange={(v) => setForm((f) => ({ ...f, name: v }))} />
          <Field label="Company" icon={<Building2 className="w-4 h-4" />} type="text"
            autoComplete="organization" placeholder="Acme Security" value={form.company}
            onChange={(v) => setForm((f) => ({ ...f, company: v }))} optional />
        </div>

        <Field label="Work email" icon={<Mail className="w-4 h-4" />} type="email"
          autoComplete="email" placeholder="you@company.com" value={form.email}
          onChange={(v) => setForm((f) => ({ ...f, email: v }))} />

        <div>
          <Field label="Password" icon={<Lock className="w-4 h-4" />}
            type={showPwd ? "text" : "password"} autoComplete="new-password"
            placeholder="At least 8 characters" value={form.password}
            onChange={(v) => setForm((f) => ({ ...f, password: v }))}
            rightSlot={
              <button type="button" onClick={() => setShowPwd((s) => !s)}
                className="text-white/45 hover:text-white/80 transition"
                aria-label={showPwd ? "Hide password" : "Show password"}>
                {showPwd ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            } />
          <PasswordMeter score={strength.score} label={strength.label} />
        </div>

        <label className="flex items-start gap-2.5 text-[12.5px] text-white/65 cursor-pointer select-none">
          <input type="checkbox" checked={form.accept}
            onChange={(e) => setForm((f) => ({ ...f, accept: e.target.checked }))}
            className="mt-0.5 appearance-none w-4 h-4 rounded border border-white/15 bg-white/[0.04] checked:bg-blue-500 checked:border-blue-500 transition" />
          <span className="leading-relaxed">
            I agree to the{" "}
            <Link to="#" className="text-blue-300 hover:text-blue-200 underline underline-offset-2">Terms of Service</Link> and{" "}
            <Link to="#" className="text-blue-300 hover:text-blue-200 underline underline-offset-2">Privacy Policy</Link>.
          </span>
        </label>

        {error && (
          <div className="px-3 py-2.5 text-[12.5px] text-rose-200 bg-rose-500/10 border border-rose-500/25 rounded-lg">
            {error}
          </div>
        )}

        <button type="submit" disabled={loading}
          className="w-full inline-flex items-center justify-center gap-2 px-5 py-3 text-[14px] font-medium text-white bg-gradient-brand rounded-xl btn-primary-glow disabled:opacity-70 disabled:cursor-not-allowed">
          {loading ? (
            <><span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />Creating account…</>
          ) : (
            <>Create free account <ArrowRight className="w-4 h-4" /></>
          )}
        </button>
      </form>

      <p className="mt-7 text-center text-[12.5px] text-white/45">
        Already have an account?{" "}
        <Link to="/login" className="text-blue-300 hover:text-blue-200 font-medium">Sign in</Link>
      </p>
      <p className="mt-8 text-center text-[11px] text-white/30 leading-relaxed">
        SOC 2 · GDPR · HIPAA-ready.{" "}
        <button onClick={() => navigate("/")} className="underline underline-offset-2 hover:text-white/50">Back to home</button>
      </p>
    </AuthLayout>
  );
}

function Field({ label, icon, type, placeholder, value, onChange, rightSlot, optional, autoComplete }: {
  label: string; icon: React.ReactNode; type: string; placeholder?: string;
  value: string; onChange: (v: string) => void; rightSlot?: React.ReactNode;
  optional?: boolean; autoComplete?: string;
}) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <label className="text-[12.5px] font-medium text-white/75">
          {label}
          {optional && <span className="ml-1.5 text-[11px] text-white/35 font-normal">optional</span>}
        </label>
      </div>
      <div className="relative">
        <span className="absolute left-3 top-1/2 -translate-y-1/2 text-white/40">{icon}</span>
        <input type={type} value={value} autoComplete={autoComplete}
          onChange={(e) => onChange(e.target.value)} placeholder={placeholder} className="auth-input" />
        {rightSlot && <span className="absolute right-3 top-1/2 -translate-y-1/2">{rightSlot}</span>}
      </div>
    </div>
  );
}

function PasswordMeter({ score, label }: { score: number; label: string }) {
  const colors = ["bg-white/10", "bg-rose-500", "bg-amber-500", "bg-blue-500", "bg-emerald-500"];
  const textColors = ["text-white/35", "text-rose-300", "text-amber-300", "text-blue-300", "text-emerald-300"];
  return (
    <div className="mt-2 flex items-center gap-2">
      <div className="flex-1 grid grid-cols-4 gap-1">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className={`h-1 rounded-full transition-colors ${i <= score ? colors[score] : "bg-white/[0.06]"}`} />
        ))}
      </div>
      <span className={`text-[10.5px] font-medium tabular-nums ${textColors[score]}`}>{label}</span>
    </div>
  );
}

function scorePassword(pwd: string): { score: number; label: string } {
  if (!pwd) return { score: 0, label: "Empty" };
  let s = 0;
  if (pwd.length >= 8) s++;
  if (/[A-Z]/.test(pwd) && /[a-z]/.test(pwd)) s++;
  if (/\d/.test(pwd)) s++;
  if (/[^A-Za-z0-9]/.test(pwd)) s++;
  s = Math.max(1, Math.min(4, s));
  return { score: s, label: ["Empty", "Weak", "Fair", "Good", "Strong"][s] };
}

function SSOButton({ provider }: { provider: "google" | "github" }) {
  const label = provider === "google" ? "Google" : "GitHub";

  const handleOAuth = () => {
    window.location.href = `${import.meta.env.VITE_API_BASE_URL || ""}/api/auth/oauth/${provider}/`;
  };

  return (
    <button type="button"
      onClick={handleOAuth}
      className="inline-flex items-center justify-center gap-2 px-3 py-2.5 text-[13px] font-medium text-white/80 bg-white/[0.03] border border-white/[0.08] hover:bg-white/[0.06] hover:border-white/20 rounded-lg transition">
      {provider === "google" ? (
        <svg className="w-4 h-4" viewBox="0 0 48 48" aria-hidden>
          <path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3c-1.7 4.7-6.2 8-11.3 8-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.9 1.2 8 3.1l5.7-5.7C34.5 6.5 29.5 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.4-.4-3.5z" />
          <path fill="#FF3D00" d="M6.3 14.7l6.6 4.8C14.7 16 19 13 24 13c3.1 0 5.9 1.2 8 3.1l5.7-5.7C34.5 6.5 29.5 4 24 4 16.3 4 9.7 8.3 6.3 14.7z" />
          <path fill="#4CAF50" d="M24 44c5.4 0 10.3-2.1 14-5.4l-6.5-5.5C29.5 35 26.9 36 24 36c-5.1 0-9.5-3.3-11.2-7.9l-6.5 5C9.5 39.6 16.2 44 24 44z" />
          <path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.2-2.2 4.1-4 5.5l6.5 5.5C41.7 36 44 30.5 44 24c0-1.3-.1-2.4-.4-3.5z" />
        </svg>
      ) : (
        <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor" aria-hidden>
          <path d="M12 .3a12 12 0 0 0-3.8 23.4c.6.1.8-.3.8-.6v-2.2c-3.3.7-4-1.4-4-1.4-.6-1.4-1.4-1.8-1.4-1.8-1.1-.7.1-.7.1-.7 1.2.1 1.9 1.2 1.9 1.2 1.1 1.9 2.9 1.4 3.6 1 .1-.8.4-1.4.8-1.7-2.7-.3-5.5-1.3-5.5-6 0-1.3.5-2.4 1.2-3.2-.1-.3-.5-1.5.1-3.2 0 0 1-.3 3.3 1.2a11.5 11.5 0 0 1 6 0c2.3-1.5 3.3-1.2 3.3-1.2.7 1.7.2 2.9.1 3.2.8.8 1.2 1.9 1.2 3.2 0 4.7-2.8 5.7-5.5 6 .4.4.8 1.1.8 2.3v3.4c0 .3.2.7.8.6A12 12 0 0 0 12 .3" />
        </svg>
      )}
      {label}
    </button>
  );
}
