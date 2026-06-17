import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowRight, Eye, EyeOff, Lock, Mail } from "lucide-react";
import { AuthLayout } from "./AuthLayout";
import { apiLogin, TokenStorage } from "../services/auth";
import { useAuth } from "../services/AuthContext";
import { DASHBOARD_URL } from "../constants";

export function Login() {
  const navigate = useNavigate();
  const { login } = useAuth();
  const [showPwd, setShowPwd] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({ username: "", password: "", remember: true });

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!form.username || !form.password) {
      setError("Please enter your username/email and password.");
      return;
    }

    setLoading(true);
    try {
      const data = await apiLogin(form.username, form.password);

      if (!data.success) {
        const backendDetail =
          typeof (data as any)?.detail === 'string'
            ? (data as any).detail
            : null;

        const errs =
          data.errors?.non_field_errors ||
          (backendDetail ? [backendDetail] : ['Invalid credentials.']);

        setError(errs[0]);
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
    <AuthLayout side="login">
      <header>
        <h1 className="text-3xl sm:text-[34px] font-semibold tracking-tight text-white leading-tight">
          Welcome back
        </h1>
        <p className="mt-2 text-[14px] text-white/55">
          Sign in to your CascadeX Intelligence console.
        </p>
      </header>

      <div className="mt-8 grid grid-cols-2 gap-2.5">
        <SSOButton provider="google" />
        <SSOButton provider="github" />
      </div>

      <div className="mt-6 flex items-center gap-3 text-[11px] text-white/35 uppercase tracking-[0.18em] font-medium">
        <span className="flex-1 h-px bg-white/[0.08]" />
        or continue with email
        <span className="flex-1 h-px bg-white/[0.08]" />
      </div>

      <form onSubmit={onSubmit} className="mt-6 space-y-4" noValidate>
        <Field
          label="Username or email"
          icon={<Mail className="w-4 h-4" />}
          type="text"
          autoComplete="username"
          placeholder="username or you@company.com"
          value={form.username}
          onChange={(v) => setForm((f) => ({ ...f, username: v }))}
        />
        <Field
          label="Password"
          icon={<Lock className="w-4 h-4" />}
          type={showPwd ? "text" : "password"}
          autoComplete="current-password"
          placeholder="••••••••"
          value={form.password}
          onChange={(v) => setForm((f) => ({ ...f, password: v }))}
          rightSlot={
            <button
              type="button"
              onClick={() => setShowPwd((s) => !s)}
              className="text-white/45 hover:text-white/80 transition"
              aria-label={showPwd ? "Hide password" : "Show password"}
            >
              {showPwd ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          }
          extra={
            <Link to="#" className="text-[12px] text-blue-300 hover:text-blue-200 transition">
              Forgot?
            </Link>
          }
        />

        <label className="flex items-center gap-2 text-[13px] text-white/65 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={form.remember}
            onChange={(e) => setForm((f) => ({ ...f, remember: e.target.checked }))}
            className="appearance-none w-4 h-4 rounded border border-white/15 bg-white/[0.04] checked:bg-blue-500 checked:border-blue-500 transition"
          />
          Remember me on this device
        </label>

        {error && (
          <div className="px-3 py-2.5 text-[12.5px] text-rose-200 bg-rose-500/10 border border-rose-500/25 rounded-lg">
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          className="w-full inline-flex items-center justify-center gap-2 px-5 py-3 text-[14px] font-medium text-white bg-gradient-brand rounded-xl btn-primary-glow disabled:opacity-70 disabled:cursor-not-allowed"
        >
          {loading ? (
            <>
              <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Signing in…
            </>
          ) : (
            <>
              Sign in to dashboard <ArrowRight className="w-4 h-4" />
            </>
          )}
        </button>
      </form>

      <p className="mt-7 text-center text-[12.5px] text-white/45">
        Don't have an account?{" "}
        <Link to="/register" className="text-blue-300 hover:text-blue-200 font-medium">
          Create one — free
        </Link>
      </p>

      <p className="mt-8 text-center text-[11px] text-white/30 leading-relaxed">
        Protected by SOC 2 controls.{" "}
        <button onClick={() => navigate("/")} className="underline underline-offset-2 hover:text-white/50">
          Back to home
        </button>
      </p>
    </AuthLayout>
  );
}

function Field({ label, icon, type, placeholder, value, onChange, rightSlot, extra, autoComplete }: {
  label: string; icon: React.ReactNode; type: string; placeholder?: string;
  value: string; onChange: (v: string) => void; rightSlot?: React.ReactNode;
  extra?: React.ReactNode; autoComplete?: string;
}) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <label className="text-[12.5px] font-medium text-white/75">{label}</label>
        {extra}
      </div>
      <div className="relative">
        <span className="absolute left-3 top-1/2 -translate-y-1/2 text-white/40">{icon}</span>
        <input type={type} value={value} autoComplete={autoComplete}
          onChange={(e) => onChange(e.target.value)} placeholder={placeholder}
          className="auth-input" />
        {rightSlot && <span className="absolute right-3 top-1/2 -translate-y-1/2">{rightSlot}</span>}
      </div>
    </div>
  );
}

function SSOButton({ provider }: { provider: "google" | "github" }) {
  const label = provider === "google" ? "Google" : "GitHub";

  const handleOAuth = () => {
    window.location.href = `/api/auth/oauth/${provider}/`;
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
