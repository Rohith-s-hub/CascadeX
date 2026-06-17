import { useEffect, useRef } from "react";

export function CursorGlow() {
  const ref = useRef<HTMLDivElement>(null);
  const target = useRef({ x: 0, y: 0 });
  const current = useRef({ x: 0, y: 0 });
  const raf = useRef<number | null>(null);

  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      target.current.x = e.clientX;
      target.current.y = e.clientY;
      if (raf.current == null) loop();
    };
    const loop = () => {
      current.current.x += (target.current.x - current.current.x) * 0.12;
      current.current.y += (target.current.y - current.current.y) * 0.12;
      if (ref.current) {
        ref.current.style.transform = `translate3d(${current.current.x - 250}px, ${current.current.y - 250}px, 0)`;
      }
      const dx = Math.abs(target.current.x - current.current.x);
      const dy = Math.abs(target.current.y - current.current.y);
      if (dx < 0.2 && dy < 0.2) {
        raf.current = null;
        return;
      }
      raf.current = requestAnimationFrame(loop);
    };
    window.addEventListener("mousemove", onMove);
    return () => {
      window.removeEventListener("mousemove", onMove);
      if (raf.current) cancelAnimationFrame(raf.current);
    };
  }, []);

  return (
    <div
      ref={ref}
      aria-hidden
      className="pointer-events-none fixed top-0 left-0 z-[1] hidden md:block"
      style={{
        width: 500,
        height: 500,
        background:
          "radial-gradient(circle, rgba(59,130,246,0.12) 0%, rgba(139,92,246,0.06) 30%, transparent 65%)",
        filter: "blur(20px)",
        willChange: "transform",
      }}
    />
  );
}
