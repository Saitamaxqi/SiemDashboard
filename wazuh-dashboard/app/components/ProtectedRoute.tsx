"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

interface Props {
  children: React.ReactNode;
}

export default function ProtectedRoute({ children }: Props) {
  const router = useRouter();
  const [checked, setChecked] = useState(false);

  useEffect(() => {
    const token = typeof window !== "undefined"
      ? localStorage.getItem("wazuh_token")
      : null;

    if (!token) {
      router.replace("/"); // back to login
    } else {
      setChecked(true);
    }
  }, [router]);

  if (!checked) {
    // simple placeholder while checking token
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-950 text-slate-100">
        <p className="text-sm text-slate-400">Checking session…</p>
      </div>
    );
  }

  return <>{children}</>;
}