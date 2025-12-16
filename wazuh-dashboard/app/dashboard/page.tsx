"use client";
import type { NextPage } from "next";
import {
  useEffect,
  useMemo,
  useState,
  useLayoutEffect,
  useRef,
} from "react";
import ProtectedRoute from "../components/ProtectedRoute";

const API_BASE = "http://10.0.2.15:5000/api";

interface AlertRow {
  timestamp: string;
  rule_id: string;
  rule_level: number;
  rule_description: string;
  rule_groups: string;
  agent_name: string;
  srcip: string;
  dstip: string;
  dstport: string;
  location: string;
  risk_score: number;
}

const DashboardPage: NextPage = () => {
  const [alerts, setAlerts] = useState<AlertRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const lastScrollYRef = useRef<number | null>(null);

  // pagination
  const [page, setPage] = useState(1);
  const [pageInput, setPageInput] = useState<string>("1");
  const PAGE_SIZE = 10;

  useEffect(() => {
    let cancelled = false;

    async function fetchAlerts() {
      try {
        setError(null);

        const token =
          typeof window !== "undefined"
            ? localStorage.getItem("wazuh_token")
            : null;

        const res = await fetch(`${API_BASE}/alerts`, {
          headers: {
            "Content-Type": "application/json",
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
        });

        if (!res.ok) {
          const text = await res.text();
          throw new Error(text || "Failed to fetch alerts");
        }

        const data: AlertRow[] = await res.json();

        if (cancelled) return;

        setAlerts((prev) => {
          if (arraysEqual(prev, data)) {
            // nothing changed → no re-render → no scroll jump
            return prev;
          }

          setLastUpdated(new Date().toLocaleString());

          // remember scroll before updating alerts
          if (typeof window !== "undefined") {
            lastScrollYRef.current = window.scrollY;
          }

          return data;
        });
      } catch (err: any) {
        if (!cancelled) {
          setError(err.message || "Error loading alerts");
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    // initial load
    fetchAlerts();

    // polling every 15s
    const intervalId = setInterval(fetchAlerts, 15000);

    return () => {
      cancelled = true;
      clearInterval(intervalId);
    };
  }, []);

  // restore scroll after alerts change
  useLayoutEffect(() => {
    if (lastScrollYRef.current !== null && typeof window !== "undefined") {
      window.scrollTo(0, lastScrollYRef.current);
      lastScrollYRef.current = null;
    }
  }, [alerts]);

  // --- Graph data helpers ---

  const levelStats = useMemo(() => {
    const counts: Record<number, number> = {};
    alerts.forEach((a) => {
      const lvl = Number(a.rule_level || 0);
      counts[lvl] = (counts[lvl] || 0) + 1;
    });
    const points = Object.entries(counts)
      .map(([level, count]) => ({
        level: Number(level),
        count,
      }))
      .sort((a, b) => a.level - b.level);
    return points;
  }, [alerts]);

  const timeBuckets = useMemo(() => {
    if (!alerts.length) return [];

    const parseHourKey = (ts: string): string => {
      const d = new Date(ts);
      if (isNaN(d.getTime())) return "unknown";
      return d.toISOString().slice(0, 13); // YYYY-MM-DDTHH
    };

    const buckets: Record<string, { sum: number; count: number }> = {};

    alerts.forEach((a) => {
      const key = parseHourKey(a.timestamp);
      if (!buckets[key]) {
        buckets[key] = { sum: 0, count: 0 };
      }
      buckets[key].sum += Number(a.risk_score || 0);
      buckets[key].count += 1;
    });

    return Object.entries(buckets)
      .map(([key, v]) => ({
        hour: key,
        avgRisk: v.count > 0 ? v.sum / v.count : 0,
      }))
      .sort((a, b) => (a.hour > b.hour ? 1 : -1));
  }, [alerts]);

  // --- sorting + pagination for table ---

  const sortedAlerts = useMemo(() => {
    const copy = [...alerts];

    copy.sort((a, b) => {
      const ta = new Date(a.timestamp || "").getTime();
      const tb = new Date(b.timestamp || "").getTime();

      if (Number.isNaN(ta) && Number.isNaN(tb)) return 0;
      if (Number.isNaN(ta)) return 1;
      if (Number.isNaN(tb)) return -1;

      return tb - ta; // newer first
    });

    return copy;
  }, [alerts]);

  const totalPages = Math.max(1, Math.ceil(sortedAlerts.length / PAGE_SIZE));

  const pagedAlerts = useMemo(() => {
    const start = (page - 1) * PAGE_SIZE;
    const end = start + PAGE_SIZE;
    return sortedAlerts.slice(start, end);
  }, [sortedAlerts, page, PAGE_SIZE]);

  // clamp page if alerts shrink
  useEffect(() => {
    if (page > totalPages) {
      setPage(totalPages);
    }
  }, [totalPages, page]);

  // keep text input in sync with current page
  useEffect(() => {
    setPageInput(String(page));
  }, [page]);

  // handle direct jump
  const handlePageJump = () => {
    const raw = pageInput.trim();
    if (!raw) return;
    const num = Number(raw);
    if (Number.isNaN(num)) return;

    const clamped = Math.min(Math.max(1, num), totalPages);
    setPage(clamped);
  };

  return (
    <ProtectedRoute>
      <div className="min-h-screen bg-slate-950 text-slate-100">
        <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur-sm">
          <div className="mx-auto max-w-6xl px-4 py-4 flex items-center justify-between">
            <div>
              <h1 className="text-xl font-semibold">
                Wazuh + Suricata Alert Dashboard
              </h1>
              <p className="text-xs text-slate-400">
                ML-based risk scoring on top of scored_alerts.csv
              </p>
            </div>
            <div className="flex flex-col items-end gap-1 text-xs text-slate-400">
              <div className="flex items-center gap-2">
                <span className="inline-flex h-2 w-2 rounded-full bg-emerald-400 mr-1" />
                <span>API: Online</span>
              </div>
              {lastUpdated && (
                <div className="text-[10px] text-slate-500">
                  Last updated: {lastUpdated}
                </div>
              )}
            </div>
          </div>
        </header>

        <main className="mx-auto max-w-6xl px-4 py-6 space-y-6">
          {/* Top stats */}
          <section className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <StatCard label="Total alerts" value={alerts.length.toString()} />
            <StatCard
              label="Avg risk score"
              value={
                alerts.length
                  ? Math.round(
                      alerts.reduce(
                        (acc, a) => acc + Number(a.risk_score || 0),
                        0
                      ) / alerts.length
                    ).toString()
                  : "0"
              }
            />
            <StatCard
              label="Unique rules"
              value={
                new Set(alerts.map((a) => a.rule_id || "")).size.toString()
              }
            />
          </section>

          {/* Graphs */}
          <section className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <GraphCard title="Alerts by rule level">
              <SimpleLineChart
                width={400}
                height={180}
                points={levelStats.map((p, idx) => ({
                  x: idx,
                  y: p.count,
                  label: p.level.toString(),
                }))}
                xLabel="Rule levels"
                yLabel="Count"
              />
            </GraphCard>

            <GraphCard title="Average risk score over time">
              <SimpleLineChart
                width={400}
                height={180}
                points={timeBuckets.map((p, idx) => ({
                  x: idx,
                  y: p.avgRisk,
                  label: p.hour.slice(11, 13) + "h",
                }))}
                xLabel="Time buckets"
                yLabel="Avg risk"
              />
            </GraphCard>
          </section>

          {/* Table */}
          <section className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
              <h2 className="text-sm font-medium">Scored alerts</h2>
              <span className="text-xs text-slate-400">
                Showing latest {sortedAlerts.length} alerts
              </span>
            </div>

            {loading && (
              <div className="px-4 py-6 text-sm text-slate-400">
                Loading alerts…
              </div>
            )}

            {error && (
              <div className="px-4 py-6 text-sm text-red-300">
                {error}
              </div>
            )}

            {!loading && !error && (
              <div className="overflow-x-auto">
                <table className="min-w-full text-xs">
                  <thead className="bg-slate-900">
                    <tr>
                      <Th>Time</Th>
                      <Th>Rule</Th>
                      <Th>Level</Th>
                      <Th>Agent</Th>
                      <Th>Src IP</Th>
                      <Th>Dst IP</Th>
                      <Th>Port</Th>
                      <Th>Risk</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {pagedAlerts.map((a, idx) => (
                      <tr
                        key={`${a.timestamp}-${a.rule_id}-${idx}`}
                        className="border-t border-slate-800/70 hover:bg-slate-900/70"
                      >
                        <Td>
                          <span className="font-mono">
                            {formatTimestamp(a.timestamp) || "-"}
                          </span>
                        </Td>
                        <Td>
                          <div className="flex flex-col">
                            <span className="font-medium text-slate-100">
                              {a.rule_description || "-"}
                            </span>
                            <span className="text-[10px] text-slate-500">
                              ID {a.rule_id} • {a.rule_groups}
                            </span>
                          </div>
                        </Td>
                        <Td>{a.rule_level}</Td>
                        <Td>{a.agent_name || "-"}</Td>
                        <Td>{a.srcip || "-"}</Td>
                        <Td>{a.dstip || "-"}</Td>
                        <Td>{a.dstport || "-"}</Td>
                        <Td>
                          <span
                            className={riskBadgeClass(
                              Number(a.risk_score || 0)
                            )}
                          >
                            {a.risk_score}
                          </span>
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </table>

                {/* pagination footer */}
                <div className="flex flex-col md:flex-row md:items-center justify-between px-4 py-3 border-t border-slate-800 text-[11px] text-slate-400 gap-2">
                  <span>
                    Showing{" "}
                    {sortedAlerts.length === 0
                      ? "0"
                      : `${(page - 1) * PAGE_SIZE + 1}–${Math.min(
                          page * PAGE_SIZE,
                          sortedAlerts.length
                        )}`}{" "}
                    of {sortedAlerts.length} alerts
                  </span>

                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      onClick={() =>
                        setPage((p) => Math.max(1, p - 1))
                      }
                      disabled={page === 1}
                      className="px-2 py-1 rounded border border-slate-700 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-800 transition"
                    >
                      Prev
                    </button>

                    <span>
                      Page {page} / {totalPages}
                    </span>

                    {/* page jump input */}
                    <div className="flex items-center gap-1">
                      <span>Go to</span>
                      <input
                        type="number"
                        min={1}
                        max={totalPages}
                        value={pageInput}
                        onChange={(e) => setPageInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") {
                            handlePageJump();
                          }
                        }}
                        className="w-14 rounded border border-slate-700 bg-slate-900 px-1 py-0.5 text-xs text-slate-100"
                      />
                      <button
                        onClick={handlePageJump}
                        className="px-2 py-1 rounded border border-slate-700 hover:bg-slate-800 transition"
                      >
                        Go
                      </button>
                    </div>

                    <button
                      onClick={() =>
                        setPage((p) => Math.min(totalPages, p + 1))
                      }
                      disabled={page === totalPages}
                      className="px-2 py-1 rounded border border-slate-700 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-800 transition"
                    >
                      Next
                    </button>
                  </div>
                </div>
              </div>
            )}
          </section>
        </main>
      </div>
    </ProtectedRoute>
  );
};

export default DashboardPage;

// --- Small UI helpers ---

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 px-4 py-3">
      <p className="text-xs text-slate-400">{label}</p>
      <p className="mt-2 text-xl font-semibold">{value}</p>
    </div>
  );
}

function GraphCard({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 px-4 py-3">
      <div className="flex items-center justify-between mb-2">
        <h2 className="text-sm font-medium">{title}</h2>
      </div>
      {children}
    </div>
  );
}

function SimpleLineChart({
  width,
  height,
  points,
  xLabel,
  yLabel,
}: {
  width: number;
  height: number;
  points: { x: number; y: number; label?: string }[];
  xLabel: string;
  yLabel: string;
}) {
  if (!points.length) {
    return (
      <div className="h-[180px] flex items-center justify-center text-xs text-slate-500">
        No data yet
      </div>
    );
  }

  const maxY = Math.max(...points.map((p) => p.y)) || 1;
  const padding = 24;
  const innerW = width - padding * 2;
  const innerH = height - padding * 2;

  const scaled = points.map((p, idx) => {
    const x =
      padding +
      (points.length === 1
        ? innerW / 2
        : (innerW * idx) / (points.length - 1));
    const y = padding + innerH - (p.y / maxY) * innerH;
    return { ...p, sx: x, sy: y };
  });

  const pathD = scaled
    .map((p, i) => `${i === 0 ? "M" : "L"} ${p.sx} ${p.sy}`)
    .join(" ");

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      className="w-full h-[180px]"
      role="img"
    >
      {/* Axes */}
      <line
        x1={padding}
        y1={padding}
        x2={padding}
        y2={height - padding}
        stroke="currentColor"
        strokeWidth={0.5}
        opacity={0.4}
      />
      <line
        x1={padding}
        y1={height - padding}
        x2={width - padding}
        y2={height - padding}
        stroke="currentColor"
        strokeWidth={0.5}
        opacity={0.4}
      />

      {/* Line */}
      <path
        d={pathD}
        fill="none"
        stroke="currentColor"
        strokeWidth={1.5}
      />

      {/* Points */}
      {scaled.map((p, idx) => (
        <g key={idx}>
          <circle cx={p.sx} cy={p.sy} r={2} fill="currentColor" />
          {p.label && (
            <text
              x={p.sx}
              y={height - padding + 10}
              textAnchor="middle"
              fontSize="7"
              fill="currentColor"
              opacity={0.7}
            >
              {p.label}
            </text>
          )}
        </g>
      ))}

      {/* Labels */}
      <text
        x={padding}
        y={padding - 6}
        fontSize="8"
        fill="currentColor"
        opacity={0.7}
      >
        {yLabel}
      </text>
      <text
        x={width - padding}
        y={height - padding + 12}
        fontSize="8"
        fill="currentColor"
        opacity={0.7}
        textAnchor="end"
      >
        {xLabel}
      </text>
    </svg>
  );
}

function riskBadgeClass(score: number) {
  if (score >= 80) {
    return "inline-flex items-center justify-center rounded-full bg-red-500/20 text-red-300 text-[11px] px-3 py-1 font-semibold";
  }
  if (score >= 50) {
    return "inline-flex items-center justify-center rounded-full bg-amber-500/20 text-amber-300 text-[11px] px-3 py-1 font-semibold";
  }
  return "inline-flex items-center justify-center rounded-full bg-emerald-500/20 text-emerald-300 text-[11px] px-3 py-1 font-semibold";
}

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th className="px-3 py-2 text-left text-[11px] font-semibold text-slate-400 uppercase tracking-wide">
      {children}
    </th>
  );
}

function Td({ children }: { children: React.ReactNode }) {
  return (
    <td className="px-3 py-2 text-[11px] align-top text-slate-100">
      {children}
    </td>
  );
}

function formatTimestamp(ts?: string) {
  if (!ts) return "-";

  const date = new Date(ts);
  if (isNaN(date.getTime())) return ts; // fallback if parsing fails

  return date
    .toLocaleString("en-US", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    })
    .replace(",", "");
}

function arraysEqual(a: AlertRow[], b: AlertRow[]) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (JSON.stringify(a[i]) !== JSON.stringify(b[i])) return false;
  }
  return true;
}