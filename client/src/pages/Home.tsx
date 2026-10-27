import { useAuth } from "@/hooks/useAuth";
import DashboardLayout from "@/components/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
import {
  Activity,
  ArrowUpRight,
  CheckCircle2,
  CircleAlert,
  Database,
  FileSpreadsheet,
  Info,
  Loader2,
  RefreshCcw,
  ShieldCheck,
  Upload,
} from "lucide-react";
import { useRef, useState } from "react";

const numberFormatter = new Intl.NumberFormat("en-US");

function formatNumber(value: number) {
  return numberFormatter.format(value);
}

function timeAgo(value: Date | string | null) {
  if (!value) return "—";
  return new Date(value).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

export default function Home() {
  const { isAuthenticated } = useAuth();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [lastResult, setLastResult] = useState<Awaited<ReturnType<typeof trpc.analysis.run.useMutation>>["data"] | null>(null);

  const utils = trpc.useUtils();
  const contextQuery = trpc.workspace.context.useQuery(undefined, { enabled: isAuthenticated });
  const summaryQuery = trpc.dashboard.summary.useQuery(undefined, { enabled: isAuthenticated });
  const runsQuery = trpc.analysis.list.useQuery(undefined, { enabled: isAuthenticated });
  const alertsQuery = trpc.analysis.alerts.useQuery(undefined, { enabled: isAuthenticated });

  const analyzeMutation = trpc.analysis.run.useMutation({
    onSuccess: async result => {
      setLastResult(result);
      setSelectedFile(null);
      if (fileInputRef.current) fileInputRef.current.value = "";
      await Promise.all([
        utils.dashboard.summary.invalidate(),
        utils.analysis.list.invalidate(),
        utils.analysis.alerts.invalidate(),
      ]);
      toast.success(`Analysis complete: ${formatNumber(result.attackCount)} attacks detected.`);
    },
    onError: error => toast.error(error.message),
  });

  const summary = summaryQuery.data ?? {
    runCount: 0,
    rowsAnalyzed: 0,
    attacksDetected: 0,
    alertsStored: 0,
  };
  const requiredColumns = contextQuery.data?.requiredInputColumns ?? [];
  const recentAlerts = alertsQuery.data ?? [];
  const recentRuns = runsQuery.data ?? [];

  async function analyzeSelectedFile() {
    if (!selectedFile) {
      toast.error("Choose a CSV file first.");
      return;
    }
    if (!selectedFile.name.toLowerCase().endsWith(".csv")) {
      toast.error("For this MVP, upload a .csv file.");
      return;
    }
    if (selectedFile.size > 5_000_000) {
      toast.error("The MVP accepts CSV files up to 5 MB.");
      return;
    }

    const csv = await selectedFile.text();
    analyzeMutation.mutate({ fileName: selectedFile.name, csv });
  }

  return (
    <DashboardLayout>
      <div className="min-h-[calc(100vh-2rem)] bg-[#f7f8fb] -m-4 p-4 md:p-7">
        <div className="mx-auto max-w-7xl space-y-6">
          <section className="relative overflow-hidden rounded-3xl bg-[#08111f] px-6 py-8 text-white shadow-2xl shadow-slate-300/30 md:px-10 md:py-10">
            <div className="absolute -right-24 -top-24 h-72 w-72 rounded-full bg-cyan-400/20 blur-3xl" />
            <div className="absolute bottom-0 right-1/4 h-32 w-56 rounded-full bg-blue-500/20 blur-3xl" />
            <div className="relative flex flex-col justify-between gap-8 lg:flex-row lg:items-end">
              <div className="max-w-2xl">
                <div className="mb-5 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-cyan-300">
                  <span className="h-2 w-2 rounded-full bg-cyan-300 shadow-[0_0_12px_rgba(103,232,249,0.9)]" />
                  ToN-IoT security workspace
                </div>
                <h1 className="max-w-xl text-3xl font-semibold tracking-tight md:text-5xl">
                  See the signal before it becomes an incident.
                </h1>
                <p className="mt-4 max-w-xl text-sm leading-6 text-slate-300 md:text-base">
                  Upload network-flow records, run an analysis, and review prioritized attack alerts in one controlled workspace.
                </p>
              </div>
              <div className="rounded-2xl border border-white/10 bg-white/5 p-4 backdrop-blur-sm lg:min-w-72">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="text-xs uppercase tracking-widest text-slate-400">Detection Engine</p>
                    <p className="mt-2 font-medium">ToN-IoT Classifier v1.0</p>
                  </div>
                  <Badge className="border-emerald-300/30 bg-emerald-400/10 text-emerald-300">Active</Badge>
                </div>
                <p className="mt-3 text-xs leading-5 text-slate-400">
                  Real-time network anomaly scoring engine analyzing 19 telemetry features with calibrated confidence thresholds.
                </p>
              </div>
            </div>
          </section>

          <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <MetricCard icon={Activity} label="Analyses" value={formatNumber(summary.runCount)} detail="completed runs" />
            <MetricCard icon={Database} label="Rows analyzed" value={formatNumber(summary.rowsAnalyzed)} detail="across this workspace" />
            <MetricCard icon={CircleAlert} label="Attacks detected" value={formatNumber(summary.attacksDetected)} detail="model-positive records" accent="rose" />
            <MetricCard icon={ShieldCheck} label="Threshold" value={contextQuery.data ? contextQuery.data.decisionThreshold.toFixed(2) : "0.85"} detail="decision boundary" accent="cyan" />
          </section>

          <section className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
            <Card className="border-0 shadow-sm shadow-slate-200/70">
              <CardHeader className="border-b border-slate-100 pb-5">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <CardTitle className="flex items-center gap-2 text-lg"><Upload className="h-5 w-5 text-cyan-600" /> Analyze traffic</CardTitle>
                    <CardDescription className="mt-1.5">Start with a ToN-IoT network-flow CSV.</CardDescription>
                  </div>
                  <Badge variant="outline" className="border-slate-200 text-slate-500">CSV · max 5 MB</Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-5 pt-6">
                <label
                  htmlFor="csv-upload"
                  className="group flex min-h-44 cursor-pointer flex-col items-center justify-center rounded-2xl border border-dashed border-slate-300 bg-slate-50/80 px-6 text-center transition-colors hover:border-cyan-400 hover:bg-cyan-50/40"
                >
                  <div className="mb-3 rounded-xl bg-white p-3 shadow-sm ring-1 ring-slate-100 group-hover:ring-cyan-100">
                    <FileSpreadsheet className="h-6 w-6 text-cyan-600" />
                  </div>
                  <p className="text-sm font-medium text-slate-800">{selectedFile ? selectedFile.name : "Drop a CSV here or browse"}</p>
                  <p className="mt-1 text-xs text-slate-500">Required schema validation runs before inference.</p>
                  <Input ref={fileInputRef} id="csv-upload" type="file" accept=".csv,text/csv" className="sr-only" onChange={event => setSelectedFile(event.target.files?.[0] ?? null)} />
                </label>
                <div className="rounded-xl bg-cyan-50 px-4 py-3 text-xs leading-5 text-cyan-900 ring-1 ring-cyan-100">
                  <div className="flex gap-2"><Info className="mt-0.5 h-4 w-4 shrink-0" /><p><strong>Input validation:</strong> {requiredColumns.length || 19} standard ToN-IoT flow attributes are validated against the detection contract before scoring.</p></div>
                </div>
                <Button className="w-full bg-[#0e7490] text-white hover:bg-[#155e75]" size="lg" onClick={analyzeSelectedFile} disabled={!selectedFile || analyzeMutation.isPending}>
                  {analyzeMutation.isPending ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Analyzing traffic…</> : <><Activity className="mr-2 h-4 w-4" />Run analysis</>}
                </Button>
              </CardContent>
            </Card>

            <Card className="border-0 shadow-sm shadow-slate-200/70">
              <CardHeader className="border-b border-slate-100 pb-5">
                <CardTitle className="flex items-center gap-2 text-lg"><CheckCircle2 className="h-5 w-5 text-emerald-600" /> Model contract</CardTitle>
                <CardDescription className="mt-1.5">The active specification satisfying the ToN-IoT IDS framework.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4 pt-6">
                <ContractRow label="Model version" value={contextQuery.data?.modelVersion ?? "loading…"} />
                <ContractRow label="Decision threshold" value={contextQuery.data ? contextQuery.data.decisionThreshold.toFixed(2) : "0.85"} />
                <ContractRow label="Input columns" value={`${requiredColumns.length || 19} validated`} />
                <ContractRow label="Data isolation" value="Organization scoped" />
                <div className="rounded-xl bg-slate-900 p-4 text-xs leading-5 text-slate-300">
                  <p className="font-semibold text-white">Detection Specification</p>
                  <p className="mt-1">Trained on heterogeneous IoT telemetry capturing DoS, DDoS, Ransomware, Backdoor, Injection, and Scanning attack vectors.</p>
                </div>
              </CardContent>
            </Card>
          </section>

          {lastResult ? (
            <section className="rounded-2xl border border-cyan-100 bg-cyan-50/70 p-5" aria-live="polite">
              <div className="flex flex-col justify-between gap-4 md:flex-row md:items-center">
                <div>
                  <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-700">Latest analysis</p>
                  <h2 className="mt-1 text-xl font-semibold text-slate-900">{formatNumber(lastResult.rowCount)} rows processed</h2>
                  <p className="mt-1 text-sm text-slate-600">{formatNumber(lastResult.attackCount)} attacks identified · {formatNumber(lastResult.normalCount)} normal records · threshold {lastResult.decisionThreshold.toFixed(2)}</p>
                </div>
                <Button variant="outline" className="border-cyan-200 bg-white text-cyan-800 hover:bg-cyan-100" onClick={() => document.getElementById("alerts")?.scrollIntoView({ behavior: "smooth" })}>Review alerts <ArrowUpRight className="ml-2 h-4 w-4" /></Button>
              </div>
            </section>
          ) : null}

          <section id="alerts" className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
            <Card className="border-0 shadow-sm shadow-slate-200/70">
              <CardHeader className="flex flex-row items-center justify-between border-b border-slate-100 pb-5">
                <div>
                  <CardTitle className="text-lg">Recent alerts</CardTitle>
                  <CardDescription className="mt-1.5">Highest-priority model-positive records.</CardDescription>
                </div>
                <Button variant="ghost" size="icon" onClick={() => alertsQuery.refetch()} aria-label="Refresh alerts"><RefreshCcw className="h-4 w-4" /></Button>
              </CardHeader>
              <CardContent className="p-0">
                {recentAlerts.length === 0 ? (
                  <EmptyState text="Run your first CSV analysis to populate alerts." />
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm">
                      <thead className="bg-slate-50 text-xs uppercase tracking-wider text-slate-500"><tr><th className="px-6 py-3 font-medium">Severity</th><th className="px-6 py-3 font-medium">Probability</th><th className="px-6 py-3 font-medium">Destination</th><th className="px-6 py-3 font-medium">Detected</th></tr></thead>
                      <tbody className="divide-y divide-slate-100">
                        {recentAlerts.slice(0, 8).map(alert => <tr key={alert.id} className="hover:bg-slate-50/80"><td className="px-6 py-4"><SeverityBadge severity={alert.severity} /></td><td className="px-6 py-4 font-mono text-xs text-slate-700">{(Number(alert.probabilityAttack) * 100).toFixed(1)}%</td><td className="px-6 py-4 text-slate-700">{alert.dstIp ?? "Unknown host"}{alert.dstPort ? <span className="text-slate-400">:{alert.dstPort}</span> : null}</td><td className="whitespace-nowrap px-6 py-4 text-xs text-slate-500">{timeAgo(alert.createdAt)}</td></tr>)}
                      </tbody>
                    </table>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="border-0 shadow-sm shadow-slate-200/70">
              <CardHeader className="border-b border-slate-100 pb-5"><CardTitle className="text-lg">Analysis history</CardTitle><CardDescription className="mt-1.5">Your organization’s latest runs.</CardDescription></CardHeader>
              <CardContent className="p-0">
                {recentRuns.length === 0 ? <EmptyState text="No analysis runs yet." /> : <div className="divide-y divide-slate-100">{recentRuns.slice(0, 6).map(run => <div key={run.id} className="flex items-center justify-between gap-4 px-6 py-4"><div className="min-w-0"><p className="truncate text-sm font-medium text-slate-800">{run.fileName}</p><p className="mt-1 text-xs text-slate-500">{timeAgo(run.createdAt)} · {formatNumber(run.rowCount)} rows</p></div><Badge className="shrink-0 border-rose-100 bg-rose-50 text-rose-700">{formatNumber(run.attackCount)} alerts</Badge></div>)}</div>}
              </CardContent>
            </Card>
          </section>
        </div>
      </div>
    </DashboardLayout>
  );
}

function MetricCard({ icon: Icon, label, value, detail, accent = "blue" }: { icon: typeof Activity; label: string; value: string; detail: string; accent?: "blue" | "rose" | "cyan" }) {
  const iconClasses = { blue: "bg-blue-50 text-blue-700", rose: "bg-rose-50 text-rose-700", cyan: "bg-cyan-50 text-cyan-700" };
  return <Card className="border-0 shadow-sm shadow-slate-200/70"><CardContent className="p-5"><div className="flex items-start justify-between"><div><p className="text-xs font-semibold uppercase tracking-wider text-slate-500">{label}</p><p className="mt-3 text-3xl font-semibold tracking-tight text-slate-900">{value}</p><p className="mt-1 text-xs text-slate-500">{detail}</p></div><div className={`rounded-xl p-2.5 ${iconClasses[accent]}`}><Icon className="h-5 w-5" /></div></div></CardContent></Card>;
}

function ContractRow({ label, value }: { label: string; value: string }) {
  return <div className="flex items-center justify-between gap-4 border-b border-slate-100 pb-3 text-sm last:border-0 last:pb-0"><span className="text-slate-500">{label}</span><span className="text-right font-medium text-slate-800">{value}</span></div>;
}

function SeverityBadge({ severity }: { severity: string }) {
  const classes = severity === "critical" ? "bg-rose-100 text-rose-800" : severity === "high" ? "bg-orange-100 text-orange-800" : "bg-amber-100 text-amber-800";
  return <Badge className={`capitalize ${classes}`}>{severity}</Badge>;
}

function EmptyState({ text }: { text: string }) {
  return <div className="flex min-h-48 flex-col items-center justify-center px-6 text-center"><div className="rounded-full bg-slate-100 p-3"><ShieldCheck className="h-5 w-5 text-slate-400" /></div><p className="mt-3 text-sm text-slate-500">{text}</p></div>;
}
