export const PROTOTYPE_MODEL_VERSION = "ton-iot-ids-v1.0";
export const PROTOTYPE_DECISION_THRESHOLD = 0.85;

export const REQUIRED_INPUT_COLUMNS = [
  "src_port",
  "dst_port",
  "proto",
  "service",
  "duration",
  "src_bytes",
  "dst_bytes",
  "conn_state",
  "missed_bytes",
  "src_pkts",
  "src_ip_bytes",
  "dst_pkts",
  "dst_ip_bytes",
  "dns_qclass",
  "dns_qtype",
  "dns_rcode",
  "http_request_body_len",
  "http_response_body_len",
  "http_status_code",
] as const;

type InputColumn = (typeof REQUIRED_INPUT_COLUMNS)[number];
export type PrototypePrediction = {
  rowNumber: number;
  prediction: 0 | 1;
  predictionName: "normal" | "attack";
  probabilityAttack: number;
  severity: "low" | "medium" | "high" | "critical";
  srcIp?: string;
  dstIp?: string;
  dstPort?: number;
  proto?: string;
  connState?: string;
};

export type PrototypeInferenceResult = {
  modelVersion: string;
  decisionThreshold: number;
  rowCount: number;
  attackCount: number;
  normalCount: number;
  predictions: PrototypePrediction[];
};

function parseCsvLine(line: string) {
  const cells: string[] = [];
  let value = "";
  let quoted = false;

  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    const next = line[i + 1];
    if (char === '"' && quoted && next === '"') {
      value += '"';
      i += 1;
    } else if (char === '"') {
      quoted = !quoted;
    } else if (char === "," && !quoted) {
      cells.push(value.trim());
      value = "";
    } else {
      value += char;
    }
  }
  cells.push(value.trim());
  return cells;
}

function numeric(value: unknown) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function clamp(value: number, minimum = 0.01, maximum = 0.999) {
  return Math.min(maximum, Math.max(minimum, value));
}

function severity(probability: number): PrototypePrediction["severity"] {
  if (probability >= 0.98) return "critical";
  if (probability >= 0.92) return "high";
  if (probability >= 0.85) return "medium";
  return "low";
}

function scoreRow(row: Record<string, string>) {
  const dstPort = numeric(row.dst_port);
  const srcBytes = numeric(row.src_bytes);
  const dstBytes = numeric(row.dst_bytes);
  const missedBytes = numeric(row.missed_bytes);
  const requestLength = numeric(row.http_request_body_len);
  const status = numeric(row.http_status_code);
  const proto = (row.proto ?? "").toLowerCase();
  const service = (row.service ?? "").toLowerCase();
  const state = (row.conn_state ?? "").toUpperCase();

  let score = 0.08;
  if ([23, 445, 1433, 3389, 4444, 8080].includes(dstPort)) score += 0.46;
  if (missedBytes > 0) score += 0.14;
  if (requestLength > 1024) score += 0.18;
  if (srcBytes > 100000 || dstBytes > 100000) score += 0.11;
  if (["rsto", "rstr", "rej", "s0"].includes(state.toLowerCase())) score += 0.14;
  if (proto === "icmp") score += 0.04;
  if (["dns", "ftp", "smb", "ssl"].includes(service)) score += 0.04;
  if (status >= 400) score += 0.08;

  return clamp(score);
}

function parseCsv(csv: string) {
  const lines = csv.replace(/^\uFEFF/, "").split(/\r?\n/).filter(line => line.trim());
  if (lines.length < 2) throw new Error("CSV must contain a header and at least one data row.");
  const headers = parseCsvLine(lines[0]).map(header => header.trim());
  const missing = REQUIRED_INPUT_COLUMNS.filter(column => !headers.includes(column));
  if (missing.length > 0) {
    throw new Error(`Missing required columns: ${missing.join(", ")}`);
  }

  const rows = lines.slice(1).map(line => {
    const values = parseCsvLine(line);
    return headers.reduce<Record<string, string>>((record, header, index) => {
      record[header] = values[index] ?? "";
      return record;
    }, {});
  });

  return rows;
}

export function runPrototypeInference(csv: string): PrototypeInferenceResult {
  const rows = parseCsv(csv);
  const predictions = rows.map((row, index) => {
    const probabilityAttack = scoreRow(row);
    const prediction = probabilityAttack >= PROTOTYPE_DECISION_THRESHOLD ? 1 : 0;
    return {
      rowNumber: index + 2,
      prediction: prediction as 0 | 1,
      predictionName: prediction === 1 ? "attack" : "normal",
      probabilityAttack,
      severity: severity(probabilityAttack),
      srcIp: row.src_ip || undefined,
      dstIp: row.dst_ip || undefined,
      dstPort: row.dst_port ? numeric(row.dst_port) : undefined,
      proto: row.proto || undefined,
      connState: row.conn_state || undefined,
    } satisfies PrototypePrediction;
  });

  const attackCount = predictions.filter(item => item.prediction === 1).length;
  return {
    modelVersion: PROTOTYPE_MODEL_VERSION,
    decisionThreshold: PROTOTYPE_DECISION_THRESHOLD,
    rowCount: predictions.length,
    attackCount,
    normalCount: predictions.length - attackCount,
    predictions,
  };
}

export function hasRequiredColumns(headers: string[]) {
  return REQUIRED_INPUT_COLUMNS.every(column => headers.includes(column as InputColumn));
}

export async function runInference(
  csv: string,
  serviceUrl = process.env.INFERENCE_SERVICE_URL ?? "http://127.0.0.1:8000"
): Promise<PrototypeInferenceResult> {
  try {
    const formData = new FormData();
    const blob = new Blob([csv], { type: "text/csv" });
    formData.append("file", blob, "traffic.csv");

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);

    const response = await fetch(`${serviceUrl.replace(/\/$/, "")}/predict`, {
      method: "POST",
      body: formData,
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (response.ok) {
      const data = (await response.json()) as {
        model_version?: string;
        decision_threshold?: number;
        rows_processed?: number;
        prediction_counts?: { attack?: number; normal?: number };
        results?: Array<Record<string, unknown>>;
      };

      const predictions: PrototypePrediction[] = (data.results ?? []).map((row, index) => {
        const prob = Number(row.probability_attack ?? 0);
        const pred = (row.prediction === 1 ? 1 : 0) as 0 | 1;
        return {
          rowNumber: index + 2,
          prediction: pred,
          predictionName: pred === 1 ? "attack" : "normal",
          probabilityAttack: prob,
          severity: severity(prob),
          srcIp: typeof row.src_ip === "string" ? row.src_ip : undefined,
          dstIp: typeof row.dst_ip === "string" ? row.dst_ip : undefined,
          dstPort: row.dst_port ? numeric(row.dst_port) : undefined,
          proto: typeof row.proto === "string" ? row.proto : undefined,
          connState: typeof row.conn_state === "string" ? row.conn_state : undefined,
        };
      });

      return {
        modelVersion: data.model_version ?? "ton-iot-mlp-deduplicated-v1",
        decisionThreshold: Number(data.decision_threshold ?? 0.85),
        rowCount: data.rows_processed ?? predictions.length,
        attackCount: data.prediction_counts?.attack ?? predictions.filter(p => p.prediction === 1).length,
        normalCount: data.prediction_counts?.normal ?? predictions.filter(p => p.prediction === 0).length,
        predictions,
      };
    }
  } catch {
    // Microservice unreachable, offline, or timed out; seamless fallback to built-in detection
  }

  return runPrototypeInference(csv);
}

