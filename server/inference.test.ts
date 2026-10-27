import { describe, expect, it } from "vitest";
import { REQUIRED_INPUT_COLUMNS, runInference, runPrototypeInference } from "./inference";

function csvWithRow(overrides: Record<string, string> = {}) {
  const headers = [...REQUIRED_INPUT_COLUMNS, "src_ip", "dst_ip"];
  const row = headers.map(header => overrides[header] ?? (header === "proto" ? "tcp" : header === "service" ? "http" : header === "conn_state" ? "SF" : "0"));
  return `${headers.join(",")}\n${row.join(",")}\n`;
}

describe("prototype inference adapter", () => {
  it("requires the production input columns", () => {
    expect(() => runPrototypeInference("src_port,dst_port\n1,2\n")).toThrow(/Missing required columns/);
  });

  it("returns normal traffic for an unremarkable row", () => {
    const result = runPrototypeInference(csvWithRow({ dst_port: "80", src_bytes: "300", dst_bytes: "1800" }));
    expect(result.rowCount).toBe(1);
    expect(result.attackCount).toBe(0);
    expect(result.predictions[0]?.predictionName).toBe("normal");
  });

  it("raises a high-confidence alert for a suspicious row", () => {
    const result = runPrototypeInference(csvWithRow({
      dst_port: "445",
      missed_bytes: "100",
      http_request_body_len: "4096",
      conn_state: "REJ",
      src_bytes: "200000",
    }));
    expect(result.attackCount).toBe(1);
    expect(result.predictions[0]?.predictionName).toBe("attack");
    expect(result.predictions[0]?.probabilityAttack).toBeGreaterThanOrEqual(0.85);
    expect(result.predictions[0]?.severity).toMatch(/high|critical/);
  });

  it("falls back to local inference when the microservice is unreachable", async () => {
    const result = await runInference(
      csvWithRow({ dst_port: "80", src_bytes: "300", dst_bytes: "1800" }),
      "http://127.0.0.1:9999" // Non-existent port
    );
    expect(result.rowCount).toBe(1);
    expect(result.attackCount).toBe(0);
  });
});

