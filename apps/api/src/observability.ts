import { timingSafeEqual } from "node:crypto";

function metricLabel(value: string): string { return value.replaceAll("\\", "\\\\").replaceAll('"', '\\"').replaceAll("\n", "\\n"); }

export class RuntimeMetrics {
  private readonly startedAt = Date.now();
  private readonly requests = new Map<string, number>();
  private readonly durationMs = new Map<string, number>();
  private readonly errors = new Map<string, number>();

  observe(method: string, route: string, statusCode: number, elapsedMs: number): void {
    const normalizedRoute = route || "unmatched";
    const key = `${method}|${normalizedRoute}|${statusCode}`;
    this.requests.set(key, (this.requests.get(key) ?? 0) + 1);
    this.durationMs.set(key, (this.durationMs.get(key) ?? 0) + elapsedMs);
    if (statusCode >= 500) this.errors.set(normalizedRoute, (this.errors.get(normalizedRoute) ?? 0) + 1);
  }

  render(): string {
    const lines = [
      "# HELP cascadia_process_uptime_seconds Process uptime in seconds.", "# TYPE cascadia_process_uptime_seconds gauge",
      `cascadia_process_uptime_seconds ${Math.floor((Date.now() - this.startedAt) / 1000)}`,
      "# HELP cascadia_http_requests_total Completed HTTP requests.", "# TYPE cascadia_http_requests_total counter",
    ];
    for (const [key, count] of this.requests) {
      const [method, route, status] = key.split("|") as [string, string, string];
      lines.push(`cascadia_http_requests_total{method="${metricLabel(method)}",route="${metricLabel(route)}",status="${metricLabel(status)}"} ${count}`);
    }
    lines.push("# HELP cascadia_http_request_duration_milliseconds_total Cumulative request duration.", "# TYPE cascadia_http_request_duration_milliseconds_total counter");
    for (const [key, duration] of this.durationMs) {
      const [method, route, status] = key.split("|") as [string, string, string];
      lines.push(`cascadia_http_request_duration_milliseconds_total{method="${metricLabel(method)}",route="${metricLabel(route)}",status="${metricLabel(status)}"} ${duration.toFixed(3)}`);
    }
    lines.push("# HELP cascadia_http_server_errors_total HTTP 5xx responses.", "# TYPE cascadia_http_server_errors_total counter");
    for (const [route, count] of this.errors) lines.push(`cascadia_http_server_errors_total{route="${metricLabel(route)}"} ${count}`);
    return `${lines.join("\n")}\n`;
  }
}

export function secureTokenMatches(provided: string | undefined, expected: string | undefined): boolean {
  if (!provided || !expected) return false;
  const left = Buffer.from(provided);
  const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}
