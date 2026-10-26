export interface ProbeTimings { dns_ms: number | null; connect_ms: number | null; tls_ms: number | null; response_ms: number | null }
export interface NetworkSample {
 family?: string; series?: string; task_id: number; name: string; latency_ms: number; loss?: number; mbps?: number; at?: number
 quality?: { epoch: string; sequence: number; type: string; outcome: string; duration_ms: number; http_status?: number; interval_seconds: number; timings?: ProbeTimings; window: { attempts: number; failed: number; min_ms: number | null; max_ms: number | null; p50_ms: number | null; p95_ms: number | null; jitter_ms: number | null } }
}
export interface NetworkPoint {
 family?: string; series?: string; task_id: number; name: string; ts: number; n: number; lost: number; avg_ms: number; avg_mbps?: number
 quality?: { samples: number; type: string; min_ms: number | null; max_ms: number | null; p50_ms: number | null; p95_ms: number | null; jitter_ms: number | null; timings: ProbeTimings; outcomes: Record<string, number>; skipped: number }
}
export interface NetworkHistory { current: NetworkSample[]; points: NetworkPoint[]; from: number; to: number; step: number }
