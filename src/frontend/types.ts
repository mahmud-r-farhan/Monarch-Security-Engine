/**
 * Monarch Security Engine — Frontend TypeScript Type Definitions
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  id: string;
  category: string;
  severity: Severity;
  title: string;
  location?: string;
  description: string;
  evidence?: any;
  remediation?: string;
}

export interface SecurityScore {
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  counts: Record<Severity, number>;
}

export interface ScanReport {
  id: string;
  target: string;
  startedAt: string;
  finishedAt?: string;
  durationMs?: number;
  status: 'running' | 'done' | 'error';
  score?: SecurityScore;
  findings: Finding[];
  technologies?: Array<{ name: string; category: string; version?: string }>;
  rateLimits?: any;
  seo?: any;
  wpAdmin?: any;
  insights?: {
    summary?: string;
    actionPlan?: Array<{ priority: string; title: string; remediation: string }>;
  };
  network?: any[];
}

export interface NetworkInterface {
  name: string;
  address: string;
  netmask: string;
  mac: string;
  cidr?: string;
  internal: boolean;
  vendor?: string;
}

export interface DiscoveredHost {
  ip: string;
  mac?: string | null;
  vendor?: string;
  hostname?: string | null;
  interface?: string | null;
  isGateway?: boolean;
  isSelf?: boolean;
  alive?: boolean;
  rtt?: number | null;
  openPorts?: Array<{
    port: number;
    proto?: 'tcp' | 'udp';
    open: boolean;
    service?: string;
    banner?: string | null;
    latencyMs?: number;
  }>;
  lastSeen?: string;
}

export interface UptimeMonitor {
  id: string;
  name: string;
  url: string;
  intervalSeconds: number;
  expectedStatus: number;
  keyword?: string;
  active: boolean;
  status: 'up' | 'down' | 'degraded' | 'paused';
  uptimePercent: number;
  lastLatencyMs?: number;
  history?: Array<{
    timestamp: number;
    status: 'up' | 'down' | 'degraded';
    latencyMs: number;
  }>;
}

export interface AiConfig {
  provider: 'openrouter' | 'openai' | 'anthropic' | 'gemini' | 'none';
  apiKey: string;
  model?: string;
}

export interface AppState {
  activeView: string;
  activeSubtab: string;
  currentScan: ScanReport | null;
  scansHistory: ScanReport[];
  monitors: UptimeMonitor[];
  discoveredDevices: DiscoveredHost[];
  networkInterfaces: NetworkInterface[];
  gateway: string | null;
  aiConfig: AiConfig;
  filters: {
    findingText: string;
    severities: Set<Severity>;
  };
  ws: WebSocket | null;
}
