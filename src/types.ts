export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface SecurityEvent {
  id: string;
  timestamp: string | null;
  severity: Severity | string;
  title: string;
  description: string;
  assetHostname: string;
  assetIp: string | null;
  sourceIp: string | null;
  tags: string[];
  userId: string | null;
  threatFlags: string[];
}

export interface User {
  id: string;
  email: string;
  role: string;
  status: string;
}

export interface CurrentUser {
  id: string;
  email: string;
  role: string;
  status?: string;
}
