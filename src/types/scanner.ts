export interface Vulnerability {
  id: string;
  type: 'XSS' | 'SQLi' | 'CSRF' | 'Directory Traversal' | 'Open Redirect' | 'Insecure Direct Object References' | 'Security Misconfiguration' | 'Sensitive Data Exposure' | 'Broken Authentication' | 'Insufficient Logging' | 'Injection';
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  title: string;
  description: string;
  evidence: string;
  recommendation: string;
  cwe?: string;
  owasp?: string;
}

export interface ScanResult {
  id: string;
  url: string;
  timestamp: Date;
  duration: number;
  vulnerabilities: Vulnerability[];
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
}

export interface ScanProgress {
  currentStep: string;
  progress: number;
  vulnerabilitiesFound: number;
}