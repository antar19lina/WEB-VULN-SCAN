import { ScanResult } from '../types/scanner';

export class ReportGenerator {
  static generateHTMLReport(scan: ScanResult): string {
    const severityColors = {
      Critical: '#DC2626',
      High: '#EA580C', 
      Medium: '#D97706',
      Low: '#2563EB',
      Info: '#6B7280'
    };

    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report - ${scan.url}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f8f9fa;
            color: #212529;
            line-height: 1.6;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            background: linear-gradient(135deg, #1f2937, #111827);
            color: white;
            padding: 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header h1 { margin: 0 0 1rem 0; font-size: 2rem; }
        .header p { margin: 0.5rem 0; opacity: 0.9; }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 2rem 0;
        }
        .stat-card {
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
            border-top: 4px solid #e5e7eb;
        }
        .stat-card h3 { margin: 0 0 0.5rem 0; color: #6b7280; font-size: 0.9rem; }
        .stat-card .value { font-size: 2rem; font-weight: bold; margin: 0; }
        .vulnerability {
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid;
        }
        .critical { border-left-color: #DC2626; }
        .high { border-left-color: #EA580C; }
        .medium { border-left-color: #D97706; }
        .low { border-left-color: #2563EB; }
        .info { border-left-color: #6B7280; }
        .vulnerability h3 { margin: 0 0 1rem 0; color: #1f2937; }
        .vulnerability .meta { 
            display: flex; 
            gap: 1rem; 
            margin-bottom: 1rem; 
            font-size: 0.9rem;
            color: #6b7280;
        }
        .vulnerability .section { margin: 1rem 0; }
        .vulnerability .section h4 { 
            margin: 0 0 0.5rem 0; 
            color: #374151; 
            font-size: 1rem;
        }
        .evidence {
            background: #f1f5f9;
            border: 1px solid #e2e8f0;
            border-radius: 4px;
            padding: 1rem;
            font-family: 'Courier New', monospace;
            white-space: pre-wrap;
            margin: 0.5rem 0;
            font-size: 0.9rem;
        }
        .no-vulns {
            text-align: center;
            padding: 3rem;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            color: #16a34a;
        }
        .disclaimer {
            margin-top: 3rem;
            padding: 2rem;
            background: #fef3c7;
            border-radius: 8px;
            border: 1px solid #f59e0b;
            color: #92400e;
        }
        .disclaimer h3 { margin: 0 0 1rem 0; color: #92400e; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Vulnerability Scan Report</h1>
            <p><strong>Target:</strong> ${scan.url}</p>
            <p><strong>Scan Date:</strong> ${scan.timestamp.toLocaleString()}</p>
            <p><strong>Duration:</strong> ${scan.duration} seconds</p>
            <p><strong>Scan ID:</strong> ${scan.id}</p>
        </div>

        <div class="summary">
            <div class="stat-card">
                <h3>Total Vulnerabilities</h3>
                <div class="value" style="color: ${scan.totalVulnerabilities > 0 ? '#DC2626' : '#16a34a'};">
                    ${scan.totalVulnerabilities}
                </div>
            </div>
            <div class="stat-card">
                <h3>Critical</h3>
                <div class="value" style="color: #DC2626;">
                    ${scan.criticalCount}
                </div>
            </div>
            <div class="stat-card">
                <h3>High</h3>
                <div class="value" style="color: #EA580C;">
                    ${scan.highCount}
                </div>
            </div>
            <div class="stat-card">
                <h3>Medium</h3>
                <div class="value" style="color: #D97706;">
                    ${scan.mediumCount}
                </div>
            </div>
            <div class="stat-card">
                <h3>Low</h3>
                <div class="value" style="color: #2563EB;">
                    ${scan.lowCount}
                </div>
            </div>
        </div>

        <h2 style="color: #1f2937; margin: 2rem 0 1rem 0;">Detailed Findings</h2>
        
        ${scan.vulnerabilities.length === 0 ? 
          '<div class="no-vulns"><h3>✅ No vulnerabilities detected</h3><p>The target appears to be secure against the tested vulnerability types.</p></div>' :
          scan.vulnerabilities.map(vuln => `
            <div class="vulnerability ${vuln.severity.toLowerCase()}">
                <h3>${vuln.title}</h3>
                <div class="meta">
                    <span><strong>Type:</strong> ${vuln.type}</span>
                    <span><strong>Severity:</strong> ${vuln.severity}</span>
                    ${vuln.cwe ? `<span><strong>CWE:</strong> ${vuln.cwe}</span>` : ''}
                    ${vuln.owasp ? `<span><strong>OWASP:</strong> ${vuln.owasp}</span>` : ''}
                </div>
                
                <div class="section">
                    <h4>Description</h4>
                    <p>${vuln.description}</p>
                </div>
                
                <div class="section">
                    <h4>Evidence</h4>
                    <div class="evidence">${vuln.evidence}</div>
                </div>
                
                <div class="section">
                    <h4>Recommendation</h4>
                    <p>${vuln.recommendation}</p>
                </div>
            </div>
        `).join('')}

        <div class="disclaimer">
            <h3>⚠️ Important Disclaimer</h3>
            <p>This report is generated for educational and authorized testing purposes only. 
            Ensure you have proper permission before conducting security assessments on any web application.
            Unauthorized vulnerability scanning may violate laws and terms of service.</p>
        </div>
    </div>
</body>
</html>`;
  }

  static generateJSONReport(scan: ScanResult): string {
    return JSON.stringify({
      report_metadata: {
        generated_at: new Date().toISOString(),
        tool: 'VulnScanner Pro',
        version: '1.0.0',
        scan_type: 'Automated Web Application Security Assessment'
      },
      scan_details: {
        id: scan.id,
        target_url: scan.url,
        start_time: scan.timestamp.toISOString(),
        duration_seconds: scan.duration,
        total_vulnerabilities: scan.totalVulnerabilities,
        status: 'completed'
      },
      severity_summary: {
        critical: scan.criticalCount,
        high: scan.highCount,
        medium: scan.mediumCount,
        low: scan.lowCount,
        info: scan.infoCount
      },
      vulnerabilities: scan.vulnerabilities.map(vuln => ({
        id: vuln.id,
        type: vuln.type,
        severity: vuln.severity,
        title: vuln.title,
        description: vuln.description,
        evidence: vuln.evidence,
        recommendation: vuln.recommendation,
        references: {
          cwe: vuln.cwe,
          owasp: vuln.owasp
        },
        risk_score: this.calculateRiskScore(vuln.severity)
      })),
      recommendations: {
        immediate_actions: scan.vulnerabilities
          .filter(v => v.severity === 'Critical' || v.severity === 'High')
          .map(v => v.recommendation),
        general_security: [
          'Implement a Web Application Firewall (WAF)',
          'Regular security code reviews',
          'Automated security testing in CI/CD pipeline',
          'Security awareness training for developers'
        ]
      }
    }, null, 2);
  }

  private static calculateRiskScore(severity: string): number {
    switch (severity) {
      case 'Critical': return 10;
      case 'High': return 7;
      case 'Medium': return 5;
      case 'Low': return 3;
      case 'Info': return 1;
      default: return 0;
    }
  }

  static generateCSVReport(scan: ScanResult): string {
    const headers = [
      'ID',
      'Type',
      'Severity',
      'Title',
      'Description',
      'Evidence',
      'Recommendation',
      'CWE',
      'OWASP',
      'Risk Score'
    ];

    const rows = scan.vulnerabilities.map(vuln => [
      vuln.id,
      vuln.type,
      vuln.severity,
      `"${vuln.title}"`,
      `"${vuln.description}"`,
      `"${vuln.evidence}"`,
      `"${vuln.recommendation}"`,
      vuln.cwe || '',
      vuln.owasp || '',
      this.calculateRiskScore(vuln.severity)
    ]);

    return [headers.join(','), ...rows.map(row => row.join(','))].join('\n');
  }
}