import React, { useState } from 'react';
import { Shield, Target, AlertTriangle, BookOpen, Play, Pause, RotateCcw, Globe } from 'lucide-react';
import { ScanEngine } from '../utils/scanEngine';
import { ScanProgress, ScanResult } from '../types/scanner';

interface ScannerProps {
  onScanComplete: (results: ScanResult[]) => void;
}

const Scanner: React.FC<ScannerProps> = ({ onScanComplete }) => {
  const [targetUrl, setTargetUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState<ScanProgress | null>(null);
  const [scanEngine] = useState(() => new ScanEngine());

  const handleStartScan = async () => {
    if (!targetUrl.trim()) {
      alert('Please enter a target URL');
      return;
    }

    // Validate URL format
    try {
      new URL(targetUrl);
    } catch {
      alert('Please enter a valid URL (e.g., https://example.com)');
      return;
    }

    setIsScanning(true);
    setScanProgress({ currentStep: 'Initializing scan...', progress: 0, vulnerabilitiesFound: 0 });

    try {
      const result = await scanEngine.performScan(targetUrl, (progress) => {
        setScanProgress(progress);
      });

      onScanComplete([result]);
    } catch (error) {
      console.error('Scan failed:', error);
      alert('Scan failed. Please check the URL and try again.');
    } finally {
      setIsScanning(false);
      setScanProgress(null);
    }
  };

  const handleStopScan = () => {
    scanEngine.stopScan();
    setIsScanning(false);
    setScanProgress(null);
  };

  return (
    <div className="space-y-8">
      {/* Scan Configuration */}
      <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-xl p-6">
        <h2 className="text-xl font-semibold text-white mb-6 flex items-center">
          <Target className="h-6 w-6 mr-2" />
          Target Configuration
        </h2>
        
        <div className="space-y-4">
          <div>
            <label htmlFor="target-url" className="block text-sm font-medium text-gray-300 mb-2">
              Target URL
            </label>
            <div className="flex space-x-3">
              <div className="flex-1 relative">
                <Globe className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
                <input
                  id="target-url"
                  type="url"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="w-full pl-10 pr-4 py-3 bg-gray-900/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-green-400 focus:border-transparent"
                  disabled={isScanning}
                />
              </div>
              
              {!isScanning ? (
                <button
                  onClick={handleStartScan}
                  disabled={!targetUrl.trim()}
                  className="px-6 py-3 bg-green-600 hover:bg-green-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded-lg font-semibold transition-colors flex items-center space-x-2"
                >
                  <Play className="h-5 w-5" />
                  <span>Start Scan</span>
                </button>
              ) : (
                <button
                  onClick={handleStopScan}
                  className="px-6 py-3 bg-red-600 hover:bg-red-700 text-white rounded-lg font-semibold transition-colors flex items-center space-x-2"
                >
                  <Pause className="h-5 w-5" />
                  <span>Stop Scan</span>
                </button>
              )}
            </div>
          </div>

          {/* Scan Progress */}
          {scanProgress && (
            <div className="bg-gray-900/50 border border-gray-600 rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-white">Scanning Progress</span>
                <span className="text-sm text-gray-400">{scanProgress.progress}%</span>
              </div>
              
              <div className="w-full bg-gray-700 rounded-full h-2 mb-3">
                <div
                  className="bg-green-400 h-2 rounded-full transition-all duration-300"
                  style={{ width: `${scanProgress.progress}%` }}
                ></div>
              </div>
              
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-300">{scanProgress.currentStep}</span>
                <span className="text-green-400">
                  {scanProgress.vulnerabilitiesFound} vulnerabilities found
                </span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* OWASP Top 10 Overview */}
      <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-xl p-6">
        <h2 className="text-xl font-semibold text-white mb-6 flex items-center">
          <BookOpen className="h-6 w-6 mr-2" />
          OWASP Top 10 Vulnerabilities (2021)
        </h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
          {[
            { rank: 'A01', name: 'Broken Access Control', color: 'red' },
            { rank: 'A02', name: 'Cryptographic Failures', color: 'orange' },
            { rank: 'A03', name: 'Injection', color: 'yellow' },
            { rank: 'A04', name: 'Insecure Design', color: 'blue' },
            { rank: 'A05', name: 'Security Misconfiguration', color: 'purple' },
            { rank: 'A06', name: 'Vulnerable Components', color: 'pink' },
            { rank: 'A07', name: 'Identification Failures', color: 'green' },
            { rank: 'A08', name: 'Software Integrity', color: 'indigo' },
            { rank: 'A09', name: 'Security Logging Failures', color: 'teal' },
            { rank: 'A10', name: 'Server-Side Request Forgery', color: 'cyan' }
          ].map((item, index) => (
            <div
              key={index}
              className="bg-gray-900/50 border border-gray-600 rounded-lg p-3 text-center hover:border-gray-500 transition-colors"
            >
              <div className="text-lg font-bold text-green-400">{item.rank}</div>
              <div className="text-xs text-gray-300 leading-tight">{item.name}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Detection Capabilities */}
      <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-xl p-6">
        <h2 className="text-xl font-semibold text-white mb-6">Detection Capabilities</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {[
            {
              name: 'Cross-Site Scripting (XSS)',
              description: 'Detects reflected, stored, and DOM-based XSS with advanced payloads',
              icon: '🔓',
              severity: 'High'
            },
            {
              name: 'SQL Injection',
              description: 'Advanced SQL injection testing including blind and time-based attacks',
              icon: '💉',
              severity: 'Critical'
            },
            {
              name: 'Authentication Flaws',
              description: 'Tests for weak credentials, session management, and user enumeration',
              icon: '🔄',
              severity: 'Critical'
            },
            {
              name: 'Directory Traversal & LFI',
              description: 'Advanced path traversal testing with encoding and filter bypass',
              icon: '📁',
              severity: 'High'
            },
            {
              name: 'Command Injection',
              description: 'Tests for OS command injection vulnerabilities',
              icon: '⚡',
              severity: 'Critical'
            },
            {
              name: 'Information Disclosure',
              description: 'Discovers sensitive files, directories, and configuration leaks',
              icon: '📋',
              severity: 'Medium'
            },
            {
              name: 'SSL/TLS Configuration',
              description: 'Analyzes HTTPS implementation and mixed content issues',
              icon: '🔒',
              severity: 'High'
            },
            {
              name: 'Open Redirect & URL Manipulation',
              description: 'Advanced redirect testing with encoding and filter bypass',
              icon: '↗️',
              severity: 'Medium'
            },
            {
              name: 'Security Headers & CSP',
              description: 'Comprehensive security headers analysis and CSP validation',
              icon: '🛡️',
              severity: 'Medium'
            },
            {
              name: 'Input Validation',
              description: 'Tests application input handling and validation mechanisms',
              icon: '✅',
              severity: 'Medium'
            }
          ].map((vuln, index) => (
            <div key={index} className="bg-gray-900/50 border border-gray-600 rounded-lg p-4 hover:border-gray-500 transition-colors">
              <div className="flex items-center space-x-3 mb-2">
                <span className="text-2xl">{vuln.icon}</span>
                <div>
                  <h3 className="font-semibold text-white text-sm">{vuln.name}</h3>
                  <span className={`text-xs px-2 py-1 rounded ${
                    vuln.severity === 'Critical' ? 'bg-red-600 text-white' :
                    vuln.severity === 'High' ? 'bg-orange-600 text-white' :
                    vuln.severity === 'Medium' ? 'bg-yellow-600 text-black' : 'bg-blue-600 text-white'
                  }`}>
                    {vuln.severity}
                  </span>
                </div>
              </div>
              <p className="text-gray-400 text-xs">{vuln.description}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Usage Guidelines */}
      <div className="bg-red-900/20 border border-red-500/50 rounded-xl p-6">
        <h2 className="text-xl font-semibold text-red-300 mb-4 flex items-center">
          <AlertTriangle className="h-6 w-6 mr-2" />
          Ethical Usage Guidelines
        </h2>
        
        <div className="space-y-3 text-sm text-red-200">
          <p>⚠️ <strong>Only scan websites you own or have explicit written permission to test</strong></p>
          <p>🚫 Unauthorized scanning is illegal and may violate computer fraud laws</p>
          <p>📋 Always get permission in writing before conducting security assessments</p>
          <p>🛡️ Use this tool responsibly for educational and authorized testing purposes only</p>
          <p>📚 Consider formal penetration testing training and certification</p>
        </div>
      </div>
    </div>
  );
};

export default Scanner;