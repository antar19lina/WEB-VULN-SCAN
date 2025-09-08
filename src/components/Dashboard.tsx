import React, { useState } from 'react';
import { BarChart, Download, Calendar, Globe, Shield, AlertTriangle, FileText, Table } from 'lucide-react';
import { ScanResult } from '../types/scanner';
import VulnerabilityCard from './VulnerabilityCard';
import { ReportGenerator } from '../utils/reportGenerator';

interface DashboardProps {
  scanResults: ScanResult[];
}

const Dashboard: React.FC<DashboardProps> = ({ scanResults }) => {
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(
    scanResults.length > 0 ? scanResults[0] : null
  );

  const exportReport = (scan: ScanResult) => {
    const jsonReport = ReportGenerator.generateJSONReport(scan);
    const blob = new Blob([jsonReport], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vulnerability_report_${scan.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportHTMLReport = (scan: ScanResult) => {
    const htmlReport = ReportGenerator.generateHTMLReport(scan);
    const blob = new Blob([htmlReport], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vulnerability_report_${scan.id}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportCSVReport = (scan: ScanResult) => {
    const csvReport = ReportGenerator.generateCSVReport(scan);
    const blob = new Blob([csvReport], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vulnerability_report_${scan.id}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (scanResults.length === 0) {
    return (
      <div className="text-center py-16">
        <Shield className="h-24 w-24 text-gray-600 mx-auto mb-6" />
        <h2 className="text-2xl font-semibold text-white mb-4">No Scans Available</h2>
        <p className="text-gray-400">
          Start your first vulnerability scan to see detailed results and analytics here.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Scan Selection */}
      <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-xl p-6">
        <h2 className="text-xl font-semibold text-white mb-6 flex items-center">
          <BarChart className="h-6 w-6 mr-2" />
          Scan History
        </h2>
        
        <div className="space-y-3">
          {scanResults.map((scan) => (
            <div
              key={scan.id}
              onClick={() => setSelectedScan(scan)}
              className={`p-4 rounded-lg border cursor-pointer transition-all ${
                selectedScan?.id === scan.id
                  ? 'border-green-400 bg-green-900/20'
                  : 'border-gray-600 bg-gray-900/30 hover:border-gray-500'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  <Globe className="h-5 w-5 text-gray-400" />
                  <div>
                    <p className="font-semibold text-white">{scan.url}</p>
                    <div className="flex items-center space-x-4 text-sm text-gray-400">
                      <span className="flex items-center space-x-1">
                        <Calendar className="h-4 w-4" />
                        <span>{scan.timestamp.toLocaleDateString()}</span>
                      </span>
                      <span>Duration: {scan.duration}s</span>
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center space-x-4">
                  {scan.totalVulnerabilities > 0 ? (
                    <div className="flex items-center space-x-2">
                      <AlertTriangle className="h-5 w-5 text-red-400" />
                      <span className="text-red-400 font-semibold">
                        {scan.totalVulnerabilities} vulnerabilities
                      </span>
                    </div>
                  ) : (
                    <div className="flex items-center space-x-2">
                      <Shield className="h-5 w-5 text-green-400" />
                      <span className="text-green-400 font-semibold">Secure</span>
                    </div>
                  )}
                  
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      exportReport(scan);
                    }}
                    className="px-3 py-1 bg-gray-700 hover:bg-gray-600 text-white rounded-md text-sm transition-colors flex items-center space-x-1"
                  >
                    <Download className="h-4 w-4" />
                    <span>Export</span>
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Selected Scan Details */}
      {selectedScan && (
        <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-xl p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-semibold text-white">Scan Details</h2>
            <div className="flex space-x-2">
              <button
                onClick={() => exportHTMLReport(selectedScan)}
                className="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors flex items-center space-x-1 text-sm"
              >
                <FileText className="h-4 w-4" />
                <span>HTML</span>
              </button>
              <button
                onClick={() => exportCSVReport(selectedScan)}
                className="px-3 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors flex items-center space-x-1 text-sm"
              >
                <Table className="h-4 w-4" />
                <span>CSV</span>
              </button>
              <button
                onClick={() => exportReport(selectedScan)}
                className="px-3 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg transition-colors flex items-center space-x-1 text-sm"
              >
                <Download className="h-4 w-4" />
                <span>JSON</span>
              </button>
            </div>
          </div>

          {/* Scan Overview */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div className="bg-gray-900/50 border border-gray-600 rounded-lg p-4">
              <h3 className="font-semibold text-white mb-2">Target Information</h3>
              <p className="text-gray-400 text-sm">URL: {selectedScan.url}</p>
              <p className="text-gray-400 text-sm">Scan ID: {selectedScan.id}</p>
              <p className="text-gray-400 text-sm">
                Completed: {selectedScan.timestamp.toLocaleString()}
              </p>
            </div>
            
            <div className="bg-gray-900/50 border border-gray-600 rounded-lg p-4">
              <h3 className="font-semibold text-white mb-2">Performance</h3>
              <p className="text-gray-400 text-sm">Duration: {selectedScan.duration} seconds</p>
              <p className="text-gray-400 text-sm">Checks Performed: 15</p>
              <p className="text-gray-400 text-sm">Response Time: Fast</p>
            </div>
            
            <div className="bg-gray-900/50 border border-gray-600 rounded-lg p-4">
              <h3 className="font-semibold text-white mb-2">Security Score</h3>
              <div className="flex items-center space-x-2 mb-2">
                {selectedScan.totalVulnerabilities === 0 ? (
                  <>
                    <div className="w-4 h-4 bg-green-400 rounded-full"></div>
                    <span className="text-green-400 font-semibold">Excellent</span>
                  </>
                ) : selectedScan.criticalCount > 0 || selectedScan.highCount > 0 ? (
                  <>
                    <div className="w-4 h-4 bg-red-400 rounded-full"></div>
                    <span className="text-red-400 font-semibold">Needs Attention</span>
                  </>
                ) : (
                  <>
                    <div className="w-4 h-4 bg-yellow-400 rounded-full"></div>
                    <span className="text-yellow-400 font-semibold">Fair</span>
                  </>
                )}
              </div>
              <p className="text-gray-400 text-sm">
                {selectedScan.totalVulnerabilities} total findings
              </p>
            </div>
          </div>

          {/* Vulnerabilities */}
          {selectedScan.vulnerabilities.length > 0 ? (
            <div className="space-y-4">
              <h3 className="text-lg font-semibold text-white">Identified Vulnerabilities</h3>
              {selectedScan.vulnerabilities.map((vulnerability) => (
                <VulnerabilityCard key={vulnerability.id} vulnerability={vulnerability} />
              ))}
            </div>
          ) : (
            <div className="text-center py-8 bg-green-900/20 border border-green-500/30 rounded-lg">
              <Shield className="h-12 w-12 text-green-400 mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-white mb-2">No Vulnerabilities Found</h3>
              <p className="text-gray-400">
                Congratulations! No security issues were detected during this scan.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default Dashboard;