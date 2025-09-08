import React, { useState } from 'react';
import { Shield, AlertTriangle, CheckCircle, XCircle, Download, Play, Pause, RotateCcw } from 'lucide-react';
import Scanner from './components/Scanner';
import Dashboard from './components/Dashboard';
import VulnerabilityCard from './components/VulnerabilityCard';
import { ScanResult, Vulnerability } from './types/scanner';

function App() {
  const [activeTab, setActiveTab] = useState<'scanner' | 'dashboard'>('scanner');
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);

  const handleScanComplete = (results: ScanResult[]) => {
    setScanResults(results);
    setActiveTab('dashboard');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black text-green-400">
      {/* Header */}
      <header className="border-b border-gray-700 bg-black/50 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8 text-green-400" />
              <div>
                <h1 className="text-2xl font-bold text-white">VulnScanner Pro</h1>
                <p className="text-sm text-gray-400">Educational Web Vulnerability Detection Tool</p>
              </div>
            </div>
            
            {/* Navigation */}
            <nav className="flex space-x-1 bg-gray-800 p-1 rounded-lg">
              <button
                onClick={() => setActiveTab('scanner')}
                className={`px-4 py-2 rounded-md transition-all ${
                  activeTab === 'scanner'
                    ? 'bg-green-400 text-black font-semibold'
                    : 'text-gray-300 hover:text-white hover:bg-gray-700'
                }`}
              >
                Scanner
              </button>
              <button
                onClick={() => setActiveTab('dashboard')}
                className={`px-4 py-2 rounded-md transition-all ${
                  activeTab === 'dashboard'
                    ? 'bg-green-400 text-black font-semibold'
                    : 'text-gray-300 hover:text-white hover:bg-gray-700'
                }`}
              >
                Dashboard
              </button>
            </nav>
          </div>
        </div>
      </header>

      {/* Warning Banner */}
      <div className="bg-red-900/30 border border-red-500/50 mx-4 mt-4 p-4 rounded-lg">
        <div className="flex items-center space-x-2">
          <AlertTriangle className="h-5 w-5 text-red-400" />
          <p className="text-red-200 font-medium">
            ⚠️ EDUCATIONAL PURPOSE ONLY - Only scan websites you own or have explicit permission to test
          </p>
        </div>
      </div>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'scanner' ? (
          <Scanner onScanComplete={handleScanComplete} />
        ) : (
          <Dashboard scanResults={scanResults} />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-700 bg-black/30 mt-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <p className="text-center text-gray-500 text-sm">
            Built for educational purposes. Always obtain proper authorization before security testing.
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;