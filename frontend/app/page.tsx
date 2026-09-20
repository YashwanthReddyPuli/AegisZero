'use client';

import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Activity,
  AlertTriangle,
  Clock,
  Radio,
  Search,
  Terminal,
  Cpu,
  Server,
  AlertOctagon,
  CheckCircle2,
  Lock
} from 'lucide-react';

interface PayloadScanResponse {
  status: string;
  payload: string;
  threat_detected: boolean;
  confidence_score: number;
}

interface TrafficAnalysisResponse {
  status: string;
  intrusion_detected: boolean;
  confidence_score: number;
}

export default function SOCDashboard() {
  // --- Data Payload Inspector State ---
  const [payload, setPayload] = useState("admin' --");
  const [payloadLoading, setPayloadLoading] = useState(false);
  const [payloadResult, setPayloadResult] = useState<PayloadScanResponse | null>(null);
  const [payloadError, setPayloadError] = useState<string | null>(null);

  // --- Network Activity Monitor State ---
  const [duration, setDuration] = useState<number>(0.8);
  const [packetSize, setPacketSize] = useState<number>(512);
  const [failedLogins, setFailedLogins] = useState<number>(0);
  const [protocol, setProtocol] = useState<number>(0); // 0=TCP, 1=UDP
  
  const [trafficLoading, setTrafficLoading] = useState(false);
  const [trafficResult, setTrafficResult] = useState<TrafficAnalysisResponse | null>(null);
  const [trafficError, setTrafficError] = useState<string | null>(null);

  const [apiUrl, setApiUrl] = useState(process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000');

  // --- Data Payload Assessment Handler ---
  const handlePayloadAssess = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!payload.trim()) return;

    setPayloadLoading(true);
    setPayloadError(null);
    setPayloadResult(null);

    const primaryUrl = `${apiUrl.replace(/\/$/, '')}/api/v1/scan-payload`;

    try {
      let response;
      try {
        response = await fetch(primaryUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ payload }),
        });
      } catch {
        if (apiUrl.includes('8000')) {
          const fallbackUrl = 'http://localhost:8001/api/v1/scan-payload';
          response = await fetch(fallbackUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ payload }),
          });
          setApiUrl('http://localhost:8001');
        } else {
          throw new Error('Connection failed');
        }
      }

      if (!response || !response.ok) {
        throw new Error(`HTTP error ${response?.status || 500}`);
      }

      const data: PayloadScanResponse = await response.json();
      setPayloadResult(data);
    } catch (err: any) {
      setPayloadError(err.message || 'Unable to connect to security backend');
    } finally {
      setPayloadLoading(false);
    }
  };

  // --- Network Activity Assessment Handler ---
  const handleTrafficAssess = async (e: React.FormEvent) => {
    e.preventDefault();

    setTrafficLoading(true);
    setTrafficError(null);
    setTrafficResult(null);

    const trafficData = {
      connection_duration: Number(duration),
      packet_size_bytes: Number(packetSize),
      failed_login_attempts: Number(failedLogins),
      protocol_type: Number(protocol)
    };

    const primaryUrl = `${apiUrl.replace(/\/$/, '')}/api/v1/analyze-traffic`;

    try {
      let response;
      try {
        response = await fetch(primaryUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(trafficData),
        });
      } catch {
        if (apiUrl.includes('8000')) {
          const fallbackUrl = 'http://localhost:8001/api/v1/analyze-traffic';
          response = await fetch(fallbackUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(trafficData),
          });
          setApiUrl('http://localhost:8001');
        } else {
          throw new Error('Connection failed');
        }
      }

      if (!response || !response.ok) {
        throw new Error(`HTTP error ${response?.status || 500}`);
      }

      const data: TrafficAnalysisResponse = await response.json();
      setTrafficResult(data);
    } catch (err: any) {
      setTrafficError(err.message || 'Unable to connect to NIDS backend');
    } finally {
      setTrafficLoading(false);
    }
  };

  // Traffic Preset Handler
  const setTrafficPreset = (d: number, pSize: number, logins: number, prot: number) => {
    setDuration(d);
    setPacketSize(pSize);
    setFailedLogins(logins);
    setProtocol(prot);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 md:p-10 font-sans antialiased">
      <div className="max-w-7xl mx-auto space-y-8">
        
        {/* Header */}
        <header className="border-b border-slate-800/80 pb-5">
          <h1 className="text-xl md:text-2xl font-normal text-slate-100 tracking-tight">
            AegisAPI Security Operations Center
          </h1>
        </header>

        {/* Top Metrics Bar */}
        <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          
          {/* Card 1: System Status */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-5 flex items-center justify-between shadow-sm">
            <div>
              <p className="text-xs font-medium text-slate-400">System Status</p>
              <div className="flex items-center space-x-2 mt-1.5">
                <span className="relative flex h-2.5 w-2.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
                </span>
                <span className="text-lg font-medium text-emerald-400">OK</span>
              </div>
            </div>
            <div className="p-2.5 bg-emerald-950/40 border border-emerald-800/40 rounded-md">
              <Activity className="w-5 h-5 text-emerald-400" />
            </div>
          </div>

          {/* Card 2: Requests Analysed (24H) */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-5 flex items-center justify-between shadow-sm">
            <div>
              <p className="text-xs font-medium text-slate-400">Requests Analysed (24H)</p>
              <p className="text-lg font-medium text-slate-200 mt-1.5">42,910</p>
            </div>
            <div className="p-2.5 bg-slate-800/50 border border-slate-700/50 rounded-md">
              <Activity className="w-5 h-5 text-slate-400" />
            </div>
          </div>

          {/* Card 3: Threats Mitigated */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-5 flex items-center justify-between shadow-sm">
            <div>
              <p className="text-xs font-medium text-slate-400">Threats Mitigated</p>
              <p className="text-lg font-medium text-rose-400 mt-1.5">301</p>
            </div>
            <div className="p-2.5 bg-rose-950/40 border border-rose-800/40 rounded-md">
              <AlertTriangle className="w-5 h-5 text-rose-400" />
            </div>
          </div>

          {/* Card 4: Avg. Analysis Time */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-5 flex items-center justify-between shadow-sm">
            <div>
              <p className="text-xs font-medium text-slate-400">Avg. Analysis Time</p>
              <p className="text-lg font-medium text-slate-200 mt-1.5">12ms</p>
            </div>
            <div className="p-2.5 bg-slate-800/50 border border-slate-700/50 rounded-md">
              <Clock className="w-5 h-5 text-slate-400" />
            </div>
          </div>

        </section>

        {/* Analytical Panels Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">

          {/* Panel 1: Data Payload Inspector */}
          <section className="bg-slate-900/90 border border-slate-800 rounded-lg p-6 shadow-sm flex flex-col justify-between space-y-6">
            <div className="space-y-6">
              <div className="border-b border-slate-800 pb-3 flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <h2 className="text-base font-normal text-slate-200">Data Payload Inspector</h2>
              </div>

              <form onSubmit={handlePayloadAssess} className="space-y-4">
                <div>
                  <div className="relative">
                    <input
                      type="text"
                      value={payload}
                      onChange={(e) => setPayload(e.target.value)}
                      placeholder="Enter string payload..."
                      className="w-full bg-slate-950 border border-slate-800 focus:border-cyan-500/80 rounded-md py-2.5 pl-3 pr-9 text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-500/50 font-mono"
                    />
                    <Search className="absolute right-3 top-3 w-4 h-4 text-slate-500" />
                  </div>
                </div>

                {/* Quick Sample Presets */}
                <div className="flex flex-wrap gap-2 pt-1">
                  <button
                    type="button"
                    onClick={() => setPayload("admin' --")}
                    className="text-xs bg-slate-950 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 px-2.5 py-1 rounded transition font-mono"
                  >
                    SQLi
                  </button>
                  <button
                    type="button"
                    onClick={() => setPayload("<script>alert('XSS')</script>")}
                    className="text-xs bg-slate-950 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 px-2.5 py-1 rounded transition font-mono"
                  >
                    XSS
                  </button>
                  <button
                    type="button"
                    onClick={() => setPayload("; cat /etc/passwd")}
                    className="text-xs bg-slate-950 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 px-2.5 py-1 rounded transition font-mono"
                  >
                    CmdInj
                  </button>
                  <button
                    type="button"
                    onClick={() => setPayload("hello world")}
                    className="text-xs bg-slate-950 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 px-2.5 py-1 rounded transition font-mono"
                  >
                    Safe
                  </button>
                </div>

                <button
                  type="submit"
                  disabled={payloadLoading}
                  className="w-full bg-slate-100 hover:bg-white text-slate-950 font-medium py-2.5 px-4 rounded-md transition disabled:opacity-50 text-sm"
                >
                  {payloadLoading ? 'Assessing...' : 'Assess'}
                </button>
              </form>

              {payloadError && (
                <div className="p-3 bg-rose-950/30 border border-rose-800/60 text-rose-300 text-xs rounded-md">
                  {payloadError}
                </div>
              )}
            </div>

            {/* Result Display Box */}
            <div className="pt-2">
              {payloadResult ? (
                payloadResult.threat_detected ? (
                  <div className="p-4 bg-rose-950/30 border border-rose-600/80 rounded-md animate-pulse flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0" />
                      <div>
                        <p className="text-sm font-semibold text-rose-400">Result: Malicious Payload Detected</p>
                        <p className="text-xs text-rose-300/80 font-mono mt-0.5">Confidence: {(payloadResult.confidence_score * 100).toFixed(1)}%</p>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="p-4 bg-emerald-950/30 border border-emerald-600/80 rounded-md flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
                      <div>
                        <p className="text-sm font-semibold text-emerald-400">Result: Safe Payload</p>
                        <p className="text-xs text-emerald-300/80 font-mono mt-0.5">Confidence: {(payloadResult.confidence_score * 100).toFixed(1)}%</p>
                      </div>
                    </div>
                  </div>
                )
              ) : (
                <div className="p-4 bg-slate-950/60 border border-slate-800 rounded-md flex items-center space-x-3 text-slate-500">
                  <Terminal className="w-4 h-4 shrink-0" />
                  <span className="text-xs font-mono">Result: Awaiting Input</span>
                </div>
              )}
            </div>
          </section>

          {/* Panel 2: Network Activity Monitor */}
          <section className="bg-slate-900/90 border border-slate-800 rounded-lg p-6 shadow-sm flex flex-col justify-between space-y-6">
            <div className="space-y-6">
              <div className="border-b border-slate-800 pb-3 flex items-center space-x-2">
                <Radio className="w-4 h-4 text-emerald-400" />
                <h2 className="text-base font-normal text-slate-200">Network Activity Monitor</h2>
              </div>

              <form onSubmit={handleTrafficAssess} className="space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Duration (Sec):</label>
                    <input
                      type="number"
                      step="0.0001"
                      min="0"
                      value={duration}
                      onChange={(e) => setDuration(parseFloat(e.target.value) || 0)}
                      className="w-full bg-slate-950 border border-slate-800 focus:border-emerald-500/80 rounded-md py-2 px-3 text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-emerald-500/50 font-mono"
                    />
                  </div>

                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Packet Size (Bytes):</label>
                    <input
                      type="number"
                      min="0"
                      max="65535"
                      value={packetSize}
                      onChange={(e) => setPacketSize(parseInt(e.target.value) || 0)}
                      className="w-full bg-slate-950 border border-slate-800 focus:border-emerald-500/80 rounded-md py-2 px-3 text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-emerald-500/50 font-mono"
                    />
                  </div>

                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Failed Logins:</label>
                    <input
                      type="number"
                      min="0"
                      value={failedLogins}
                      onChange={(e) => setFailedLogins(parseInt(e.target.value) || 0)}
                      className="w-full bg-slate-950 border border-slate-800 focus:border-emerald-500/80 rounded-md py-2 px-3 text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-emerald-500/50 font-mono"
                    />
                  </div>

                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Protocol:</label>
                    <select
                      value={protocol}
                      onChange={(e) => setProtocol(parseInt(e.target.value))}
                      className="w-full bg-slate-950 border border-slate-800 focus:border-emerald-500/80 rounded-md py-2 px-3 text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-emerald-500/50 font-mono"
                    >
                      <option value={0}>0 - TCP</option>
                      <option value={1}>1 - UDP</option>
                    </select>
                  </div>
                </div>

                {/* Attack Scenario Presets */}
                <div className="flex flex-wrap gap-2 pt-1">
                  <button
                    type="button"
                    onClick={() => setTrafficPreset(0.8, 512, 0, 0)}
                    className="text-xs bg-slate-950 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 px-2.5 py-1 rounded transition font-mono"
                  >
                    Normal HTTP
                  </button>
                  <button
                    type="button"
                    onClick={() => setTrafficPreset(0.002, 65000, 0, 1)}
                    className="text-xs bg-slate-950 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 px-2.5 py-1 rounded transition font-mono"
                  >
                    DDoS Flood
                  </button>
                  <button
                    type="button"
                    onClick={() => setTrafficPreset(45.0, 256, 12, 0)}
                    className="text-xs bg-slate-950 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 px-2.5 py-1 rounded transition font-mono"
                  >
                    SSH Brute Force
                  </button>
                  <button
                    type="button"
                    onClick={() => setTrafficPreset(0.0005, 40, 0, 0)}
                    className="text-xs bg-slate-950 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 px-2.5 py-1 rounded transition font-mono"
                  >
                    SYN Port Scan
                  </button>
                </div>

                <button
                  type="submit"
                  disabled={trafficLoading}
                  className="w-full bg-slate-100 hover:bg-white text-slate-950 font-medium py-2.5 px-4 rounded-md transition disabled:opacity-50 text-sm"
                >
                  {trafficLoading ? 'Assessing Traffic...' : 'Assess Traffic'}
                </button>
              </form>

              {trafficError && (
                <div className="p-3 bg-rose-950/30 border border-rose-800/60 text-rose-300 text-xs rounded-md">
                  {trafficError}
                </div>
              )}
            </div>

            {/* Network Result Display Box */}
            <div className="pt-2">
              {trafficResult ? (
                trafficResult.intrusion_detected ? (
                  <div className="p-4 bg-rose-950/30 border border-rose-600/80 rounded-md animate-pulse flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <AlertOctagon className="w-5 h-5 text-rose-400 shrink-0" />
                      <div>
                        <p className="text-sm font-semibold text-rose-400">Result: DDoS / Intrusion Pattern Detected</p>
                        <p className="text-xs text-rose-300/80 font-mono mt-0.5">Confidence: {(trafficResult.confidence_score * 100).toFixed(1)}%</p>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="p-4 bg-emerald-950/30 border border-emerald-600/80 rounded-md flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                      <div>
                        <p className="text-sm font-semibold text-emerald-400">Result: Safe Traffic</p>
                        <p className="text-xs text-emerald-300/80 font-mono mt-0.5">Confidence: {(trafficResult.confidence_score * 100).toFixed(1)}%</p>
                      </div>
                    </div>
                  </div>
                )
              ) : (
                <div className="p-4 bg-slate-950/60 border border-slate-800 rounded-md flex items-center space-x-3 text-slate-500">
                  <Server className="w-4 h-4 shrink-0" />
                  <span className="text-xs font-mono">Result: Awaiting Assessment</span>
                </div>
              )}
            </div>
          </section>

        </div>
      </div>
    </div>
  );
}
