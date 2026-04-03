import { ShieldAlert, ShieldCheck, Activity, CheckCircle, AlertTriangle, Key, Download } from 'lucide-react';

export interface DastResults {
  metadata: { url: string; domain: string; status_code: number; server: string };
  vulnerabilities: any[];
  api_keys_found: any[];
  security_headers: Record<string, { present: boolean }>;
  authentication: any;
  cors: { allow_origin: string; tests: any[] };
  rate_limiting: { requests_sent: number; successful: number; blocked: number };
  ssl_tls: { https_enabled: boolean; certificate_valid: boolean };
  pdfReportAvailable?: boolean;
}

interface Props {
  report: DastResults;
}

export default function LiveScanReport({ report }: Props) {
  const { metadata, vulnerabilities, security_headers, cors, rate_limiting, ssl_tls, api_keys_found } = report;

  const getSeverityStyle = (severity: string) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return 'bg-red-500/10 border-red-500/50 text-red-400';
      case 'HIGH': return 'bg-orange-500/10 border-orange-500/50 text-orange-400';
      case 'MEDIUM': return 'bg-yellow-500/10 border-yellow-500/50 text-yellow-400';
      case 'LOW': return 'bg-blue-500/10 border-blue-500/50 text-blue-400';
      default: return 'bg-gray-500/10 border-gray-500/50 text-gray-400';
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      
      {/* Top Banner */}
      <div className="flex items-center justify-between p-4 bg-gray-900 rounded-lg border border-gray-800">
        <div className="flex items-center gap-3">
          {vulnerabilities.length > 0 ? <ShieldAlert className="text-red-500" size={24} /> : <ShieldCheck className="text-emerald-500" size={24} />}
          <h2 className="text-xl font-semibold text-white">Live Dynamic Scan: {metadata.domain}</h2>
        </div>
        <div className="flex gap-4 text-sm text-gray-400 items-center">
            <span className="bg-gray-800 px-2 py-1 rounded text-white border border-gray-700">Status: {metadata.status_code}</span>
            {report.pdfReportAvailable && (
              <a href="/security_report.pdf" download className="flex items-center gap-1 bg-purple-600 hover:bg-purple-500 transition-colors text-white px-3 py-1.5 rounded text-xs font-bold shadow-lg">
                <Download size={14}/> Download PDF Report
              </a>
            )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        
        {/* SSL & Config */}
        <div className="p-5 rounded-lg border bg-gray-900 border-gray-800">
          <h3 className="text-lg font-bold text-white mb-4 border-b border-gray-800 pb-2">Infrastructure</h3>
          <ul className="space-y-3 text-sm">
            <li className="flex justify-between items-center">
              <span className="text-gray-400">Server</span>
              <span className="font-mono text-gray-200">{metadata.server}</span>
            </li>
            <li className="flex justify-between items-center">
              <span className="text-gray-400">SSL/TLS Valid</span>
              {ssl_tls.certificate_valid ? <CheckCircle className="text-emerald-500" size={16}/> : <AlertTriangle className="text-red-500" size={16}/>}
            </li>
            <li className="flex justify-between items-center">
              <span className="text-gray-400">Rate Limiting</span>
              <span className={rate_limiting.blocked > 0 ? "text-emerald-400" : "text-red-400 font-bold"}>
                {rate_limiting.blocked > 0 ? "Enabled" : "Missing / Vulnerable"}
              </span>
            </li>
            <li className="flex justify-between items-center">
              <span className="text-gray-400">CORS Policy</span>
              <span className="font-mono text-gray-200 text-xs truncate max-w-[150px]">{cors.allow_origin || 'None'}</span>
            </li>
          </ul>
        </div>

        {/* Security Headers */}
        <div className="p-5 rounded-lg border bg-gray-900 border-gray-800">
          <h3 className="text-lg font-bold text-white mb-4 border-b border-gray-800 pb-2">Security Headers</h3>
          <div className="grid grid-cols-2 gap-2 text-sm">
            {Object.entries(security_headers || {}).map(([header, data]) => (
                <div key={header} className="flex items-center justify-between bg-gray-950 p-2 rounded border border-gray-800">
                    <span className="text-xs text-gray-400 truncate pr-2" title={header}>{header}</span>
                    {data.present ? <CheckCircle size={14} className="text-emerald-500 shrink-0"/> : <AlertTriangle size={14} className="text-red-500 shrink-0"/>}
                </div>
            ))}
          </div>
        </div>
      </div>

      {api_keys_found?.length > 0 && (
          <div className="p-5 rounded-lg border bg-red-500/10 border-red-500/50">
             <div className="flex items-center gap-2 mb-4">
                 <Key className="text-red-500" size={20} />
                 <h3 className="text-lg font-bold text-white">Exposed API Keys Detected</h3>
             </div>
             {api_keys_found.map((k, i) => (
                 <div key={i} className="flex items-center justify-between text-sm bg-gray-950 p-3 rounded mb-2 border border-red-500/20">
                     <span className="font-bold text-red-400">{k.type}</span>
                     <span className="font-mono text-gray-300">{k.value}</span>
                 </div>
             ))}
          </div>
      )}

      {/* Vulnerabilities List */}
      <h3 className="text-xl font-bold text-white pt-4">Discovered Vulnerabilities</h3>
      {vulnerabilities.length === 0 ? (
          <div className="text-center p-8 text-gray-500 border border-dashed border-gray-700 rounded-lg">
             No immediate vulnerabilities found on the surface.
          </div>
      ) : (
        <div className="grid gap-4">
            {vulnerabilities.map((vuln, idx) => (
            <div key={idx} className={`p-4 rounded-lg border backdrop-blur-sm ${getSeverityStyle(vuln.severity)}`}>
                <div className="flex items-center gap-3">
                <span className={`inline-block px-2 py-1 text-xs font-bold rounded ${
                    vuln.severity === 'CRITICAL' ? 'bg-red-500 text-white' : 
                    vuln.severity === 'HIGH' ? 'bg-orange-500 text-white' : 
                    'bg-gray-800 text-white'
                }`}>
                    {vuln.severity}
                </span>
                <p className="text-sm font-semibold">{vuln.description || vuln.type}</p>
                </div>
            </div>
            ))}
        </div>
      )}
    </div>
  );
}
