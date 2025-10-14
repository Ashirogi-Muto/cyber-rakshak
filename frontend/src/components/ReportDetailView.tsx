import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Button } from "./ui/button";
import { Badge } from "./ui/badge";
import { Download, ArrowLeft, AlertTriangle, Shield, Server, Database } from "lucide-react";
import { toast } from "sonner";
import { motion } from "framer-motion";
import { mockData } from "../services/mockData";

// Props interface for the component
interface ReportDetailViewProps {
  reportId: string;
  onBack: () => void;
}

export function ReportDetailView({ reportId, onBack }: ReportDetailViewProps) {
  const [report, setReport] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchReport = async () => {
      try {
        setLoading(true);
        // Find the report in mock data
        const foundReport = mockData.reports.find(r => r.id === reportId);
        if (foundReport) {
          // Create a detailed report object with vulnerabilities
          const detailedReport = {
            report_id: foundReport.id,
            target: foundReport.target,
            vulnerabilities: mockData.vulnerabilities.filter(v => v.host === foundReport.target || foundReport.target.includes(v.host))
          };
          setReport(detailedReport);
        } else {
          // If not found, use the first report as fallback
          const firstReport = mockData.reports[0];
          const detailedReport = {
            report_id: firstReport.id,
            target: firstReport.target,
            vulnerabilities: mockData.vulnerabilities.filter(v => v.host === firstReport.target || firstReport.target.includes(v.host))
          };
          setReport(detailedReport);
        }
      } catch (err) {
        console.error("Failed to fetch report:", err);
        setError("Failed to load report details. Please try again later.");
        toast.error("Failed to load report", {
          description: "Please try again later"
        });
      } finally {
        setLoading(false);
      }
    };

    fetchReport();
  }, [reportId]);

  const handleDownload = () => {
    if (report) {
      toast.success(`Downloading report for ${report.target}`, {
        description: `Report ID: ${report.report_id}`
      });
      
      // Simulate download
      setTimeout(() => {
        toast.success("Download complete", {
          description: `Report for ${report.target} has been saved`
        });
      }, 2000);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "bg-red-500/20 text-red-400 border-red-500/30";
      case "high":
        return "bg-orange-500/20 text-orange-400 border-orange-500/30";
      case "medium":
        return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
      case "low":
        return "bg-green-500/20 text-green-400 border-green-500/30";
      default:
        return "bg-gray-500/20 text-gray-400 border-gray-500/30";
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return <AlertTriangle className="w-4 h-4 text-red-400" />;
      case "high":
        return <AlertTriangle className="w-4 h-4 text-orange-400" />;
      case "medium":
        return <AlertTriangle className="w-4 h-4 text-yellow-400" />;
      case "low":
        return <Shield className="w-4 h-4 text-green-400" />;
      default:
        return <Shield className="w-4 h-4 text-gray-400" />;
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-500"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-64 space-y-4">
        <div className="text-red-500 text-2xl">⚠️</div>
        <h2 className="text-xl font-semibold">Error Loading Report</h2>
        <p className="text-muted-foreground">{error}</p>
        <Button onClick={onBack}>Go Back</Button>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="flex flex-col items-center justify-center h-64 space-y-4">
        <div className="text-yellow-500 text-2xl">🔍</div>
        <h2 className="text-xl font-semibold">Report Not Found</h2>
        <p className="text-muted-foreground">The requested report could not be found.</p>
        <Button onClick={onBack}>Go Back</Button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-4">
          <Button 
            variant="outline" 
            size="sm" 
            onClick={onBack}
            className="flex items-center gap-2"
          >
            <ArrowLeft className="w-4 h-4" />
            Back
          </Button>
          <div>
            <h1 className="mb-1">Security Report</h1>
            <p className="text-muted-foreground">Detailed analysis for {report.target}</p>
          </div>
        </div>
        <Button 
          className="bg-primary hover:bg-primary/90 flex items-center gap-2"
          onClick={handleDownload}
        >
          <Download className="w-4 h-4" />
          Download Report
        </Button>
      </div>

      {/* Report Summary */}
      <Card className="border-border/40 glass-card enhanced-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Server className="w-5 h-5 text-cyan-400 neon-glow-cyan" />
            Report Summary
          </CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 rounded-lg bg-muted/30 border border-border/40">
            <p className="text-sm text-muted-foreground mb-1">Target</p>
            <p className="font-medium">{report.target}</p>
          </div>
          <div className="p-4 rounded-lg bg-muted/30 border border-border/40">
            <p className="text-sm text-muted-foreground mb-1">Report ID</p>
            <p className="font-mono text-sm">{report.report_id}</p>
          </div>
          <div className="p-4 rounded-lg bg-muted/30 border border-border/40">
            <p className="text-sm text-muted-foreground mb-1">Vulnerabilities Found</p>
            <p className="font-medium">{report.vulnerabilities.length}</p>
          </div>
        </CardContent>
      </Card>

      {/* Vulnerabilities List */}
      <Card className="border-border/40 glass-card enhanced-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-orange-400 neon-glow-orange" />
            Identified Vulnerabilities
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {report.vulnerabilities.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Shield className="w-12 h-12 mb-4" />
              <p>No vulnerabilities found in this scan</p>
            </div>
          ) : (
            report.vulnerabilities.map((vuln: any, index: number) => (
              <motion.div
                key={vuln.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3, delay: index * 0.05 }}
                className="p-4 rounded-lg bg-muted/30 border border-border/40 hover:bg-muted/50 transition-colors"
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    {getSeverityIcon(vuln.severity)}
                    <div>
                      <h3 className="font-medium">{vuln.title}</h3>
                      {vuln.cve && (
                        <Badge variant="secondary" className="mt-1">
                          {vuln.cve}
                        </Badge>
                      )}
                    </div>
                  </div>
                  <Badge className={getSeverityColor(vuln.severity)}>
                    {vuln.severity}
                  </Badge>
                </div>
                
                {vuln.description && (
                  <p className="text-sm text-muted-foreground mb-3">
                    {vuln.description}
                  </p>
                )}
                
                <div className="flex flex-wrap gap-4 text-xs">
                  {vuln.cvss && (
                    <div className="flex items-center gap-1">
                      <span className="text-muted-foreground">CVSS:</span>
                      <span className="font-medium">{vuln.cvss}</span>
                    </div>
                  )}
                  {vuln.reference && (
                    <div className="flex items-center gap-1">
                      <span className="text-muted-foreground">Reference:</span>
                      <a 
                        href={vuln.reference} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="text-cyan-400 hover:underline"
                      >
                        View Details
                      </a>
                    </div>
                  )}
                </div>
              </motion.div>
            ))
          )}
        </CardContent>
      </Card>

      {/* Recommendations */}
      <Card className="border-border/40 glass-card enhanced-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="w-5 h-5 text-green-400 neon-glow-green" />
            Remediation Recommendations
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="p-4 rounded-lg bg-green-500/10 border border-green-500/20">
              <h4 className="font-medium mb-2">Immediate Actions</h4>
              <ul className="list-disc list-inside text-sm space-y-1">
                <li>Patch critical vulnerabilities as soon as possible</li>
                <li>Review and update firewall rules</li>
                <li>Implement multi-factor authentication</li>
              </ul>
            </div>
            
            <div className="p-4 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
              <h4 className="font-medium mb-2">Short-term Actions</h4>
              <ul className="list-disc list-inside text-sm space-y-1">
                <li>Conduct security awareness training</li>
                <li>Implement network segmentation</li>
                <li>Review and harden system configurations</li>
              </ul>
            </div>
            
            <div className="p-4 rounded-lg bg-blue-500/10 border border-blue-500/20">
              <h4 className="font-medium mb-2">Long-term Actions</h4>
              <ul className="list-disc list-inside text-sm space-y-1">
                <li>Implement a comprehensive vulnerability management program</li>
                <li>Establish regular penetration testing schedule</li>
                <li>Develop and maintain an incident response plan</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}