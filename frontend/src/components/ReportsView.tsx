import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Button } from "./ui/button";
import { Badge } from "./ui/badge";
import { FileText, Download, Calendar, Eye } from "lucide-react";
import { toast } from "sonner";
import { motion } from "framer-motion";
import { mockData } from "../services/mockData";

interface ReportsViewProps {
  onViewReport?: (reportId: string) => void;
}

export function ReportsView({ onViewReport }: ReportsViewProps) {
  const [reports, setReports] = useState(mockData.reports);
  const [loading, setLoading] = useState(false);

  const scheduledReports = [
    { name: "Daily Scan Summary", frequency: "Daily", nextRun: "Tomorrow at 9:00 AM", status: "Active" },
    { name: "Weekly Vulnerability Report", frequency: "Weekly", nextRun: "Sunday at 6:00 PM", status: "Active" },
    { name: "Monthly Executive Summary", frequency: "Monthly", nextRun: "Nov 1 at 8:00 AM", status: "Active" },
    { name: "Quarterly Compliance Report", frequency: "Quarterly", nextRun: "Jan 1, 2025", status: "Active" }
  ];

  const handleDownload = (report: any) => {
    toast.success(`Downloading report for ${report.target}`, {
      description: `Report ID: ${report.id}`
    });
    
    // Simulate download
    setTimeout(() => {
      toast.success("Download complete", {
        description: `Report for ${report.target} has been saved`
      });
    }, 2000);
  };

  const handleView = (report: any) => {
    toast.info(`Opening report for ${report.target}`, {
      description: "Loading report details..."
    });
    
    // If onViewReport callback is provided, use it
    if (onViewReport) {
      onViewReport(report.id);
    } else {
      // Otherwise, show a toast message
      toast.info(`Report viewer for ${report.target}`, {
        description: "Report viewer would open here in a full implementation"
      });
    }
  };

  const handleConfigure = (report: typeof scheduledReports[0]) => {
    toast.info(`Configuring ${report.name}`, {
      description: "Opening configuration panel..."
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="mb-2">Reports</h1>
          <p className="text-muted-foreground">Generate and download security reports</p>
        </div>
        <Button className="bg-primary hover:bg-primary/90">
          <FileText className="w-4 h-4 mr-2" />
          Generate New Report
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="border-border/40 glass-card enhanced-card">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-cyan-500/10 flex items-center justify-center neon-glow-cyan">
                <FileText className="w-5 h-5 text-cyan-400" />
              </div>
              <div>
                <p className="text-2xl">{reports.length}</p>
                <p className="text-xs text-muted-foreground">Total Reports</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-border/40 glass-card enhanced-card">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center neon-glow-purple">
                <Calendar className="w-5 h-5 text-purple-400" />
              </div>
              <div>
                <p className="text-2xl">{scheduledReports.length}</p>
                <p className="text-xs text-muted-foreground">Scheduled</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-border/40 glass-card enhanced-card">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center">
                <Download className="w-5 h-5 text-green-400" />
              </div>
              <div>
                <p className="text-2xl">342</p>
                <p className="text-xs text-muted-foreground">Downloads</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-border/40 glass-card enhanced-card">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-orange-500/10 flex items-center justify-center">
                <Eye className="w-5 h-5 text-orange-400" />
              </div>
              <div>
                <p className="text-2xl">1.2K</p>
                <p className="text-xs text-muted-foreground">Views</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Reports List */}
      <Card className="border-border/40 glass-card enhanced-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyan-400 neon-glow-cyan" />
            Available Reports
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {loading ? (
            <div className="flex justify-center items-center h-32">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500"></div>
            </div>
          ) : (
            reports.map((report, index) => (
              <motion.div
                key={report.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3, delay: index * 0.05 }}
                className="flex items-center justify-between p-4 rounded-lg bg-muted/30 border border-border/40 hover:bg-muted/50 transition-colors"
              >
                <div className="flex items-start gap-4 flex-1">
                  <div className="w-12 h-12 rounded-lg bg-cyan-500/10 flex items-center justify-center">
                    <FileText className="w-6 h-6 text-cyan-400" />
                  </div>
                  <div className="flex-1">
                    <h4 className="mb-1">Report for {report.target}</h4>
                    <div className="flex items-center gap-3 text-sm text-muted-foreground">
                      <Badge variant="secondary" className="bg-purple-500/20 text-purple-400">
                        Scan Report
                      </Badge>
                      <span className="flex items-center gap-1">
                        <Calendar className="w-3 h-3" />
                        {new Date(report.scan_timestamp).toLocaleDateString()}
                      </span>
                      <span>
                        {report.severity_counts.critical + report.severity_counts.high + 
                         report.severity_counts.medium + report.severity_counts.low} findings
                      </span>
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Badge className="bg-green-500/20 text-green-400">
                    Ready
                  </Badge>
                  <Button 
                    variant="outline" 
                    size="sm"
                    onClick={() => handleView(report)}
                  >
                    <Eye className="w-4 h-4 mr-2" />
                    View
                  </Button>
                  <Button 
                    size="sm" 
                    className="bg-primary hover:bg-primary/90"
                    onClick={() => handleDownload(report)}
                  >
                    <Download className="w-4 h-4 mr-2" />
                    Download
                  </Button>
                </div>
              </motion.div>
            ))
          )}
        </CardContent>
      </Card>

      {/* Scheduled Reports */}
      <Card className="border-border/40 glass-card enhanced-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Calendar className="w-5 h-5 text-purple-400 neon-glow-purple" />
            Scheduled Reports
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {scheduledReports.map((report, idx) => (
              <motion.div
                key={idx}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.3, delay: idx * 0.1 }}
                className="flex items-center justify-between p-4 rounded-lg bg-muted/30 border border-border/40 hover:bg-muted/50 transition-colors"
              >
                <div className="space-y-1">
                  <h4 className="text-sm">{report.name}</h4>
                  <div className="flex items-center gap-3 text-xs text-muted-foreground">
                    <span>{report.frequency}</span>
                    <span>•</span>
                    <span>Next run: {report.nextRun}</span>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <Badge className="bg-green-500/20 text-green-400">
                    {report.status}
                  </Badge>
                  <Button 
                    variant="outline" 
                    size="sm"
                    onClick={() => handleConfigure(report)}
                  >
                    Configure
                  </Button>
                </div>
              </motion.div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}