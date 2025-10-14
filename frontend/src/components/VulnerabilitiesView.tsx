import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Input } from "./ui/input";
import { Button } from "./ui/button";
import { Badge } from "./ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";
import { Search, AlertTriangle, Download, Eye, CheckCircle, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { motion } from "framer-motion";
import { mockData } from "../services/mockData";

interface VulnerabilityDisplay {
  id: string;
  cve: string;
  title: string;
  cvss: number;
  severity: "critical" | "high" | "medium" | "low";
  host: string;
  tool: string;
  date: string;
  status: string;
}

export function VulnerabilitiesView() {
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [toolFilter, setToolFilter] = useState("all");
  const [vulnerabilities, setVulnerabilities] = useState([] as VulnerabilityDisplay[]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        // Use mock data directly
        const vulnerabilitiesDisplay: VulnerabilityDisplay[] = mockData.vulnerabilities.map(vuln => ({
          id: vuln.id,
          cve: vuln.cve,
          title: vuln.title,
          cvss: vuln.cvss,
          severity: vuln.severity,
          host: vuln.host,
          tool: vuln.tool,
          date: vuln.date,
          status: vuln.status
        }));
        setVulnerabilities(vulnerabilitiesDisplay);
      } catch (error) {
        console.error("Failed to fetch data:", error);
        toast.error("Failed to load vulnerabilities", {
          description: "Please try again later"
        });
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const filteredVulnerabilities = vulnerabilities.filter(vuln => {
    const matchesSearch = vuln.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         vuln.cve.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         vuln.host.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSeverity = severityFilter === "all" || vuln.severity === severityFilter;
    const matchesTool = toolFilter === "all" || vuln.tool === toolFilter;
    return matchesSearch && matchesSeverity && matchesTool;
  });

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "bg-red-500/20 text-red-400 border-red-500/30";
      case "high": return "bg-orange-500/20 text-orange-400 border-orange-500/30";
      case "medium": return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
      case "low": return "bg-blue-500/20 text-blue-400 border-blue-500/30";
      default: return "bg-gray-500/20 text-gray-400 border-gray-500/30";
    }
  };

  const getCVSSColor = (cvss: number) => {
    if (cvss >= 9.0) return "text-red-400";
    if (cvss >= 7.0) return "text-orange-400";
    if (cvss >= 4.0) return "text-yellow-400";
    return "text-blue-400";
  };

  const handleExport = () => {
    toast.success("Report exported successfully", {
      description: `Exported ${filteredVulnerabilities.length} vulnerabilities to CSV`
    });
  };

  const handleViewDetails = (vuln: VulnerabilityDisplay) => {
    toast.info(`Viewing ${vuln.cve}`, {
      description: vuln.title
    });
  };

  const handleResolve = (vulnId: string) => {
    setVulnerabilities(prev => prev.map(v => 
      v.id === vulnId ? { ...v, status: "Resolved" } : v
    ));
    toast.success("Vulnerability marked as resolved", {
      description: "Status updated successfully"
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="mb-2">Vulnerabilities</h1>
          <p className="text-muted-foreground">Manage and track security vulnerabilities</p>
        </div>
        <Button onClick={handleExport} className="bg-primary hover:bg-primary/90" disabled={loading}>
          <Download className="w-4 h-4 mr-2" />
          Export Report
        </Button>
      </div>

      {/* Filters */}
      <Card className="border-border/40 glass-card">
        <CardContent className="pt-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="md:col-span-2">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  placeholder="Search by CVE, title, or host..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10 bg-muted/50 border-border/60"
                  disabled={loading}
                />
              </div>
            </div>
            <Select value={severityFilter} onValueChange={setSeverityFilter} disabled={loading}>
              <SelectTrigger className="bg-muted/50 border-border/60">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severities</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
            <Select value={toolFilter} onValueChange={setToolFilter} disabled={loading}>
              <SelectTrigger className="bg-muted/50 border-border/60">
                <SelectValue placeholder="Tool" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Tools</SelectItem>
                <SelectItem value="Nmap">Nmap</SelectItem>
                <SelectItem value="Nessus">Nessus</SelectItem>
                <SelectItem value="OpenVAS">OpenVAS</SelectItem>
                <SelectItem value="Nikto">Nikto</SelectItem>
                <SelectItem value="Nuclei">Nuclei</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="border-border/40 glass-card enhanced-card">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center neon-glow">
                <AlertTriangle className="w-5 h-5 text-red-400" />
              </div>
              <div>
                <p className="text-2xl">{vulnerabilities.filter(v => v.severity === "critical").length}</p>
                <p className="text-xs text-muted-foreground">Critical</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-border/40 glass-card enhanced-card">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-orange-500/10 flex items-center justify-center">
                <AlertTriangle className="w-5 h-5 text-orange-400" />
              </div>
              <div>
                <p className="text-2xl">{vulnerabilities.filter(v => v.severity === "high").length}</p>
                <p className="text-xs text-muted-foreground">High</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-border/40 glass-card enhanced-card">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-yellow-500/10 flex items-center justify-center">
                <AlertTriangle className="w-5 h-5 text-yellow-400" />
              </div>
              <div>
                <p className="text-2xl">{vulnerabilities.filter(v => v.severity === "medium").length}</p>
                <p className="text-xs text-muted-foreground">Medium</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-border/40 glass-card enhanced-card">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center neon-glow-cyan">
                <AlertTriangle className="w-5 h-5 text-blue-400" />
              </div>
              <div>
                <p className="text-2xl">{vulnerabilities.filter(v => v.severity === "low").length}</p>
                <p className="text-xs text-muted-foreground">Low</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Vulnerabilities Table */}
      <Card className="border-border/40 glass-card enhanced-card">
        <CardHeader>
          <CardTitle>
            {loading ? (
              <div className="flex items-center gap-2">
                <Loader2 className="w-4 h-4 animate-spin" />
                Loading Vulnerabilities...
              </div>
            ) : (
              `${filteredVulnerabilities.length} Vulnerabilities Found`
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex justify-center items-center h-64">
              <Loader2 className="w-8 h-8 animate-spin text-cyan-400" />
            </div>
          ) : (
            <div className="rounded-md border border-border/40">
              <Table>
                <TableHeader>
                  <TableRow className="border-border/40 hover:bg-muted/30">
                    <TableHead>CVE</TableHead>
                    <TableHead>Vulnerability</TableHead>
                    <TableHead>CVSS</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Host</TableHead>
                    <TableHead>Tool</TableHead>
                    <TableHead>Date</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredVulnerabilities.length > 0 ? (
                    filteredVulnerabilities.map((vuln, index) => (
                      <motion.tr
                        key={vuln.id}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.3, delay: index * 0.05 }}
                        className="border-border/40 hover:bg-muted/30"
                      >
                        <TableCell>
                          <code className="text-xs bg-muted/50 px-2 py-1 rounded">{vuln.cve || "N/A"}</code>
                        </TableCell>
                        <TableCell className="max-w-xs">
                          <p className="text-sm truncate">{vuln.title}</p>
                        </TableCell>
                        <TableCell>
                          <span className={`${getCVSSColor(vuln.cvss)}`}>
                            {vuln.cvss}
                          </span>
                        </TableCell>
                        <TableCell>
                          <Badge className={getSeverityColor(vuln.severity)}>
                            {vuln.severity}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <code className="text-xs">{vuln.host}</code>
                        </TableCell>
                        <TableCell>
                          <Badge variant="secondary" className="bg-cyan-500/20 text-cyan-400">
                            {vuln.tool}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {vuln.date}
                        </TableCell>
                        <TableCell>
                          <Badge variant={vuln.status === "Resolved" ? "default" : "secondary"}>
                            {vuln.status}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex gap-2">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleViewDetails(vuln)}
                            >
                              <Eye className="w-4 h-4" />
                            </Button>
                            {vuln.status !== "Resolved" && (
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => handleResolve(vuln.id)}
                              >
                                <CheckCircle className="w-4 h-4" />
                              </Button>
                            )}
                          </div>
                        </TableCell>
                      </motion.tr>
                    ))
                  ) : (
                    <TableRow>
                      <TableCell colSpan={9} className="text-center py-8 text-muted-foreground">
                        No vulnerabilities found matching your filters
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}