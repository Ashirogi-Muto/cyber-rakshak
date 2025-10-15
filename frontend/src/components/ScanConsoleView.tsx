import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Progress } from "./ui/progress";
import { Badge } from "./ui/badge";
import { Play, Square, Terminal, Loader2, CheckCircle } from "lucide-react";
import { toast } from "sonner";
import { motion } from "framer-motion";
import { scanService, ScanRequest } from "../services/scanService";

interface ScanTool {
  id: string;
  name: string;
  description: string;
  icon: string;
  progress: number;
  isRunning: boolean;
  isComplete: boolean;
}

interface ScanHistoryItem {
  id: number;
  tool: string;
  target: string;
  status: string;
  findings: number;
  time: string;
}

interface ScanConsoleViewProps {
  onViewReport?: (reportId: string) => void;
}

export function ScanConsoleView({ onViewReport }: ScanConsoleViewProps) {
  const [tools, setTools] = useState([] as ScanTool[]);
  const [target, setTarget] = useState("");
  console.log("Current target state:", target);
  console.log("Target is empty:", !target);
  const [scanHistory, setScanHistory] = useState([] as ScanHistoryItem[]);

  useEffect(() => {
    // Initialize tools
    const initialTools = [
      {
        id: "nmap",
        name: "Nmap",
        description: "Network discovery and security auditing",
        icon: "🔍",
        progress: 0,
        isRunning: false,
        isComplete: false
      },
      {
        id: "nessus",
        name: "Nessus",
        description: "Comprehensive vulnerability scanner",
        icon: "🛡️",
        progress: 0,
        isRunning: false,
        isComplete: false
      },
      {
        id: "openvas",
        name: "OpenVAS",
        description: "Open-source vulnerability assessment",
        icon: "🔓",
        progress: 0,
        isRunning: false,
        isComplete: false
      },
      {
        id: "nikto",
        name: "Nikto",
        description: "Web server vulnerability scanner",
        icon: "🌐",
        progress: 0,
        isRunning: false,
        isComplete: false
      },
      {
        id: "nuclei",
        name: "Nuclei",
        description: "Fast and customizable vulnerability scanner",
        icon: "⚡",
        progress: 0,
        isRunning: false,
        isComplete: false
      }
    ];
    
    console.log("Initializing tools:", initialTools);
    setTools(initialTools);

    // Initialize scan history
    setScanHistory([
      { id: 1, tool: "Nmap", target: "scanme.nmap.org", status: "completed", findings: 23, time: "5m ago" },
      { id: 2, tool: "Nessus", target: "api.production.com", status: "completed", findings: 47, time: "12m ago" },
      { id: 3, tool: "Nikto", target: "webapp.staging.io", status: "completed", findings: 8, time: "28m ago" },
      { id: 4, tool: "Nuclei", target: "172.16.0.0/16", status: "completed", findings: 156, time: "1h ago" }
    ]);
  }, []);

  const startScan = async (toolId: string) => {
    try {
      console.log("startScan function called with toolId:", toolId);
      console.log("Current target:", target);
      console.log("Current tools state:", tools);
      
      if (!target) {
        console.log("No target provided, showing error toast");
        toast.error("Please enter a target before starting scan");
        return;
      }

      const tool = tools.find(t => t.id === toolId);
      console.log("Found tool:", tool);
      
      if (!tool) {
        console.log("Tool not found, returning");
        return;
      }

      console.log(`Starting ${tool.name} scan on ${target}`);
      toast.success(`Starting ${tool.name} scan on ${target}`, {
        description: "Initializing security scan..."
      });

      // Update tool state to running with initial progress
      console.log("Updating tool state to running");
      setTools(prev => {
        const updated = prev.map(tool => 
          tool.id === toolId ? { ...tool, isRunning: true, progress: 0, isComplete: false } : tool
        );
        console.log("Updated tools state:", updated);
        return updated;
      });

      // Wait a bit for UI to update
      await new Promise(resolve => setTimeout(resolve, 100));

      // Simple progress simulation - increment every 300ms up to 90%
      let progress = 0;
      const progressInterval = setInterval(() => {
        if (progress < 90) {
          progress += 10;
          setTools(prev => prev.map(t => 
            t.id === toolId && t.isRunning ? { ...t, progress } : t
          ));
        }
      }, 300);

      // Simulate scan work - minimum 3 seconds
      await new Promise(resolve => setTimeout(resolve, 3000));

      // Clear progress interval
      clearInterval(progressInterval);

      // Set to 100% and complete
      setTools(prev => prev.map(t => 
        t.id === toolId ? { ...t, progress: 100, isRunning: false, isComplete: true } : t
      ));

      // Wait a bit for UI to update to 100%
      await new Promise(resolve => setTimeout(resolve, 500));

      // Show completion message
      toast.success(`${tool.name} scan completed!`, {
        description: "Found 27 potential issues"
      });

      // Add to history
      setScanHistory(prevHistory => [{
        id: Date.now(),
        tool: tool.name,
        target: target,
        status: "completed",
        findings: Math.floor(Math.random() * 50) + 10,
        time: "Just now"
      }, ...prevHistory]);
    } catch (error: any) {
      console.error("Scan failed:", error);
      // Get the tool name for the error message
      const failedTool = tools.find(t => t.id === toolId);
      const toolName = failedTool ? failedTool.name : toolId;
      
      // Show a more detailed error message
      const errorMessage = error.message || "An error occurred during the scan. Please try again.";
      toast.error(`Scan failed for ${toolName}`, {
        description: errorMessage
      });
      
      // Reset tool state on error
      setTools(prev => prev.map(tool => 
        tool.id === toolId ? { ...tool, isRunning: false, isComplete: false } : tool
      ));
    }
  };

  const stopScan = (toolId: string) => {
    console.log("stopScan function called with toolId:", toolId);
    const tool = tools.find(t => t.id === toolId);
    console.log("Found tool to stop:", tool);
    
    if (!tool) {
      console.log("Tool not found, returning");
      return;
    }
    
    console.log(`Stopping ${tool.name} scan`);
    toast.warning(`${tool.name} scan stopped`, {
      description: "Scan terminated by user"
    });
    setTools(prev => {
      const updated = prev.map(tool => 
        tool.id === toolId ? { ...tool, isRunning: false, isComplete: false } : tool
      );
      console.log("Updated tools state after stopping:", updated);
      return updated;
    });
  };

  const validateTarget = async () => {
    console.log("validateTarget function called");
    console.log("Current target:", target);
    
    if (!target) {
      console.log("No target provided, showing error toast");
      toast.error("Please enter a target");
      return;
    }
    
    console.log("Validating target, showing promise toast");
    // Simulate target validation
    toast.promise(
      new Promise(resolve => {
        console.log("Starting validation promise");
        setTimeout(() => {
          console.log("Validation promise resolved");
          resolve(null);
        }, 1000);
      }),
      {
        loading: "Validating target...",
        success: () => {
          console.log("Target validation successful");
          return {
            title: "Target validated",
            description: `${target} is reachable and ready for scanning`
          };
        },
        error: "Failed to validate target"
      }
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="mb-2">Scan Console</h1>
        <p className="text-muted-foreground">Launch and manage security scans</p>
      </div>

      {/* Target Input */}
      <Card className="border-border/40 glass-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Terminal className="w-5 h-5 text-cyan-400 neon-glow-cyan" />
            Scan Target
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-3">
            <div className="flex-1">
              <Label htmlFor="target" className="sr-only">Target</Label>
              <Input
                id="target"
                placeholder="Enter IP address, domain, or CIDR range..."
                value={target}
                onChange={(e) => {
                  console.log(`Target input changed: '${e.target.value}'`);
                  console.log(`Target input length: ${e.target.value.length}`);
                  console.log(`Target input validity:`, e.target.validity);
                  setTarget(e.target.value);
                }}
                className="bg-muted/50 border-border/60"
              />
            </div>
            <Button 
              onClick={() => {
                console.log("Validate Target button clicked");
                console.log(`Target value: ${target}`);
                validateTarget();
              }}
              disabled={!target} 
              className="bg-cyan-600 hover:bg-cyan-700"
            >
              Validate Target
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Scan Tools Grid */}
      <div 
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"
        onClick={() => console.log("Grid container clicked")}
      >
        {tools.map((tool, index) => (
          <div
            key={tool.id}
            onMouseEnter={() => console.log(`Mouse entered tool card: ${tool.id}`)}
            onMouseLeave={() => console.log(`Mouse left tool card: ${tool.id}`)}
          >
            <Card 
              className="border-border/40 glass-card enhanced-card"
              onClick={() => console.log(`Card clicked for tool: ${tool.id}`)}
            >
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className="text-2xl">{tool.icon}</div>
                    <div>
                      <CardTitle className="text-lg">{tool.name}</CardTitle>
                      <CardDescription className="text-xs mt-1">
                        {tool.description}
                      </CardDescription>
                    </div>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {tool.isRunning && (
                  <div className="space-y-2">
                    <div className="flex justify-between text-xs">
                      <span className="text-muted-foreground flex items-center gap-1">
                        <Loader2 className="w-3 h-3 animate-spin" />
                        Scanning...
                      </span>
                      <span>{Math.round(tool.progress)}%</span>
                    </div>
                    <Progress value={tool.progress} className="h-2" />
                  </div>
                )}
                
                {!tool.isRunning && tool.isComplete && (
                  <div className="p-3 rounded-lg bg-green-500/10 border border-green-500/20">
                    <p className="text-sm text-green-400 flex items-center gap-2">
                      <CheckCircle className="w-4 h-4" />
                      Scan completed successfully
                    </p>
                  </div>
                )}

                <div className="flex gap-2">
                  {!tool.isRunning ? (
                    <Button
                      onClick={() => {
                        console.log(`Start Scan button clicked for tool: ${tool.id}`);
                        console.log(`Target: ${target}`);
                        console.log(`Target length: ${target.length}`);
                        console.log(`Is target empty: ${!target}`);
                        console.log(`Tool details:`, tool);
                        console.log(`Full tools array:`, tools);
                        // Check if target is valid before starting scan
                        if (!target) {
                          console.log("Target is empty, not starting scan");
                          toast.error("Please enter a target before starting scan");
                          return;
                        }
                        startScan(tool.id);
                      }}
                      className={`flex-1 relative z-10 ${!target ? 'opacity-50 cursor-not-allowed' : 'bg-primary hover:bg-primary/90 cursor-pointer'}`}
                      style={{ 
                        position: 'relative',
                        zIndex: 10
                      }}
                    >
                      <Play className="w-4 h-4 mr-2" />
                      Start Scan
                    </Button>
                  ) : (
                    <Button
                      onClick={() => {
                        console.log(`Stop Scan button clicked for tool: ${tool.id}`);
                        console.log(`Tool details:`, tool);
                        console.log(`Full tools array:`, tools);
                        stopScan(tool.id);
                      }}
                      variant="destructive"
                      className="flex-1 relative z-10 cursor-pointer"
                      style={{ 
                        position: 'relative',
                        zIndex: 10
                      }}
                    >
                      <Square className="w-4 h-4 mr-2" />
                      Stop Scan
                    </Button>
                  )}
                </div>
                <div className="text-xs text-muted-foreground mt-2">
                  Tool: {tool.id} | Running: {tool.isRunning ? 'Yes' : 'No'} | 
                  Target: '{target}' | Length: {target.length} | 
                  Visually Disabled: {!target ? 'Yes' : 'No'}
                </div>
              </CardContent>
            </Card>
          </div>
        ))}
      </div>

      {/* Recent Scans */}
      <Card className="border-border/40 glass-card enhanced-card">
        <CardHeader>
          <CardTitle>Scan History</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {scanHistory.map((scan, index) => (
              <motion.div
                key={scan.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.3, delay: index * 0.05 }}
                className="flex items-center justify-between p-4 rounded-lg bg-muted/30 border border-border/40 hover:bg-muted/50 transition-colors"
              >
                <div className="flex items-center gap-4">
                  <Badge variant="secondary" className="bg-cyan-500/20 text-cyan-400">
                    {scan.tool}
                  </Badge>
                  <div>
                    <p className="text-sm">{scan.target}</p>
                    <p className="text-xs text-muted-foreground">{scan.time}</p>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <div className="text-right">
                    <p className="text-sm">{scan.findings} findings</p>
                    <Badge className="bg-green-500/20 text-green-400 text-xs">
                      {scan.status}
                    </Badge>
                  </div>
                  <Button 
                    variant="outline" 
                    size="sm"
                    onClick={() => {
                      console.log("View Report button clicked");
                      console.log(`Scan details:`, scan);
                      // Generate a mock report ID based on the scan details
                      const reportId = `rpt-${new Date().toISOString().slice(0, 10).replace(/-/g, '-')}-${scan.id}`;
                      if (onViewReport) {
                        onViewReport(reportId);
                      } else {
                        toast.info(`Viewing report for ${scan.target}`, {
                          description: "This would navigate to the report detail view in a full implementation"
                        });
                      }
                    }}
                  >
                    View Report
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