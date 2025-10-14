import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { GitBranch, AlertTriangle, Server, Database, Globe, Lock, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { mockData } from "../services/mockData";

interface Node {
  id: string;
  type: "entry" | "intermediate" | "critical" | "host" | "vuln";
  label: string;
  x: number;
  y: number;
  severity: "critical" | "high" | "medium" | "low";
  cve?: string;
  description?: string;
}

interface Edge {
  from: string;
  to: string;
  desc: string;
}

export function AttackPathView() {
  const [nodes, setNodes] = useState<Node[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [loading, setLoading] = useState(true);
  const [attackPaths, setAttackPaths] = useState<Array<{
    id: number;
    name: string;
    steps: number;
    severity: string;
    probability: string;
    impact: string;
  }>>([]);

  useEffect(() => {
    const fetchAttackPath = async () => {
      try {
        setLoading(true);
        // Use mock data for a specific report
        const attackPathData = mockData.attackPaths["rpt-2025-10-15-0001"];
        
        // Convert to our node format with random positions for demo
        const convertedNodes: Node[] = attackPathData.nodes.map(node => ({
          id: node.id,
          type: node.type,
          label: node.label,
          x: Math.random() * 600 + 50,
          y: Math.random() * 300 + 100,
          severity: node.severity,
          cve: node.cve,
          description: node.description
        }));
        
        setNodes(convertedNodes);
        setEdges(attackPathData.edges);
        
        // Generate attack paths based on the data
        setAttackPaths([
          {
            id: 1,
            name: "Web to Database Compromise",
            steps: attackPathData.edges.length,
            severity: "critical",
            probability: "High",
            impact: "Complete data breach"
          },
          {
            id: 2,
            name: "Privilege Escalation Chain",
            steps: Math.floor(attackPathData.edges.length / 2),
            severity: "high",
            probability: "Medium",
            impact: "Administrator access"
          }
        ]);
      } catch (error) {
        console.error("Failed to fetch attack path:", error);
        toast.error("Failed to load attack path", {
          description: "Please try again later"
        });
      } finally {
        setLoading(false);
      }
    };

    fetchAttackPath();
  }, []);

  const getNodeColor = (severity: string) => {
    switch (severity) {
      case "critical": return "#ef4444";
      case "high": return "#f97316";
      case "medium": return "#eab308";
      case "low": return "#06b6d4";
      default: return "#06b6d4";
    }
  };

  const getNodeIcon = (type: string) => {
    switch (type) {
      case "host": return <Server className="w-8 h-8" />;
      case "vuln": return <AlertTriangle className="w-8 h-8" />;
      case "entry": return <Globe className="w-8 h-8" />;
      case "critical": return <Database className="w-8 h-8" />;
      default: return <Server className="w-8 h-8" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="mb-2">Attack Path Visualizer</h1>
        <p className="text-muted-foreground">Visualize potential attack chains and exploitation paths</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Graph Visualization */}
        <Card className="border-border/40 glass-card enhanced-card lg:col-span-2 relative overflow-hidden">
          <div className="scan-line"></div>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <GitBranch className="w-5 h-5 text-purple-400 neon-glow-purple" />
              Attack Chain Graph
            </CardTitle>
            <CardDescription>
              Click on nodes to view vulnerability details
            </CardDescription>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="flex justify-center items-center h-96">
                <Loader2 className="w-8 h-8 animate-spin text-purple-400" />
              </div>
            ) : (
              <div className="relative bg-muted/20 rounded-lg border border-border/40 p-8" style={{ height: "500px" }}>
                {/* SVG Graph */}
                <svg width="100%" height="100%" className="absolute inset-0">
                  {/* Draw edges */}
                  <defs>
                    <marker
                      id="arrowhead"
                      markerWidth="10"
                      markerHeight="10"
                      refX="9"
                      refY="3"
                      orient="auto"
                    >
                      <polygon points="0 0, 10 3, 0 6" fill="#6366f1" opacity="0.5" />
                    </marker>
                  </defs>
                  {edges.map((edge, idx) => {
                    const fromNode = nodes.find(n => n.id === edge.from);
                    const toNode = nodes.find(n => n.id === edge.to);
                    if (!fromNode || !toNode) return null;
                    return (
                      <line
                        key={idx}
                        x1={fromNode.x}
                        y1={fromNode.y}
                        x2={toNode.x}
                        y2={toNode.y}
                        stroke="#6366f1"
                        strokeWidth="2"
                        opacity="0.5"
                        markerEnd="url(#arrowhead)"
                      />
                    );
                  })}
                </svg>

                {/* Draw nodes */}
                {nodes.map((node) => (
                  <div
                    key={node.id}
                    className="absolute cursor-pointer transform -translate-x-1/2 -translate-y-1/2 transition-all hover:scale-110"
                    style={{
                      left: `${node.x}px`,
                      top: `${node.y}px`,
                    }}
                    onClick={() => setSelectedNode(node)}
                  >
                    <div
                      className="w-16 h-16 rounded-full flex items-center justify-center border-4 shadow-lg"
                      style={{
                        backgroundColor: getNodeColor(node.severity) + "20",
                        borderColor: getNodeColor(node.severity),
                      }}
                    >
                      {getNodeIcon(node.type)}
                    </div>
                    <div className="mt-2 text-center">
                      <p className="text-xs whitespace-nowrap">{node.label}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Node Details */}
        <Card className="border-border/40 glass-card enhanced-card">
          <CardHeader>
            <CardTitle>Node Details</CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="flex justify-center items-center h-64">
                <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
              </div>
            ) : selectedNode ? (
              <div className="space-y-4">
                <div>
                  <h3 className="mb-2">{selectedNode.label}</h3>
                  <Badge className={
                    selectedNode.severity === "critical" ? "bg-red-500/20 text-red-400" :
                    selectedNode.severity === "high" ? "bg-orange-500/20 text-orange-400" :
                    selectedNode.severity === "medium" ? "bg-yellow-500/20 text-yellow-400" :
                    "bg-blue-500/20 text-blue-400"
                  }>
                    {selectedNode.severity}
                  </Badge>
                </div>

                {selectedNode.cve && (
                  <div className="space-y-2">
                    <p className="text-sm text-muted-foreground">Associated CVE</p>
                    <code className="text-xs bg-muted/50 px-2 py-1 rounded block">
                      {selectedNode.cve}
                    </code>
                  </div>
                )}

                {selectedNode.description && (
                  <div className="space-y-2">
                    <p className="text-sm text-muted-foreground">Description</p>
                    <p className="text-sm">{selectedNode.description}</p>
                  </div>
                )}

                <div className="space-y-2">
                  <p className="text-sm text-muted-foreground">Node Type</p>
                  <p className="text-sm capitalize">{selectedNode.type.replace("_", " ")}</p>
                </div>

                <div className="space-y-2">
                  <p className="text-sm text-muted-foreground">Impact</p>
                  <p className="text-sm">
                    {selectedNode.type === "critical" ? "Full system compromise possible" :
                     selectedNode.type === "vuln" ? "Exploitable vulnerability" :
                     selectedNode.type === "host" ? "System asset" :
                     "Network component"}
                  </p>
                </div>

                <div className="pt-4 space-y-2">
                  <Button className="w-full bg-primary hover:bg-primary/90">
                    View Remediation
                  </Button>
                  <Button variant="outline" className="w-full">
                    Generate Report
                  </Button>
                </div>
              </div>
            ) : (
              <div className="text-center py-8 text-muted-foreground">
                <Lock className="w-12 h-12 mx-auto mb-3 opacity-50" />
                <p className="text-sm">Select a node to view details</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Attack Paths List */}
      <Card className="border-border/40 glass-card enhanced-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-orange-400" />
            Identified Attack Paths
          </CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex justify-center items-center h-32">
              <Loader2 className="w-6 h-6 animate-spin text-orange-400" />
            </div>
          ) : (
            <div className="space-y-3">
              {attackPaths.map((path) => (
                <div
                  key={path.id}
                  className="flex items-center justify-between p-4 rounded-lg bg-muted/30 border border-border/40"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-3">
                      <h4>{path.name}</h4>
                      <Badge className={
                        path.severity === "critical" ? "bg-red-500/20 text-red-400" :
                        "bg-orange-500/20 text-orange-400"
                      }>
                        {path.severity}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-4 text-sm text-muted-foreground">
                      <span>{path.steps} steps</span>
                      <span>•</span>
                      <span>Probability: {path.probability}</span>
                      <span>•</span>
                      <span>{path.impact}</span>
                    </div>
                  </div>
                  <Button variant="outline" size="sm">
                    Analyze Path
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}