import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Button } from "./ui/button";
import { Progress } from "./ui/progress";
import { Badge } from "./ui/badge";
import { Activity, AlertTriangle, Clock, CheckCircle2, RefreshCw, TrendingUp, Users, Globe, Database, Zap } from "lucide-react";
import { motion } from "framer-motion";
import { mockData } from "../services/mockData";

export function DashboardView() {
  const [refreshing, setRefreshing] = useState(false);
  
  const handleRefresh = () => {
    setRefreshing(true);
    // Simulate refresh
    setTimeout(() => setRefreshing(false), 1000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Security Dashboard</h1>
          <p className="text-muted-foreground">Monitor your cybersecurity posture</p>
        </div>
        <Button 
          onClick={handleRefresh}
          variant="outline" 
          size="sm"
          className="flex items-center gap-2"
          disabled={refreshing}
        >
          <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
        >
          <Card className="glass-card enhanced-card">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
              <Activity className="w-4 h-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{mockData.dashboard.totalScans.toLocaleString()}</div>
              <p className="text-xs text-muted-foreground">+12% from last month</p>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.1 }}
        >
          <Card className="glass-card enhanced-card border-destructive/50">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium">Critical Issues</CardTitle>
              <AlertTriangle className="w-4 h-4 text-destructive" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-destructive">{mockData.dashboard.vulnerabilities.critical}</div>
              <p className="text-xs text-muted-foreground">Requires immediate attention</p>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.2 }}
        >
          <Card className="glass-card enhanced-card">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium">High Risk</CardTitle>
              <TrendingUp className="w-4 h-4 text-orange-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-orange-500">{mockData.dashboard.vulnerabilities.high}</div>
              <p className="text-xs text-muted-foreground">Needs prompt resolution</p>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.3 }}
        >
          <Card className="glass-card enhanced-card">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium">System Health</CardTitle>
              <CheckCircle2 className="w-4 h-4 text-green-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-500">98%</div>
              <p className="text-xs text-muted-foreground">All systems operational</p>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Vulnerabilities Chart */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.4 }}
          className="lg:col-span-2"
        >
          <Card className="glass-card enhanced-card">
            <CardHeader>
              <CardTitle>Vulnerability Distribution</CardTitle>
              <CardDescription>Breakdown by severity level</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span>Critical</span>
                    <span>{mockData.dashboard.vulnerabilities.critical}</span>
                  </div>
                  <Progress value={(mockData.dashboard.vulnerabilities.critical / 100) * 100} className="h-2" />
                </div>
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span>High</span>
                    <span>{mockData.dashboard.vulnerabilities.high}</span>
                  </div>
                  <Progress value={(mockData.dashboard.vulnerabilities.high / 100) * 100} className="h-2 bg-orange-900/30" />
                </div>
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span>Medium</span>
                    <span>{mockData.dashboard.vulnerabilities.medium}</span>
                  </div>
                  <Progress value={(mockData.dashboard.vulnerabilities.medium / 100) * 100} className="h-2 bg-yellow-900/30" />
                </div>
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span>Low</span>
                    <span>{mockData.dashboard.vulnerabilities.low}</span>
                  </div>
                  <Progress value={(mockData.dashboard.vulnerabilities.low / 100) * 100} className="h-2 bg-green-900/30" />
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* System Health */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.5 }}
        >
          <Card className="glass-card enhanced-card">
            <CardHeader>
              <CardTitle>System Health</CardTitle>
              <CardDescription>Resource utilization</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span className="flex items-center gap-2">
                      <Zap className="w-4 h-4" />
                      CPU
                    </span>
                    <span>{mockData.dashboard.systemHealth.cpu}%</span>
                  </div>
                  <Progress value={mockData.dashboard.systemHealth.cpu} className="h-2" />
                </div>
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span className="flex items-center gap-2">
                      <Database className="w-4 h-4" />
                      Memory
                    </span>
                    <span>{mockData.dashboard.systemHealth.memory}%</span>
                  </div>
                  <Progress value={mockData.dashboard.systemHealth.memory} className="h-2" />
                </div>
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span className="flex items-center gap-2">
                      <Globe className="w-4 h-4" />
                      Disk
                    </span>
                    <span>{mockData.dashboard.systemHealth.disk}%</span>
                  </div>
                  <Progress value={mockData.dashboard.systemHealth.disk} className="h-2" />
                </div>
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span className="flex items-center gap-2">
                      <Users className="w-4 h-4" />
                      Network
                    </span>
                    <span>{mockData.dashboard.systemHealth.network}%</span>
                  </div>
                  <Progress value={mockData.dashboard.systemHealth.network} className="h-2" />
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Recent Activity and Top Assets */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Recent Activity */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.6 }}
        >
          <Card className="glass-card enhanced-card">
            <CardHeader>
              <CardTitle>Recent Activity</CardTitle>
              <CardDescription>Latest security scans and assessments</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {mockData.dashboard.recentActivity.map((activity, index) => (
                  <div key={activity.id} className="flex items-center gap-4 p-3 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors">
                    <div className={`p-2 rounded-full ${
                      activity.status === 'success' ? 'bg-green-500/20' :
                      activity.status === 'warning' ? 'bg-orange-500/20' :
                      'bg-blue-500/20'
                    }`}>
                      {activity.status === 'success' ? (
                        <CheckCircle2 className="w-4 h-4 text-green-500" />
                      ) : activity.status === 'warning' ? (
                        <AlertTriangle className="w-4 h-4 text-orange-500" />
                      ) : (
                        <Clock className="w-4 h-4 text-blue-500" />
                      )}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{activity.action}</p>
                      <p className="text-xs text-muted-foreground truncate">{activity.target}</p>
                    </div>
                    <div className="text-xs text-muted-foreground whitespace-nowrap">
                      {activity.time}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Top Assets */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.7 }}
        >
          <Card className="glass-card enhanced-card">
            <CardHeader>
              <CardTitle>Top Assets</CardTitle>
              <CardDescription>Critical infrastructure components</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {mockData.dashboard.topAssets.map((asset, index) => (
                  <div key={index} className="flex items-center justify-between p-3 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors">
                    <div>
                      <p className="text-sm font-medium">{asset.name}</p>
                      <Badge 
                        variant={
                          asset.risk === 'Critical' ? 'destructive' :
                          asset.risk === 'High' ? 'secondary' :
                          'default'
                        }
                        className="mt-1"
                      >
                        {asset.risk} Risk
                      </Badge>
                    </div>
                    <div className="text-right">
                      <p className="text-sm font-medium">{asset.vulnerabilities} issues</p>
                      <p className="text-xs text-muted-foreground">Vulnerabilities</p>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>
    </div>
  );
}