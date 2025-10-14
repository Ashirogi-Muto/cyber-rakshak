import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Badge } from "./ui/badge";
import { Globe, TrendingUp, AlertCircle, Shield, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { mockData } from "../services/mockData";

interface Threat {
  id: number;
  name: string;
  type: string;
  severity: string;
  targets: string;
  description: string;
  indicators: string[];
  firstSeen: string;
  lastActivity: string;
}

interface TrendingCVE {
  cve: string;
  title: string;
  exploitAvailable: boolean;
  cvss: number;
  description?: string;
}

interface ThreatActor {
  name: string;
  activity: string;
  targets: string;
  origin: string;
}

export function ThreatIntelView() {
  const [threats, setThreats] = useState([] as Threat[]);
  const [trendingCVEs, setTrendingCVEs] = useState([] as TrendingCVE[]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setThreats(mockData.threats);
    setTrendingCVEs(mockData.trendingCVEs);
    setLoading(false);
  }, []);

  const threatActors: ThreatActor[] = mockData.threatActors;

  const handleViewCVE = (cve: string) => {
    const cveData = mockData.trendingCVEs.find(item => item.cve === cve);
    if (cveData) {
      toast.info(`CVE Details: ${cve}`, {
        description: cveData.description
      });
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="mb-2">Threat Intelligence</h1>
        <p className="text-muted-foreground">Latest threats, vulnerabilities, and actor activities</p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="border-border/40 glass-card enhanced-card">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center neon-glow">
                <AlertCircle className="w-5 h-5 text-red-400" />
              </div>
              <div>
                <p className="text-2xl">23</p>
                <p className="text-xs text-muted-foreground">Active Threats</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-border/40 glass-card enhanced-card">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center neon-glow-purple">
                <Globe className="w-5 h-5 text-purple-400" />
              </div>
              <div>
                <p className="text-2xl">156</p>
                <p className="text-xs text-muted-foreground">IOCs Tracked</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-border/40 glass-card enhanced-card">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-orange-500/10 flex items-center justify-center">
                <TrendingUp className="w-5 h-5 text-orange-400" />
              </div>
              <div>
                <p className="text-2xl">{trendingCVEs.length}</p>
                <p className="text-xs text-muted-foreground">Trending CVEs</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-border/40 glass-card enhanced-card">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-cyan-500/10 flex items-center justify-center neon-glow-cyan">
                <Shield className="w-5 h-5 text-cyan-400" />
              </div>
              <div>
                <p className="text-2xl">12</p>
                <p className="text-xs text-muted-foreground">Threat Actors</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Active Threats */}
      <Card className="border-border/40 glass-card enhanced-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertCircle className="w-5 h-5 text-red-400" />
            Active Threat Campaigns
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {threats.map((threat) => (
            <div key={threat.id} className="p-4 rounded-lg bg-muted/30 border border-border/40 space-y-3">
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-3 mb-2">
                    <h3>{threat.name}</h3>
                    <Badge className={
                      threat.severity === "critical" ? "bg-red-500/20 text-red-400" :
                      threat.severity === "high" ? "bg-orange-500/20 text-orange-400" :
                      "bg-yellow-500/20 text-yellow-400"
                    }>
                      {threat.severity}
                    </Badge>
                    <Badge variant="secondary" className="bg-purple-500/20 text-purple-400">
                      {threat.type}
                    </Badge>
                  </div>
                  <p className="text-sm text-muted-foreground mb-2">
                    Targets: {threat.targets}
                  </p>
                </div>
                <div className="text-right text-xs text-muted-foreground">
                  <p>First seen: {threat.firstSeen}</p>
                  <p>Last activity: {threat.lastActivity}</p>
                </div>
              </div>

              <p className="text-sm">{threat.description}</p>

              <div className="space-y-2">
                <p className="text-sm text-muted-foreground">Indicators of Compromise (IOCs):</p>
                <div className="flex flex-wrap gap-2">
                  {threat.indicators.map((indicator, idx) => (
                    <code key={idx} className="text-xs bg-muted/50 px-2 py-1 rounded">
                      {indicator}
                    </code>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Trending CVEs */}
        <Card className="border-border/40 glass-card enhanced-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp className="w-5 h-5 text-orange-400" />
              Trending CVEs
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {loading ? (
              <div className="flex justify-center items-center h-32">
                <Loader2 className="w-6 h-6 animate-spin text-orange-400" />
              </div>
            ) : trendingCVEs.length > 0 ? (
              trendingCVEs.map((cve) => (
                <div 
                  key={cve.cve} 
                  className="flex items-center justify-between p-3 rounded-lg bg-muted/30 border border-border/40 cursor-pointer hover:bg-muted/50 transition-colors"
                  onClick={() => handleViewCVE(cve.cve)}
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <code className="text-xs bg-muted/50 px-2 py-1 rounded">{cve.cve}</code>
                      {cve.exploitAvailable && (
                        <Badge className="bg-red-500/20 text-red-400 text-xs">
                          Exploit Available
                        </Badge>
                      )}
                    </div>
                    <p className="text-sm">{cve.title}</p>
                  </div>
                  <div className="text-right">
                    <p className={cve.cvss >= 9 ? "text-red-400" : cve.cvss >= 7 ? "text-orange-400" : "text-yellow-400"}>
                      {cve.cvss}
                    </p>
                    <p className="text-xs text-muted-foreground">CVSS</p>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-8 text-muted-foreground">
                <p>No trending CVEs found</p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Threat Actors */}
        <Card className="border-border/40 glass-card enhanced-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-cyan-400 neon-glow-cyan" />
              Known Threat Actors
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {threatActors.map((actor, idx) => (
              <div key={idx} className="p-3 rounded-lg bg-muted/30 border border-border/40">
                <div className="flex items-start justify-between mb-2">
                  <h4 className="text-sm">{actor.name}</h4>
                  <Badge className={
                    actor.activity === "High" ? "bg-red-500/20 text-red-400" :
                    actor.activity === "Medium" ? "bg-yellow-500/20 text-yellow-400" :
                    "bg-green-500/20 text-green-400"
                  }>
                    {actor.activity} Activity
                  </Badge>
                </div>
                <div className="space-y-1 text-xs text-muted-foreground">
                  <p>Targets: {actor.targets}</p>
                  <p>Origin: {actor.origin}</p>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}