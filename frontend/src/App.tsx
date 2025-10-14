import { useState } from "react";
import { DashboardView } from "./components/DashboardView";
import { ScanConsoleView } from "./components/ScanConsoleView";
import { ReportsView } from "./components/ReportsView";
import { VulnerabilitiesView } from "./components/VulnerabilitiesView";
import { ThreatIntelView } from "./components/ThreatIntelView";
import { AttackPathView } from "./components/AttackPathView";
import { SettingsView } from "./components/SettingsView";
import { ChatAssistant } from "./components/ChatAssistant";

export default function App() {
  const [view, setView] = useState("dashboard");
  
  const renderView = () => {
    switch (view) {
      case "dashboard":
        return <DashboardView />;
      case "scan":
        return <ScanConsoleView />;
      case "reports":
        return <ReportsView />;
      case "vulnerabilities":
        return <VulnerabilitiesView />;
      case "threat-intel":
        return <ThreatIntelView />;
      case "attack-path":
        return <AttackPathView />;
      case "settings":
        return <SettingsView />;
      case "chat":
        return <ChatAssistant />;
      default:
        return <DashboardView />;
    }
  };

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Navigation */}
      <nav className="border-b border-border/40 bg-card/60 backdrop-blur-sm sticky top-0 z-50">
        <div className="container flex items-center gap-6 h-16">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-primary flex items-center justify-center">
              <div className="w-4 h-4 rounded-full bg-primary-foreground"></div>
            </div>
            <span className="font-bold text-lg">CyberShield</span>
          </div>
          
          <div className="flex items-center gap-4 ml-auto">
            <button 
              onClick={() => setView("dashboard")}
              className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                view === "dashboard" 
                  ? "bg-primary text-primary-foreground" 
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              Dashboard
            </button>
            <button 
              onClick={() => setView("scan")}
              className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                view === "scan" 
                  ? "bg-primary text-primary-foreground" 
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              Scan Console
            </button>
            <button 
              onClick={() => setView("reports")}
              className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                view === "reports" 
                  ? "bg-primary text-primary-foreground" 
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              Reports
            </button>
            <button 
              onClick={() => setView("vulnerabilities")}
              className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                view === "vulnerabilities" 
                  ? "bg-primary text-primary-foreground" 
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              Vulnerabilities
            </button>
            <button 
              onClick={() => setView("threat-intel")}
              className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                view === "threat-intel" 
                  ? "bg-primary text-primary-foreground" 
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              Threat Intel
            </button>
            <button 
              onClick={() => setView("attack-path")}
              className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                view === "attack-path" 
                  ? "bg-primary text-primary-foreground" 
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              Attack Path
            </button>
            <button 
              onClick={() => setView("chat")}
              className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                view === "chat" 
                  ? "bg-primary text-primary-foreground" 
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              Chat Assistant
            </button>
            <button 
              onClick={() => setView("settings")}
              className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                view === "settings" 
                  ? "bg-primary text-primary-foreground" 
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              Settings
            </button>
          </div>
        </div>
      </nav>
      
      {/* Main Content */}
      <main className="container py-6">
        {renderView()}
      </main>
    </div>
  );
}