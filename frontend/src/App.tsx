import { useState, useEffect } from "react";
import { DashboardView } from "./components/DashboardView";
import { ScanConsoleView } from "./components/ScanConsoleView";
import { ReportsView } from "./components/ReportsView";
import { VulnerabilitiesView } from "./components/VulnerabilitiesView";
import { ThreatIntelView } from "./components/ThreatIntelView";
import { AttackPathView } from "./components/AttackPathView";
import { SettingsView } from "./components/SettingsView";
import { ChatAssistant } from "./components/ChatAssistant";
import { ReportDetailView } from "./components/ReportDetailView";
import { LoginPage } from "./components/LoginPage";
import { authService } from "./services/authService";

export default function App() {
  const [view, setView] = useState("dashboard");
  const [currentReportId, setCurrentReportId] = useState<string | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  // Check authentication status on component mount
  useEffect(() => {
    const checkAuthStatus = () => {
      const authStatus = authService.isAuthenticated();
      setIsAuthenticated(authStatus);
      setIsLoading(false);
    };

    checkAuthStatus();
  }, []);

  const handleLogin = () => {
    setIsAuthenticated(true);
    // Reset view to dashboard after login
    setView("dashboard");
  };

  const handleLogout = async () => {
    await authService.logout();
    setIsAuthenticated(false);
    setView("dashboard");
  };

  // Show loading state while checking auth
  if (isLoading) {
    return (
      <div className="min-h-screen bg-background text-foreground flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p>Loading...</p>
        </div>
      </div>
    );
  }

  // Show login page if not authenticated
  if (!isAuthenticated) {
    return <LoginPage onLogin={handleLogin} />;
  }

  const renderView = () => {
    switch (view) {
      case "dashboard":
        return <DashboardView />;
      case "scan":
        return <ScanConsoleView onViewReport={(reportId) => {
          setCurrentReportId(reportId);
          setView("report-detail");
        }} />;
      case "reports":
        return <ReportsView onViewReport={(reportId) => {
          setCurrentReportId(reportId);
          setView("report-detail");
        }} />;
      case "report-detail":
        return currentReportId ? (
          <ReportDetailView 
            reportId={currentReportId} 
            onBack={() => setView("reports")} 
          />
        ) : (
          <ReportsView />
        );
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
            <span className="font-bold text-lg">Cyber Rakshak</span>
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
            <button 
              onClick={handleLogout}
              className="px-3 py-2 rounded-md text-sm font-medium text-muted-foreground hover:text-foreground"
            >
              Logout
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