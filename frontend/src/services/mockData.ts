// Mock data service for the cybersecurity dashboard
export interface MockReport {
  id: string;
  target: string;
  scan_timestamp: string;
  severity_counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export interface MockVulnerability {
  id: string;
  cve: string;
  title: string;
  cvss: number;
  severity: "critical" | "high" | "medium" | "low";
  host: string;
  tool: string;
  date: string;
  status: string;
  description?: string;
  reference?: string;
}

export interface MockThreat {
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

export interface MockTrendingCVE {
  cve: string;
  title: string;
  exploitAvailable: boolean;
  cvss: number;
  description?: string;
}

export interface MockThreatActor {
  name: string;
  activity: string;
  targets: string;
  origin: string;
}

export interface MockAttackPathNode {
  id: string;
  type: "entry" | "intermediate" | "critical" | "host" | "vuln";
  label: string;
  severity: "critical" | "high" | "medium" | "low";
  cve?: string;
  description?: string;
}

export interface MockAttackPathEdge {
  from: string;
  to: string;
  desc: string;
}

export interface MockAttackPath {
  nodes: MockAttackPathNode[];
  edges: MockAttackPathEdge[];
}

export interface MockChatMessage {
  id: number;
  type: "user" | "assistant";
  content: string;
  timestamp: string;
  confidence?: number;
  citations?: Array<{ id: string; text: string }>;
}

// Mock data for all components
export const mockData = {
  // Dashboard data
  dashboard: {
    totalScans: 1247,
    vulnerabilities: {
      critical: 3,
      high: 12,
      medium: 45,
      low: 89
    },
    recentActivity: [
      { id: 1, action: "Nmap scan completed", target: "192.168.1.0/24", time: "2 minutes ago", status: "success" },
      { id: 2, action: "Vulnerability assessment", target: "api.example.com", time: "15 minutes ago", status: "warning" },
      { id: 3, action: "Network discovery", target: "10.0.0.0/16", time: "1 hour ago", status: "success" },
      { id: 4, action: "Compliance check", target: "internal.db", time: "3 hours ago", status: "info" }
    ],
    systemHealth: {
      cpu: 45,
      memory: 68,
      disk: 32,
      network: 12
    },
    topAssets: [
      { name: "Web Application", risk: "High", vulnerabilities: 27 },
      { name: "Database Server", risk: "Critical", vulnerabilities: 5 },
      { name: "API Gateway", risk: "Medium", vulnerabilities: 12 },
      { name: "File Server", risk: "Low", vulnerabilities: 3 }
    ]
  },

  // Reports data
  reports: [
    {
      id: "rpt-2025-10-15-0001",
      target: "scanme.nmap.org",
      scan_timestamp: "2025-10-15T10:30:00Z",
      severity_counts: { critical: 2, high: 5, medium: 12, low: 23 }
    },
    {
      id: "rpt-2025-10-14-0002",
      target: "192.168.1.0/24",
      scan_timestamp: "2025-10-14T14:45:00Z",
      severity_counts: { critical: 1, high: 8, medium: 15, low: 31 }
    },
    {
      id: "rpt-2025-10-13-0003",
      target: "api.examplecorp.com",
      scan_timestamp: "2025-10-13T09:12:00Z",
      severity_counts: { critical: 0, high: 3, medium: 7, low: 18 }
    },
    {
      id: "rpt-2025-10-12-0004",
      target: "webapp.staging.io",
      scan_timestamp: "2025-10-12T16:22:00Z",
      severity_counts: { critical: 3, high: 6, medium: 9, low: 14 }
    }
  ] as MockReport[],

  // Vulnerabilities data
  vulnerabilities: [
    {
      id: "vuln-1",
      cve: "CVE-2021-44228",
      title: "Apache Log4Shell Remote Code Execution",
      cvss: 10.0,
      severity: "critical",
      host: "scanme.nmap.org",
      tool: "Nuclei",
      date: "2025-10-15",
      status: "Open",
      description: "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
      reference: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    },
    {
      id: "vuln-2",
      cve: "CVE-2020-1472",
      title: "Netlogon Elevation of Privilege Vulnerability",
      cvss: 10.0,
      severity: "critical",
      host: "192.168.1.10",
      tool: "Nmap",
      date: "2025-10-14",
      status: "In Progress",
      description: "A remote code execution vulnerability exists when an attacker has established a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC).",
      reference: "https://nvd.nist.gov/vuln/detail/CVE-2020-1472"
    },
    {
      id: "vuln-3",
      cve: "CVE-2021-34527",
      title: "Windows Print Spooler Elevation of Privilege",
      cvss: 8.8,
      severity: "high",
      host: "192.168.1.15",
      tool: "Nuclei",
      date: "2025-10-14",
      status: "Open",
      description: "Windows Print Spooler Remote Code Execution Vulnerability",
      reference: "https://nvd.nist.gov/vuln/detail/CVE-2021-34527"
    },
    {
      id: "vuln-4",
      cve: "CVE-2017-0144",
      title: "Windows SMB Remote Code Execution",
      cvss: 8.1,
      severity: "high",
      host: "192.168.1.22",
      tool: "Nmap",
      date: "2025-10-14",
      status: "Resolved",
      description: "The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets.",
      reference: "https://nvd.nist.gov/vuln/detail/CVE-2017-0144"
    },
    {
      id: "vuln-5",
      cve: "CVE-2021-26855",
      title: "Microsoft Exchange Server Remote Code Execution",
      cvss: 9.1,
      severity: "critical",
      host: "mail.examplecorp.com",
      tool: "Nuclei",
      date: "2025-10-13",
      status: "Open",
      description: "Microsoft Exchange Server Remote Code Execution Vulnerability",
      reference: "https://nvd.nist.gov/vuln/detail/CVE-2021-26855"
    },
    {
      id: "vuln-6",
      cve: "",
      title: "SSH Weak Encryption Algorithms Enabled",
      cvss: 5.3,
      severity: "medium",
      host: "192.168.1.10",
      tool: "Nikto",
      date: "2025-10-14",
      status: "Open",
      description: "The SSH server is configured to support weak encryption algorithms such as arcfour and blowfish-cbc."
    },
    {
      id: "vuln-7",
      cve: "",
      title: "HTTP Server Header Disclosure",
      cvss: 5.3,
      severity: "medium",
      host: "webapp.staging.io",
      tool: "Nikto",
      date: "2025-10-12",
      status: "In Progress",
      description: "The web server is disclosing its version in HTTP headers, which can be used by attackers to identify potentially vulnerable versions."
    }
  ] as MockVulnerability[],

  // Threat intelligence data
  threats: [
    {
      id: 1,
      name: "APT-2024-STORM",
      type: "Advanced Persistent Threat",
      severity: "critical",
      targets: "Financial Services, Healthcare",
      description: "Sophisticated malware campaign targeting cloud infrastructure with zero-day exploits",
      indicators: ["185.220.101.45", "malicious-domain.xyz", "SHA256:a1b2c3..."],
      firstSeen: "2024-10-10",
      lastActivity: "2 hours ago"
    },
    {
      id: 2,
      name: "Ransomware-LOCK2024",
      type: "Ransomware Campaign",
      severity: "high",
      targets: "SMBs, Education",
      description: "New ransomware variant using double extortion tactics and supply chain compromise",
      indicators: ["192.168.88.1", "ransom-payment.onion", "SHA256:d4e5f6..."],
      firstSeen: "2024-10-08",
      lastActivity: "1 day ago"
    },
    {
      id: 3,
      name: "PHISH-CORP-Q4",
      type: "Phishing Campaign",
      severity: "medium",
      targets: "Corporate Email Users",
      description: "Credential harvesting campaign impersonating major SaaS providers",
      indicators: ["phishing-site.com", "185.220.102.33", "sender@fake-microsoft.com"],
      firstSeen: "2024-10-05",
      lastActivity: "5 hours ago"
    }
  ] as MockThreat[],

  threatActors: [
    { name: "LAZARUS GROUP", activity: "High", targets: "Cryptocurrency, Defense", origin: "North Korea" },
    { name: "FANCY BEAR", activity: "Medium", targets: "Government, Military", origin: "Russia" },
    { name: "WIZARD SPIDER", activity: "High", targets: "Healthcare, Finance", origin: "Eastern Europe" },
    { name: "KIMSUKY", activity: "Low", targets: "Think Tanks, Academia", origin: "North Korea" }
  ] as MockThreatActor[],

  trendingCVEs: [
    {
      cve: "CVE-2021-44228",
      title: "Apache Log4Shell",
      exploitAvailable: true,
      cvss: 10.0,
      description: "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints."
    },
    {
      cve: "CVE-2021-45046",
      title: "Apache Log4j DoS",
      exploitAvailable: true,
      cvss: 9.0,
      description: "When using the JMS Appender with a JNDI LDAP service URL in the format ${jndi:ldap://127.0.0.1#} with an unspecified host, Apache Log4j versions 2.0-alpha1 through 2.16.0 (excluding security release 2.12.2) were vulnerable to a denial of service attack."
    },
    {
      cve: "CVE-2022-22965",
      title: "Spring Framework RCE",
      exploitAvailable: true,
      cvss: 9.8,
      description: "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding when using JDK 9+ and specifically crafted references in the class property."
    }
  ] as MockTrendingCVE[],

  // Attack path data
  attackPaths: {
    "rpt-2025-10-15-0001": {
      nodes: [
        { id: "h1", type: "host", label: "scanme.nmap.org", severity: "critical", description: "Target host with multiple vulnerabilities" },
        { id: "v1", type: "vuln", label: "CVE-2021-44228", severity: "critical", cve: "CVE-2021-44228", description: "Apache Log4Shell Remote Code Execution" },
        { id: "v2", type: "vuln", label: "CVE-2020-1472", severity: "critical", cve: "CVE-2020-1472", description: "Netlogon Elevation of Privilege" },
        { id: "s1", type: "host", label: "Apache Tomcat", severity: "high", description: "Service running on port 8080" },
        { id: "s2", type: "host", label: "SSH", severity: "medium", description: "Service running on port 22" }
      ],
      edges: [
        { from: "h1", to: "v1", desc: "Vulnerable service detected" },
        { from: "h1", to: "v2", desc: "Domain controller vulnerability" },
        { from: "h1", to: "s1", desc: "Service running" },
        { from: "h1", to: "s2", desc: "Service running" },
        { from: "v1", to: "s1", desc: "Exploitable through web service" }
      ]
    },
    "rpt-2025-10-14-0002": {
      nodes: [
        { id: "h1", type: "host", label: "192.168.1.10", severity: "critical", description: "Windows Server 2019" },
        { id: "h2", type: "host", label: "192.168.1.15", severity: "high", description: "Windows 10 Workstation" },
        { id: "h3", type: "host", label: "192.168.1.22", severity: "medium", description: "Linux Server" },
        { id: "v1", type: "vuln", label: "CVE-2020-1472", severity: "critical", cve: "CVE-2020-1472", description: "Zerologon vulnerability" },
        { id: "v2", type: "vuln", label: "CVE-2021-34527", severity: "high", cve: "CVE-2021-34527", description: "PrintNightmare vulnerability" },
        { id: "s1", type: "host", label: "Telnet", severity: "high", description: "Insecure service on port 23" },
        { id: "s2", type: "host", label: "HTTPS", severity: "medium", description: "Weak SSL/TLS on port 443" }
      ],
      edges: [
        { from: "h1", to: "v1", desc: "Domain controller vulnerability" },
        { from: "h2", to: "v2", desc: "Print spooler vulnerability" },
        { from: "h2", to: "s1", desc: "Insecure service running" },
        { from: "h3", to: "s2", desc: "Weak encryption protocols" },
        { from: "v1", to: "h2", desc: "Lateral movement possible" },
        { from: "v1", to: "h3", desc: "Lateral movement possible" }
      ]
    }
  } as Record<string, MockAttackPath>,

  // Chat assistant data
  chatMessages: [
    {
      id: 1,
      type: "assistant",
      content: "Hello! I'm your AI cybersecurity assistant. I can help you with vulnerability analysis, CVE explanations, remediation steps, and security best practices. How can I assist you today?",
      timestamp: new Date().toLocaleTimeString()
    }
  ] as MockChatMessage[],

  sampleQuestions: [
    "What is the most critical vulnerability?",
    "How can I fix log4shell?",
    "What is the attack path?",
    "Explain CVSS scoring",
    "What is OWASP Top 10?",
    "How to prevent ransomware?",
    "What is a zero-day vulnerability?"
  ],

  // Settings data
  settings: {
    general: {
      companyName: "Cyber Rakshak",
      timezone: "UTC-05:00",
      language: "en",
      theme: "dark"
    },
    security: {
      twoFactorAuth: true,
      passwordExpiry: 90,
      sessionTimeout: 30,
      ipWhitelist: "192.168.1.0/24, 10.0.0.0/8"
    },
    notifications: {
      emailAlerts: true,
      slackNotifications: false,
      criticalAlerts: true,
      weeklyReports: true
    },
    scan: {
      autoScan: true,
      scanSchedule: "daily",
      concurrentScans: 5,
      scanTimeout: 3600
    }
  }
};