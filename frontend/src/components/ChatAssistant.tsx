import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Input } from "./ui/input";
import { Button } from "./ui/button";
import { ScrollArea } from "./ui/scroll-area";
import { Bot, Send, User, AlertTriangle } from "lucide-react";
import { toast } from "sonner";
import { mockData } from "../services/mockData";

interface Message {
  id: number;
  type: "user" | "assistant";
  content: string;
  timestamp: string;
  confidence?: number;
  citations?: Array<{ id: string; text: string }>;
}

export function ChatAssistant() {
  const [messages, setMessages] = useState([] as Message[]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    // Initialize with mock messages
    setMessages(mockData.chatMessages);
  }, []);

  const sampleQuestions = mockData.sampleQuestions;

  // Hardcoded responses for quick questions
  const getHardcodedResponse = (query: string): any | null => {
    const normalizedQuery = query.toLowerCase().trim();
    
    // Greetings - more comprehensive handling
    if (normalizedQuery === "hi" || normalizedQuery === "hello" || normalizedQuery === "hey" || 
        normalizedQuery.includes("hello") || normalizedQuery.includes("hi") || normalizedQuery.includes("hey") ||
        normalizedQuery === "good morning" || normalizedQuery.includes("good morning") ||
        normalizedQuery === "good afternoon" || normalizedQuery.includes("good afternoon") ||
        normalizedQuery === "good evening" || normalizedQuery.includes("good evening")) {
      // Determine specific greeting response
      if (normalizedQuery === "good morning" || normalizedQuery.includes("good morning")) {
        return {
          answer: "Good morning! Ready to dive into cybersecurity topics? I can help with vulnerability assessments, threat intelligence, or security recommendations.",
          confidence: 0.95
        };
      }
      
      if (normalizedQuery === "good afternoon" || normalizedQuery.includes("good afternoon")) {
        return {
          answer: "Good afternoon! How can I assist with your cybersecurity needs today? I'm here to help with vulnerability analysis, CVE research, and security guidance.",
          confidence: 0.95
        };
      }
      
      if (normalizedQuery === "good evening" || normalizedQuery.includes("good evening")) {
        return {
          answer: "Good evening! I'm here to help with any cybersecurity questions you might have. Whether it's about vulnerabilities, threats, or security best practices, just ask!",
          confidence: 0.95
        };
      }
      
      // Default greeting response
      return {
        answer: "Hello! I'm your AI cybersecurity assistant. How can I help you with vulnerability analysis, CVE explanations, or security best practices today?",
        confidence: 0.95
      };
    }
    
    // Common questions
    if (normalizedQuery.includes("what can you do") || normalizedQuery.includes("what are your capabilities") || 
        normalizedQuery.includes("help") || normalizedQuery === "help") {
      return {
        answer: "I'm your AI cybersecurity assistant with several key capabilities:\n\n" +
                "1. **Vulnerability Analysis**: I can explain CVEs, their severity, and potential impact\n" +
                "2. **Remediation Guidance**: I provide step-by-step instructions to fix security issues\n" +
                "3. **Threat Intelligence**: I can discuss current threats and attack vectors\n" +
                "4. **Security Best Practices**: I offer guidance on secure configurations and practices\n" +
                "5. **Attack Path Analysis**: I can explain how vulnerabilities might be chained together\n\n" +
                "Try asking me about specific CVEs like \"What is CVE-2021-44228?\" or general questions like \"How to secure a web server?\"",
        confidence: 0.95
      };
    }
    
    if (normalizedQuery.includes("how are you") || normalizedQuery.includes("how do you do")) {
      return {
        answer: "I'm functioning optimally and ready to assist with your cybersecurity questions! I'm constantly updated with the latest threat intelligence and vulnerability data. How can I help you today?",
        confidence: 0.95
      };
    }
    
    if (normalizedQuery.includes("thank") || normalizedQuery.includes("thanks")) {
      return {
        answer: "You're welcome! I'm glad I could assist. Feel free to ask anytime if you have more cybersecurity questions. Stay secure!",
        confidence: 0.95
      };
    }
    
    if (normalizedQuery.includes("who are you") || normalizedQuery.includes("what are you")) {
      return {
        answer: "I'm your AI-powered cybersecurity assistant, part of the Cyber Rakshak platform. I'm designed to help security professionals and developers understand vulnerabilities, assess risks, and implement effective security measures. I have access to extensive vulnerability databases, threat intelligence, and security best practices.",
        confidence: 0.95
      };
    }
    
    if (normalizedQuery.includes("most critical vulnerability") || normalizedQuery.includes("critical vulnerability")) {
      return {
        answer: "Based on the scan results, the most critical vulnerability identified is Apache Log4Shell (CVE-2021-44228). This is a remote code execution vulnerability in Apache Log4j with a CVSS score of 10.0 (Critical). It allows attackers to execute arbitrary code on affected systems simply by logging a specially crafted string.",
        citations: [
          {
            id: "cve-1",
            source: "NVD",
            text_snippet: "CVE-2021-44228: Apache Log4j RCE vulnerability",
            ref: "nvd:cve-2021-44228"
          }
        ],
        confidence: 0.95
      };
    }
    
    if (normalizedQuery.includes("owasp top 10") || normalizedQuery.includes("owasp")) {
      return {
        answer: "The OWASP Top 10 is a standard awareness document for developers and web application security. It represents a broad consensus about the most critical security risks to web applications. The current 2021 list includes:\n\n" +
                "1. **Broken Access Control** - Failures in authentication and session management\n" +
                "2. **Cryptographic Failures** - Including sensitive data exposure\n" +
                "3. **Injection** - SQL, NoSQL, OS, and LDAP injection flaws\n" +
                "4. **Insecure Design** - Design flaws that lead to security issues\n" +
                "5. **Security Misconfiguration** - Insecure default configurations\n" +
                "6. **Vulnerable and Outdated Components** - Using components with known vulnerabilities\n" +
                "7. **Identification and Authentication Failures** - Flaws in authentication mechanisms\n" +
                "8. **Software and Data Integrity Failures** - Including code signing issues\n" +
                "9. **Security Logging and Monitoring Failures** - Insufficient logging and monitoring\n" +
                "10. **Server-Side Request Forgery (SSRF)** - Triggering requests to unintended destinations",
        citations: [
          {
            id: "owasp-1",
            source: "OWASP",
            text_snippet: "OWASP Top 10 - 2021",
            ref: "owasp:top10-2021"
          }
        ],
        confidence: 0.95
      };
    }
    
    if (normalizedQuery.includes("zero day") || normalizedQuery.includes("zero-day")) {
      return {
        answer: "A zero-day vulnerability is a software flaw that is unknown to the vendor and has not yet been patched. The term \"zero-day\" refers to the fact that the vendor has had zero days to address and patch the vulnerability. Attackers can exploit these vulnerabilities immediately, making them particularly dangerous.\n\n" +
                "Key characteristics of zero-day attacks:\n" +
                "- **Unknown to defenders**: No patches or signatures exist to detect them\n" +
                "- **High impact**: Often successful because systems are unprepared\n" +
                "- **Valuable**: Can sell for hundreds of thousands of dollars on the black market\n" +
                "- **Short lifespan**: Once discovered, vendors rush to create patches\n\n" +
                "Protection strategies include:\n" +
                "- Behavioral analysis and anomaly detection\n" +
                "- Keeping systems updated with latest security patches\n" +
                "- Network segmentation to limit lateral movement\n" +
                "- Regular security assessments and penetration testing",
        citations: [
          {
            id: "zero-1",
            source: "NIST",
            text_snippet: "Zero-day vulnerability definition and mitigation strategies",
            ref: "nist:zero-day-mitigation"
          }
        ],
        confidence: 0.9
      };
    }
    
    if (normalizedQuery.includes("ransomware") || normalizedQuery.includes("ransom ware")) {
      return {
        answer: "Ransomware is a type of malicious software that encrypts a victim's files and demands payment (ransom) for the decryption key. It's one of the most significant cybersecurity threats today.\n\n" +
                "Common ransomware attack vectors:\n" +
                "- **Phishing emails** with malicious attachments\n" +
                "- **Remote Desktop Protocol (RDP)** exploitation\n" +
                "- **Software vulnerabilities** in web browsers or plugins\n" +
                "- **Malvertising** (malicious advertising) on legitimate websites\n\n" +
                "Protection strategies:\n" +
                "- Regular backups stored offline or in cloud services\n" +
                "- Employee security awareness training\n" +
                "- Network segmentation to limit lateral movement\n" +
                "- Application whitelisting and endpoint protection\n" +
                "- Regular software updates and patch management\n\n" +
                "In case of infection:\n" +
                "- Isolate affected systems immediately\n" +
                "- Report to authorities (FBI IC3, local cybercrime units)\n" +
                "- Do not pay the ransom (no guarantee of data recovery)\n" +
                "- Engage cybersecurity incident response professionals",
        citations: [
          {
            id: "ransom-1",
            source: "CISA",
            text_snippet: "Ransomware guide and protection recommendations",
            ref: "cisa:ransomware-protection"
          }
        ],
        confidence: 0.95
      };
    }
    
    if (normalizedQuery.includes("fix log4shell") || normalizedQuery.includes("log4shell")) {
      return {
        answer: "To fix the Log4Shell vulnerability (CVE-2021-44228), follow these remediation steps:\n\n1. **Immediate Action**: Update Apache Log4j to version 2.17.1 or later\n2. **Workaround**: Set the system property 'log4j2.formatMsgNoLookups' to 'true'\n3. **Mitigation**: Remove the JndiLookup class from the log4j-core JAR file\n4. **Monitoring**: Watch for exploitation attempts in your logs\n5. **Verification**: Confirm the update was successful across all affected systems",
        citations: [
          {
            id: "rem-1",
            source: "Apache",
            text_snippet: "Log4j 2.17.1 release notes and security fixes",
            ref: "apache:log4j-2.17.1"
          }
        ],
        confidence: 0.9
      };
    }
    
    if (normalizedQuery.includes("attack path")) {
      return {
        answer: "The identified attack path to gain root access on the target system is:\n\n1. **Initial Access**: Exploit Apache Log4Shell (CVE-2021-44228) on port 8080 to gain user-level access\n2. **Privilege Escalation**: Use Dirty Pipe (CVE-2022-0847) to escalate from user to root privileges\n3. **Persistence**: Install a backdoor for continued access\n\nThis path has a high likelihood of success due to the critical severity of both vulnerabilities.",
        citations: [
          {
            id: "path-1",
            source: "AttackGraph",
            text_snippet: "Critical vulnerability chain: Log4Shell → Dirty Pipe",
            ref: "attackgraph:critical-chain"
          }
        ],
        confidence: 0.85
      };
    }
    
    if (normalizedQuery.includes("cvss scoring") || normalizedQuery.includes("cvss")) {
      return {
        answer: "CVSS (Common Vulnerability Scoring System) is an open framework for communicating the characteristics and severity of software vulnerabilities. The scoring ranges are:\n\n- **None**: 0.0\n- **Low**: 0.1 - 3.9\n- **Medium**: 4.0 - 6.9\n- **High**: 7.0 - 8.9\n- **Critical**: 9.0 - 10.0\n\nThe CVSS score is calculated based on metrics such as attack vector, attack complexity, privileges required, user interaction, scope, confidentiality, integrity, and availability impact.",
        citations: [
          {
            id: "cvss-1",
            source: "NIST",
            text_snippet: "CVSS v3.1 specification and scoring guidelines",
            ref: "nist:cvss-v3.1"
          }
        ],
        confidence: 0.95
      };
    }
    
    return null;
  };

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;

    const userMessage: Message = {
      id: messages.length + 1,
      type: "user",
      content: input,
      timestamp: new Date().toLocaleTimeString()
    };

    setMessages(prev => [...prev, userMessage]);
    setIsLoading(true);
    setInput("");

    try {
      // Check if we have a hardcoded response for this query
      const hardcodedResponse = getHardcodedResponse(input);
      
      if (hardcodedResponse) {
        // Use the hardcoded response
        const assistantMessage: Message = {
          id: messages.length + 2,
          type: "assistant",
          content: hardcodedResponse.answer,
          timestamp: new Date().toLocaleTimeString(),
          confidence: hardcodedResponse.confidence,
          citations: hardcodedResponse.citations ? hardcodedResponse.citations.map((c: any) => ({ id: c.id, text: c.text_snippet })) : []
        };

        setMessages(prev => [...prev, assistantMessage]);
      } else {
        // Create a mock response for other queries
        const mockResponse = {
          answer: "I understand your question about \"" + input + "\". Based on the security data I've analyzed, this is an important topic in cybersecurity. For specific vulnerabilities or threats, I recommend checking the Vulnerabilities and Threat Intel sections of the dashboard.",
          confidence: 0.7,
          citations: []
        };

        const assistantMessage: Message = {
          id: messages.length + 2,
          type: "assistant",
          content: mockResponse.answer,
          timestamp: new Date().toLocaleTimeString(),
          confidence: mockResponse.confidence,
          citations: mockResponse.citations
        };

        setMessages(prev => [...prev, assistantMessage]);
      }
    } catch (error) {
      console.error("Chat error:", error);
      toast.error("Chat error", {
        description: "Failed to get response from the assistant. Please try again."
      });

      const errorMessage: Message = {
        id: messages.length + 2,
        type: "assistant",
        content: "Sorry, I encountered an error processing your request. Please try again.",
        timestamp: new Date().toLocaleTimeString()
      };

      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="mb-2">Chat Assistant</h1>
        <p className="text-muted-foreground">Ask questions about vulnerabilities, CVEs, and security best practices</p>
      </div>

      <Card className="border-border/40 glass-card relative">
        <div className="scan-line"></div>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bot className="w-5 h-5 text-cyan-400 neon-glow-cyan" />
            AI Security Assistant
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Chat Messages */}
          <ScrollArea className="h-[500px] pr-4">
            <div className="space-y-4">
              {messages.map((message) => (
                <div
                  key={message.id}
                  className={`flex gap-3 ${message.type === "user" ? "justify-end" : "justify-start"}`}
                >
                  {message.type === "assistant" && (
                    <div className="w-8 h-8 rounded-full bg-cyan-500/20 flex items-center justify-center flex-shrink-0">
                      <Bot className="w-4 h-4 text-cyan-400" />
                    </div>
                  )}
                  <div
                    className={`max-w-[80%] rounded-lg p-4 ${
                      message.type === "user"
                        ? "bg-primary text-primary-foreground"
                        : "bg-muted/50"
                    }`}
                  >
                    <p className="text-sm whitespace-pre-line">{message.content}</p>
                    {message.confidence !== undefined && (
                      <div className="mt-2 flex items-center gap-2 text-xs">
                        <span className="opacity-60">Confidence:</span>
                        <div className="flex items-center gap-1">
                          <AlertTriangle className={`w-3 h-3 ${
                            message.confidence > 0.8 ? "text-green-400" :
                            message.confidence > 0.6 ? "text-yellow-400" : "text-red-400"
                          }`} />
                          <span className={
                            message.confidence > 0.8 ? "text-green-400" :
                            message.confidence > 0.6 ? "text-yellow-400" : "text-red-400"
                          }>
                            {Math.round(message.confidence * 100)}%
                          </span>
                        </div>
                      </div>
                    )}
                    {message.citations && message.citations.length > 0 && (
                      <div className="mt-2 text-xs opacity-60">
                        <p className="font-semibold">Sources:</p>
                        <ul className="list-disc pl-4 space-y-1">
                          {message.citations.map((citation, idx) => (
                            <li key={citation.id}>{citation.text}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                    <p className="text-xs opacity-60 mt-2">{message.timestamp}</p>
                  </div>
                  {message.type === "user" && (
                    <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center flex-shrink-0">
                      <User className="w-4 h-4 text-primary" />
                    </div>
                  )}
                </div>
              ))}
              {isLoading && (
                <div className="flex gap-3 justify-start">
                  <div className="w-8 h-8 rounded-full bg-cyan-500/20 flex items-center justify-center flex-shrink-0">
                    <Bot className="w-4 h-4 text-cyan-400" />
                  </div>
                  <div className="bg-muted/50 rounded-lg p-4 max-w-[80%]">
                    <div className="flex space-x-2">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 animate-bounce"></div>
                      <div className="w-2 h-2 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: '0.2s' }}></div>
                      <div className="w-2 h-2 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: '0.4s' }}></div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </ScrollArea>

          {/* Sample Questions */}
          <div className="space-y-2">
            <p className="text-sm text-muted-foreground">Quick questions:</p>
            <div className="flex flex-wrap gap-2">
              {sampleQuestions.slice(0, 5).map((question, idx) => (
                <Button
                  key={idx}
                  variant="outline"
                  size="sm"
                  onClick={() => setInput(question)}
                  className="text-xs"
                  disabled={isLoading}
                >
                  {question}
                </Button>
              ))}
            </div>
          </div>

          {/* Input */}
          <div className="flex gap-2">
            <Input
              placeholder="Ask about vulnerabilities, CVEs, remediation..."
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyPress={(e) => e.key === "Enter" && handleSend()}
              className="bg-muted/50 border-border/60"
              disabled={isLoading}
            />
            <Button 
              onClick={handleSend} 
              disabled={!input.trim() || isLoading} 
              className="bg-primary hover:bg-primary/90"
            >
              {isLoading ? (
                <div className="w-4 h-4 rounded-full border-2 border-white border-t-transparent animate-spin"></div>
              ) : (
                <Send className="w-4 h-4" />
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Features Info */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="border-border/40 glass-card enhanced-card">
          <CardContent className="p-4">
            <h4 className="mb-2">CVE Explanations</h4>
            <p className="text-sm text-muted-foreground">
              Get detailed information about any CVE including severity, impact, and affected systems.
            </p>
          </CardContent>
        </Card>
        <Card className="border-border/40 glass-card enhanced-card">
          <CardContent className="p-4">
            <h4 className="mb-2">Remediation Steps</h4>
            <p className="text-sm text-muted-foreground">
              Receive step-by-step guidance on how to fix vulnerabilities and secure your systems.
            </p>
          </CardContent>
        </Card>
        <Card className="border-border/40 glass-card enhanced-card">
          <CardContent className="p-4">
            <h4 className="mb-2">Best Practices</h4>
            <p className="text-sm text-muted-foreground">
              Learn industry best practices for security configurations and threat prevention.
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}