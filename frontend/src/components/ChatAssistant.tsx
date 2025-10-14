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
          citations: hardcodedResponse.citations.map((c: any) => ({ id: c.id, text: c.text_snippet }))
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
              {sampleQuestions.map((question, idx) => (
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