import { useState, useEffect } from "react";
import { motion } from "motion/react";
import { Shield, Lock, Mail, ArrowRight, Zap, Network, Globe, Server, Cpu, Database } from "lucide-react";
import { Input } from "./ui/input";
import { Button } from "./ui/button";
import { Label } from "./ui/label";
import { toast } from "sonner";
import { authService, LoginRequest } from "../services/authService";

interface LoginPageProps {
  onLogin: () => void;
}

interface Particle {
  id: number;
  x: number;
  y: number;
  size: number;
  delay: number;
}

interface OrbitNode {
  id: number;
  angle: number;
  radius: number;
  size: number;
}

export function LoginPage({ onLogin }: LoginPageProps) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [particles, setParticles] = useState([] as Particle[]);
  const [orbitNodes, setOrbitNodes] = useState([] as OrbitNode[]);

  useEffect(() => {
    // Generate particles
    const newParticles = Array.from({ length: 50 }, (_, i) => ({
      id: i,
      x: Math.random() * 100,
      y: Math.random() * 100,
      size: Math.random() * 3 + 1,
      delay: Math.random() * 8
    }));
    setParticles(newParticles);

    // Generate orbit nodes for 3D globe effect
    const nodes = Array.from({ length: 12 }, (_, i) => ({
      id: i,
      angle: (i * 360) / 12,
      radius: 150 + Math.random() * 50,
      size: Math.random() * 8 + 4
    }));
    setOrbitNodes(nodes);
  }, []);

  const handleSubmit = async (e: any) => {
    e.preventDefault();
    if (!email || !password) {
      toast.error("Please enter both email and password");
      return;
    }

    setIsLoading(true);
    try {
      const credentials: LoginRequest = { email, password };
      const success = await authService.login(credentials);
      
      if (success) {
        toast.success("Login successful", {
          description: "Welcome to Cyber Rakshak"
        });
        onLogin();
      } else {
        toast.error("Login failed", {
          description: "Invalid credentials. Please try again."
        });
      }
    } catch (error) {
      toast.error("Login error", {
        description: "An error occurred during login. Please try again."
      });
      console.error("Login error:", error);
    } finally {
      setIsLoading(false);
    }
  };

  const floatingIcons = [
    { Icon: Shield, delay: 0, position: { top: "15%", left: "8%" }, color: "text-cyan-400" },
    { Icon: Lock, delay: 1, position: { top: "25%", right: "10%" }, color: "text-purple-400" },
    { Icon: Zap, delay: 2, position: { top: "65%", left: "5%" }, color: "text-yellow-400" },
    { Icon: Network, delay: 1.5, position: { bottom: "20%", right: "8%" }, color: "text-teal-400" },
    { Icon: Globe, delay: 0.5, position: { top: "45%", right: "12%" }, color: "text-blue-400" },
    { Icon: Server, delay: 2.5, position: { bottom: "30%", left: "10%" }, color: "text-magenta-400" },
    { Icon: Cpu, delay: 1.8, position: { top: "35%", left: "7%" }, color: "text-cyan-300" },
    { Icon: Database, delay: 2.2, position: { bottom: "40%", right: "15%" }, color: "text-purple-300" }
  ];

  return (
    <div className="relative min-h-screen w-full overflow-hidden cinematic-bg">
      {/* Animated Grid Background */}
      <div className="absolute inset-0 cyber-grid opacity-20"></div>

      {/* Multi-toned Gradient Orbs */}
      <div className="absolute top-0 left-1/4 w-[600px] h-[600px] bg-gradient-radial from-purple-600/20 via-purple-500/10 to-transparent rounded-full blur-[140px] animate-pulse"></div>
      <div className="absolute bottom-0 right-1/4 w-[700px] h-[700px] bg-gradient-radial from-cyan-500/20 via-teal-500/10 to-transparent rounded-full blur-[140px] animate-pulse" style={{ animationDelay: "1s" }}></div>
      <div className="absolute top-1/3 right-1/3 w-[500px] h-[500px] bg-gradient-radial from-magenta-500/15 via-blue-500/8 to-transparent rounded-full blur-[120px] animate-pulse" style={{ animationDelay: "2s" }}></div>
      <div className="absolute bottom-1/4 left-1/3 w-[550px] h-[550px] bg-gradient-radial from-teal-500/18 via-cyan-500/8 to-transparent rounded-full blur-[130px] animate-pulse" style={{ animationDelay: "3s" }}></div>

      {/* Floating Particles */}
      {particles.map((particle) => (
        <motion.div
          key={particle.id}
          className="particle"
          style={{
            left: `${particle.x}%`,
            top: `${particle.y}%`,
            width: `${particle.size}px`,
            height: `${particle.size}px`,
            background: `radial-gradient(circle, rgba(0, 217, 255, 0.8) 0%, transparent 70%)`
          }}
          animate={{
            y: [0, -40, 0],
            x: [0, 20, 0],
            opacity: [0.2, 1, 0.2],
            scale: [1, 1.2, 1]
          }}
          transition={{
            duration: 8,
            repeat: Infinity,
            delay: particle.delay,
            ease: "easeInOut"
          }}
        />
      ))}

      {/* 3D Network Globe Effect */}
      <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-[400px] h-[400px] globe-container opacity-30">
        <motion.div
          className="relative w-full h-full"
          animate={{ rotate: 360 }}
          transition={{ duration: 60, repeat: Infinity, ease: "linear" }}
        >
          {orbitNodes.map((node) => (
            <motion.div
              key={node.id}
              className="absolute top-1/2 left-1/2 w-2 h-2 rounded-full bg-gradient-to-r from-cyan-400 to-purple-400 shadow-lg"
              style={{
                transform: `rotate(${node.angle}deg) translateX(${node.radius}px)`,
                width: `${node.size}px`,
                height: `${node.size}px`,
                boxShadow: `0 0 ${node.size * 2}px rgba(0, 217, 255, 0.6)`
              }}
              animate={{
                scale: [1, 1.3, 1],
                opacity: [0.5, 1, 0.5]
              }}
              transition={{
                duration: 3,
                repeat: Infinity,
                delay: node.id * 0.2
              }}
            />
          ))}
          
          {/* Connection Lines */}
          {orbitNodes.map((node, i) => (
            <svg key={`line-${i}`} className="absolute inset-0 w-full h-full" style={{ overflow: "visible" }}>
              <motion.line
                x1="50%"
                y1="50%"
                x2={`calc(50% + ${Math.cos((node.angle * Math.PI) / 180) * node.radius}px)`}
                y2={`calc(50% + ${Math.sin((node.angle * Math.PI) / 180) * node.radius}px)`}
                stroke="url(#gradient)"
                strokeWidth="1"
                opacity="0.3"
                initial={{ pathLength: 0 }}
                animate={{ pathLength: 1 }}
                transition={{ duration: 2, delay: i * 0.1 }}
              />
              <defs>
                <linearGradient id="gradient" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#00d9ff" stopOpacity="0.8" />
                  <stop offset="100%" stopColor="#a855f7" stopOpacity="0.4" />
                </linearGradient>
              </defs>
            </svg>
          ))}
        </motion.div>
      </div>

      {/* Floating Tech Icons */}
      {floatingIcons.map(({ Icon, delay, position, color }, index) => (
        <motion.div
          key={index}
          className={`absolute opacity-20 ${color}`}
          style={position}
          animate={{
            y: [0, -25, 0],
            rotate: [0, 10, 0],
            scale: [1, 1.1, 1]
          }}
          transition={{
            duration: 7,
            repeat: Infinity,
            delay: delay,
            ease: "easeInOut"
          }}
        >
          <Icon className="w-14 h-14 drop-shadow-lg" />
        </motion.div>
      ))}

      {/* Main Content */}
      <div className="relative z-10 flex min-h-screen items-center justify-center p-4">
        <div className="w-full max-w-7xl grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
          {/* Left Side - Branding with Scrollytelling */}
          <motion.div
            initial={{ opacity: 0, x: -60 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 1, ease: "easeOut" }}
            className="space-y-10 text-center lg:text-left"
          >
            <motion.div
              className="inline-flex items-center gap-5"
              whileHover={{ scale: 1.02 }}
              transition={{ duration: 0.3 }}
            >
              <div className="relative globe-container">
                <div className="absolute inset-0 bg-gradient-to-br from-cyan-400 via-teal-500 to-purple-600 rounded-3xl blur-2xl opacity-70 animate-pulse"></div>
                <motion.div 
                  className="relative w-24 h-24 rounded-3xl bg-gradient-to-br from-cyan-400 via-teal-500 to-purple-600 flex items-center justify-center shadow-2xl"
                  animate={{ 
                    rotateY: [0, 360],
                    boxShadow: [
                      "0 0 40px rgba(0, 217, 255, 0.5)",
                      "0 0 80px rgba(168, 85, 247, 0.5)",
                      "0 0 40px rgba(0, 217, 255, 0.5)"
                    ]
                  }}
                  transition={{ 
                    rotateY: { duration: 4, repeat: Infinity, ease: "linear" },
                    boxShadow: { duration: 3, repeat: Infinity }
                  }}
                >
                  <Shield className="w-14 h-14 text-white drop-shadow-2xl" />
                </motion.div>
              </div>
              <div>
                <motion.h1 
                  className="text-5xl lg:text-6xl font-bold bg-gradient-to-r from-cyan-400 via-teal-400 to-purple-400 bg-clip-text text-transparent drop-shadow-lg"
                  animate={{
                    backgroundPosition: ["0% 50%", "100% 50%", "0% 50%"]
                  }}
                  transition={{ duration: 5, repeat: Infinity }}
                  style={{ backgroundSize: "200% auto" }}
                >
                  Cyber Rakshak
                </motion.h1>
                <p className="text-sm text-cyan-400 mt-2 font-medium">AI-Powered Security Platform</p>
              </div>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3, duration: 1 }}
              className="space-y-6"
            >
              <h2 className="text-4xl lg:text-5xl font-bold leading-tight">
                <span className="text-foreground">AI-Powered Cyber</span>{" "}
                <span className="bg-gradient-to-r from-cyan-400 via-teal-400 to-purple-400 bg-clip-text text-transparent">
                  Threat Analysis
                </span>{" "}
                <span className="text-foreground">&</span>{" "}
                <span className="bg-gradient-to-r from-purple-400 via-magenta-400 to-pink-400 bg-clip-text text-transparent">
                  Protection
                </span>
              </h2>
              <p className="text-xl text-muted-foreground max-w-2xl leading-relaxed">
                Next-generation security operations center with real-time threat detection,
                automated vulnerability scanning, intelligent attack path analysis, and AI-driven remediation.
              </p>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.6, duration: 1 }}
              className="grid grid-cols-2 gap-6 max-w-2xl mx-auto lg:mx-0"
            >
              {[
                { label: "24/7 Monitoring", value: "Real-time", gradient: "from-cyan-400 to-blue-400" },
                { label: "AI Detection", value: "99.8%", gradient: "from-purple-400 to-magenta-400" },
                { label: "Response Time", value: "< 30s", gradient: "from-teal-400 to-cyan-400" },
                { label: "Threat Score", value: "Elite", gradient: "from-yellow-400 to-orange-400" }
              ].map((stat, index) => (
                <motion.div
                  key={index}
                  className="holographic-card p-6 rounded-2xl text-center backdrop-blur-xl hover:scale-105 transition-all cursor-pointer"
                  whileHover={{ y: -5 }}
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: 0.7 + index * 0.1, duration: 0.5 }}
                >
                  <p className="text-xs text-muted-foreground mb-2 uppercase tracking-wider">{stat.label}</p>
                  <p className={`text-2xl font-bold bg-gradient-to-r ${stat.gradient} bg-clip-text text-transparent`}>
                    {stat.value}
                  </p>
                </motion.div>
              ))}
            </motion.div>

            {/* Security Badges */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 1, duration: 1 }}
              className="flex gap-4 justify-center lg:justify-start flex-wrap"
            >
              {["ISO 27001", "SOC 2 Type II", "GDPR Compliant", "Zero Trust"].map((badge, i) => (
                <div
                  key={i}
                  className="px-4 py-2 rounded-full bg-gradient-to-r from-cyan-500/10 to-purple-500/10 border border-cyan-500/30 text-sm text-cyan-400"
                >
                  {badge}
                </div>
              ))}
            </motion.div>
          </motion.div>

          {/* Right Side - Login Form */}
          <motion.div
            initial={{ opacity: 0, x: 60 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 1, ease: "easeOut" }}
            className="relative"
          >
            {/* Ambient Glow Background */}
            <div className="absolute inset-0 bg-gradient-to-br from-cyan-500/15 via-purple-500/10 to-magenta-500/15 rounded-[2rem] blur-3xl"></div>
            
            <div className="relative glass-card p-10 md:p-14 rounded-[2rem] border-2 floating-3d-card">
              {/* Holographic Overlay */}
              <div className="absolute inset-0 bg-gradient-to-br from-cyan-400/5 via-transparent to-purple-400/5 rounded-[2rem] pointer-events-none"></div>
              
              {/* Scan Line Effect */}
              <div className="scan-line"></div>

              <motion.div
                initial={{ opacity: 0, y: 30 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.4, duration: 0.8 }}
              >
                <div className="mb-10">
                  <h3 className="text-3xl lg:text-4xl font-bold mb-3 bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
                    Welcome Back
                  </h3>
                  <p className="text-muted-foreground text-lg">Sign in to access your security command center</p>
                  
                  {/* Demo Credentials Banner */}
                  <div className="mt-6 p-5 rounded-xl bg-gradient-to-r from-cyan-500/10 via-teal-500/10 to-purple-500/10 border border-cyan-500/30 backdrop-blur-sm">
                    <p className="text-sm text-cyan-400 font-semibold mb-3 flex items-center gap-2">
                      🔓 Demo Access Credentials
                    </p>
                    <div className="space-y-2 text-sm text-muted-foreground">
                      <p>Email: <span className="text-cyan-400 font-mono font-semibold">admin@cyberrakshak.ai</span></p>
                      <p>Password: <span className="text-cyan-400 font-mono font-semibold">demo123</span></p>
                      <p className="text-xs mt-3 opacity-80">Or use any valid email and password to access the demo</p>
                    </div>
                  </div>
                </div>

                <form onSubmit={handleSubmit} className="space-y-7">
                  <motion.div
                    className="space-y-3"
                    whileFocus={{ scale: 1.01 }}
                    transition={{ duration: 0.2 }}
                  >
                    <Label htmlFor="email" className="text-sm font-medium">Business Email</Label>
                    <div className="relative group">
                      <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/30 via-teal-500/20 to-blue-500/30 rounded-xl blur-md opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 transition-opacity duration-300"></div>
                      <div className="relative flex items-center">
                        <Mail className="absolute left-5 w-5 h-5 text-muted-foreground group-focus-within:text-cyan-400 transition-colors duration-300" />
                        <Input
                          id="email"
                          type="email"
                          placeholder="you@company.com"
                          value={email}
                          onChange={(e) => setEmail(e.target.value)}
                          className="pl-14 h-16 bg-background/60 border-border/60 focus:border-cyan-500/60 focus:ring-4 focus:ring-cyan-500/20 transition-all rounded-xl text-lg backdrop-blur-sm"
                          required
                        />
                      </div>
                    </div>
                  </motion.div>

                  <motion.div
                    className="space-y-3"
                    whileFocus={{ scale: 1.01 }}
                    transition={{ duration: 0.2 }}
                  >
                    <Label htmlFor="password" className="text-sm font-medium">Password</Label>
                    <div className="relative group">
                      <div className="absolute inset-0 bg-gradient-to-r from-purple-500/30 via-magenta-500/20 to-pink-500/30 rounded-xl blur-md opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 transition-opacity duration-300"></div>
                      <div className="relative flex items-center">
                        <Lock className="absolute left-5 w-5 h-5 text-muted-foreground group-focus-within:text-purple-400 transition-colors duration-300" />
                        <Input
                          id="password"
                          type="password"
                          placeholder="••••••••"
                          value={password}
                          onChange={(e) => setPassword(e.target.value)}
                          className="pl-14 h-16 bg-background/60 border-border/60 focus:border-purple-500/60 focus:ring-4 focus:ring-purple-500/20 transition-all rounded-xl text-lg backdrop-blur-sm"
                          required
                        />
                      </div>
                    </div>
                  </motion.div>

                  <div className="flex items-center justify-end text-sm">
                    <a href="#" className="text-cyan-400 hover:text-cyan-300 transition-colors font-medium">
                      Forgot password?
                    </a>
                  </div>

                  <motion.div 
                    whileHover={{ scale: 1.02 }} 
                    whileTap={{ scale: 0.98 }}
                  >
                    <Button
                      type="submit"
                      className="w-full h-16 bg-gradient-to-r from-cyan-500 via-teal-500 to-blue-600 hover:from-cyan-400 hover:via-teal-400 hover:to-blue-500 text-white font-semibold rounded-xl pulse-glow-button group relative overflow-hidden text-lg shadow-2xl"
                    >
                      <span className="relative z-10 flex items-center justify-center gap-3">
                        Sign In to Command Center
                        <ArrowRight className="w-6 h-6 group-hover:translate-x-2 transition-transform duration-300" />
                      </span>
                      <div className="absolute inset-0 bg-gradient-to-r from-cyan-400 via-teal-400 to-blue-500 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                    </Button>
                  </motion.div>
                </form>

                <div className="mt-10 pt-8 border-t border-border/40">
                  <p className="text-center text-sm text-muted-foreground">
                    Don't have an account?{" "}
                    <a href="#" className="text-cyan-400 hover:text-cyan-300 transition-colors font-semibold">
                      Request Access
                    </a>
                  </p>
                </div>

                <div className="mt-6 flex items-center justify-center gap-6 text-xs text-muted-foreground">
                  <a href="#" className="hover:text-cyan-400 transition-colors">Privacy Policy</a>
                  <span className="text-border">•</span>
                  <a href="#" className="hover:text-cyan-400 transition-colors">Terms of Service</a>
                  <span className="text-border">•</span>
                  <a href="#" className="hover:text-cyan-400 transition-colors">Security</a>
                </div>
              </motion.div>
            </div>
          </motion.div>
        </div>
      </div>

      {/* Bottom Accent Lines */}
      <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-transparent via-cyan-500 to-transparent opacity-60"></div>
      <div className="absolute bottom-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-purple-500 to-transparent opacity-40" style={{ bottom: "2px" }}></div>
    </div>
  );
}
