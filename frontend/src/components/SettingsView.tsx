import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Switch } from "./ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./ui/select";
import { Separator } from "./ui/separator";
import { Badge } from "./ui/badge";
import { 
  Save, 
  Shield, 
  Bell, 
  Palette, 
  Database, 
  Key, 
  Globe,
  Mail,
  Lock,
  User
} from "lucide-react";
import { toast } from "sonner";
import { mockData } from "../services/mockData";

export function SettingsView() {
  const [saving, setSaving] = useState(false);
  
  // Form states initialized with mock data
  const [generalSettings, setGeneralSettings] = useState(mockData.settings.general);
  const [securitySettings, setSecuritySettings] = useState(mockData.settings.security);
  const [notificationSettings, setNotificationSettings] = useState(mockData.settings.notifications);
  const [scanSettings, setScanSettings] = useState(mockData.settings.scan);

  const handleSave = () => {
    setSaving(true);
    // Simulate saving
    setTimeout(() => {
      setSaving(false);
      toast.success("Settings saved successfully");
    }, 1000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold">Settings</h1>
        <p className="text-muted-foreground">Manage your dashboard preferences and configurations</p>
      </div>

      {/* General Settings */}
      <Card className="glass-card enhanced-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <User className="w-5 h-5" />
            General Settings
          </CardTitle>
          <CardDescription>Configure basic dashboard settings</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-2">
              <Label htmlFor="companyName">Company Name</Label>
              <Input
                id="companyName"
                value={generalSettings.companyName}
                onChange={(e) => setGeneralSettings({...generalSettings, companyName: e.target.value})}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="timezone">Timezone</Label>
              <Select 
                value={generalSettings.timezone}
                onValueChange={(value) => setGeneralSettings({...generalSettings, timezone: value})}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="UTC-12:00">UTC-12:00</SelectItem>
                  <SelectItem value="UTC-08:00">UTC-08:00</SelectItem>
                  <SelectItem value="UTC-05:00">UTC-05:00</SelectItem>
                  <SelectItem value="UTC+00:00">UTC+00:00</SelectItem>
                  <SelectItem value="UTC+01:00">UTC+01:00</SelectItem>
                  <SelectItem value="UTC+05:30">UTC+05:30</SelectItem>
                  <SelectItem value="UTC+08:00">UTC+08:00</SelectItem>
                  <SelectItem value="UTC+09:00">UTC+09:00</SelectItem>
                  <SelectItem value="UTC+10:00">UTC+10:00</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="language">Language</Label>
              <Select 
                value={generalSettings.language}
                onValueChange={(value) => setGeneralSettings({...generalSettings, language: value})}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="en">English</SelectItem>
                  <SelectItem value="es">Spanish</SelectItem>
                  <SelectItem value="fr">French</SelectItem>
                  <SelectItem value="de">German</SelectItem>
                  <SelectItem value="ja">Japanese</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="theme">Theme</Label>
              <Select 
                value={generalSettings.theme}
                onValueChange={(value) => setGeneralSettings({...generalSettings, theme: value})}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="light">Light</SelectItem>
                  <SelectItem value="dark">Dark</SelectItem>
                  <SelectItem value="system">System</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      <Separator className="my-6" />

      {/* Security Settings */}
      <Card className="glass-card enhanced-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Lock className="w-5 h-5" />
            Security Settings
          </CardTitle>
          <CardDescription>Configure authentication and security policies</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <Label>Two-Factor Authentication</Label>
              <p className="text-sm text-muted-foreground">Require 2FA for all users</p>
            </div>
            <Switch
              checked={securitySettings.twoFactorAuth}
              onCheckedChange={(checked) => setSecuritySettings({...securitySettings, twoFactorAuth: checked})}
            />
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-2">
              <Label htmlFor="passwordExpiry">Password Expiry (days)</Label>
              <Input
                id="passwordExpiry"
                type="number"
                value={securitySettings.passwordExpiry}
                onChange={(e) => setSecuritySettings({...securitySettings, passwordExpiry: parseInt(e.target.value) || 0})}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="sessionTimeout">Session Timeout (minutes)</Label>
              <Input
                id="sessionTimeout"
                type="number"
                value={securitySettings.sessionTimeout}
                onChange={(e) => setSecuritySettings({...securitySettings, sessionTimeout: parseInt(e.target.value) || 0})}
              />
            </div>
          </div>
          
          <div className="space-y-2">
            <Label htmlFor="ipWhitelist">IP Whitelist</Label>
            <Input
              id="ipWhitelist"
              value={securitySettings.ipWhitelist}
              onChange={(e) => setSecuritySettings({...securitySettings, ipWhitelist: e.target.value})}
              placeholder="Enter comma-separated IP ranges"
            />
          </div>
        </CardContent>
      </Card>

      <Separator className="my-6" />

      {/* Notification Settings */}
      <Card className="glass-card enhanced-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bell className="w-5 h-5" />
            Notification Settings
          </CardTitle>
          <CardDescription>Configure how you receive alerts and reports</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <Label>Email Alerts</Label>
              <p className="text-sm text-muted-foreground">Receive security alerts via email</p>
            </div>
            <Switch
              checked={notificationSettings.emailAlerts}
              onCheckedChange={(checked) => setNotificationSettings({...notificationSettings, emailAlerts: checked})}
            />
          </div>
          
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <Label>Slack Notifications</Label>
              <p className="text-sm text-muted-foreground">Send notifications to Slack</p>
            </div>
            <Switch
              checked={notificationSettings.slackNotifications}
              onCheckedChange={(checked) => setNotificationSettings({...notificationSettings, slackNotifications: checked})}
            />
          </div>
          
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <Label>Critical Alerts</Label>
              <p className="text-sm text-muted-foreground">Receive immediate alerts for critical issues</p>
            </div>
            <Switch
              checked={notificationSettings.criticalAlerts}
              onCheckedChange={(checked) => setNotificationSettings({...notificationSettings, criticalAlerts: checked})}
            />
          </div>
          
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <Label>Weekly Reports</Label>
              <p className="text-sm text-muted-foreground">Receive weekly security summaries</p>
            </div>
            <Switch
              checked={notificationSettings.weeklyReports}
              onCheckedChange={(checked) => setNotificationSettings({...notificationSettings, weeklyReports: checked})}
            />
          </div>
        </CardContent>
      </Card>

      <Separator className="my-6" />

      {/* Scan Settings */}
      <Card className="glass-card enhanced-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="w-5 h-5" />
            Scan Settings
          </CardTitle>
          <CardDescription>Configure automated scanning preferences</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <Label>Automatic Scanning</Label>
              <p className="text-sm text-muted-foreground">Run scans automatically on schedule</p>
            </div>
            <Switch
              checked={scanSettings.autoScan}
              onCheckedChange={(checked) => setScanSettings({...scanSettings, autoScan: checked})}
            />
          </div>
          
          <div className="space-y-2">
            <Label htmlFor="scanSchedule">Scan Schedule</Label>
            <Select 
              value={scanSettings.scanSchedule}
              onValueChange={(value) => setScanSettings({...scanSettings, scanSchedule: value})}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="hourly">Hourly</SelectItem>
                <SelectItem value="daily">Daily</SelectItem>
                <SelectItem value="weekly">Weekly</SelectItem>
                <SelectItem value="monthly">Monthly</SelectItem>
              </SelectContent>
            </Select>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-2">
              <Label htmlFor="concurrentScans">Concurrent Scans</Label>
              <Input
                id="concurrentScans"
                type="number"
                value={scanSettings.concurrentScans}
                onChange={(e) => setScanSettings({...scanSettings, concurrentScans: parseInt(e.target.value) || 1})}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="scanTimeout">Scan Timeout (seconds)</Label>
              <Input
                id="scanTimeout"
                type="number"
                value={scanSettings.scanTimeout}
                onChange={(e) => setScanSettings({...scanSettings, scanTimeout: parseInt(e.target.value) || 3600})}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Save Button */}
      <div className="flex justify-end">
        <Button 
          onClick={handleSave}
          disabled={saving}
          className="flex items-center gap-2"
        >
          <Save className={`w-4 h-4 ${saving ? 'animate-spin' : ''}`} />
          {saving ? 'Saving...' : 'Save Settings'}
        </Button>
      </div>
    </div>
  );
}