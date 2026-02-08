'use client';

/**
 * Settings Page
 * 
 * Configure API connections, agent settings, and system preferences
 * for the AI Security Auditor.
 * 
 * @module app/settings/page
 */

import React, { useState } from 'react';
import {
  Settings,
  Server,
  Shield,
  Zap,
  Bell,
  Key,
  Database,
  RefreshCw,
  CheckCircle,
  AlertCircle,
  ExternalLink,
  Save,
  RotateCcw,
} from 'lucide-react';
import { DashboardShell, DashboardCard } from '@/components/dashboard/dashboard-shell';
import { Badge } from '@/components/ui/badge';
import { useHealth } from '@/hooks';
import { cn } from '@/lib/utils';

// Settings sections configuration
interface SettingItem {
  id: string;
  label: string;
  description: string;
  type: 'text' | 'toggle' | 'select' | 'number';
  value: string | boolean | number;
  options?: { label: string; value: string }[];
}

interface SettingSection {
  id: string;
  title: string;
  description: string;
  icon: typeof Settings;
  settings: SettingItem[];
}

const SETTINGS_SECTIONS: SettingSection[] = [
  {
    id: 'api',
    title: 'API Configuration',
    description: 'Configure backend API connection settings',
    icon: Server,
    settings: [
      {
        id: 'api_url',
        label: 'API Base URL',
        description: 'Base URL for the FastAPI backend',
        type: 'text',
        value: 'http://localhost:8000',
      },
      {
        id: 'api_timeout',
        label: 'Request Timeout (ms)',
        description: 'Maximum time to wait for API responses',
        type: 'number',
        value: 30000,
      },
      {
        id: 'ws_enabled',
        label: 'WebSocket Updates',
        description: 'Enable real-time updates via WebSocket',
        type: 'toggle',
        value: true,
      },
    ],
  },
  {
    id: 'agents',
    title: 'Agent Settings',
    description: 'Configure security agent behavior',
    icon: Shield,
    settings: [
      {
        id: 'default_framework',
        label: 'Default Framework',
        description: 'Default compliance framework for new audits',
        type: 'select',
        value: 'soc2',
        options: [
          { label: 'SOC 2', value: 'soc2' },
          { label: 'GDPR', value: 'gdpr' },
          { label: 'HIPAA', value: 'hipaa' },
          { label: 'NIST 800-53A', value: 'nist_800_53a' },
        ],
      },
      {
        id: 'use_llm',
        label: 'Enable LLM Analysis',
        description: 'Use AI for enhanced analysis (defaults to conservative mode)',
        type: 'toggle',
        value: false,
      },
      {
        id: 'confidence_threshold',
        label: 'Confidence Threshold',
        description: 'Minimum confidence for automatic assessments',
        type: 'select',
        value: '0.85',
        options: [
          { label: '70%', value: '0.70' },
          { label: '80%', value: '0.80' },
          { label: '85%', value: '0.85' },
          { label: '90%', value: '0.90' },
          { label: '95%', value: '0.95' },
        ],
      },
    ],
  },
  {
    id: 'anti_hallucination',
    title: 'Anti-Hallucination Rules',
    description: 'Configure evidence validation settings',
    icon: Zap,
    settings: [
      {
        id: 'require_evidence',
        label: 'Require Evidence',
        description: 'All claims must cite specific evidence artifacts',
        type: 'toggle',
        value: true,
      },
      {
        id: 'block_weasel_words',
        label: 'Block Weasel Words',
        description: 'Reject responses with hedging language',
        type: 'toggle',
        value: true,
      },
      {
        id: 'evidence_freshness_days',
        label: 'Evidence Freshness (days)',
        description: 'Maximum age for evidence before freshness penalty',
        type: 'number',
        value: 90,
      },
    ],
  },
  {
    id: 'notifications',
    title: 'Notifications',
    description: 'Configure alert and notification preferences',
    icon: Bell,
    settings: [
      {
        id: 'notify_critical',
        label: 'Critical Findings',
        description: 'Alert when critical findings are discovered',
        type: 'toggle',
        value: true,
      },
      {
        id: 'notify_completion',
        label: 'Audit Completion',
        description: 'Notify when audits complete',
        type: 'toggle',
        value: true,
      },
      {
        id: 'notify_errors',
        label: 'Error Alerts',
        description: 'Alert on agent errors',
        type: 'toggle',
        value: true,
      },
    ],
  },
];

export default function SettingsPage() {
  const { data: health, isLoading: healthLoading } = useHealth();
  const [settings, setSettings] = useState<Record<string, string | boolean | number>>(() => {
    // Initialize with default values
    const initial: Record<string, string | boolean | number> = {};
    SETTINGS_SECTIONS.forEach(section => {
      section.settings.forEach(setting => {
        initial[setting.id] = setting.value;
      });
    });
    return initial;
  });
  const [hasChanges, setHasChanges] = useState(false);

  const updateSetting = (id: string, value: string | boolean | number) => {
    setSettings(prev => ({ ...prev, [id]: value }));
    setHasChanges(true);
  };

  const handleSave = () => {
    // In a real app, this would save to backend/localStorage
    console.log('Saving settings:', settings);
    setHasChanges(false);
  };

  const handleReset = () => {
    const initial: Record<string, string | boolean | number> = {};
    SETTINGS_SECTIONS.forEach(section => {
      section.settings.forEach(setting => {
        initial[setting.id] = setting.value;
      });
    });
    setSettings(initial);
    setHasChanges(false);
  };

  return (
    <DashboardShell>
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center gap-3">
          <Settings className="h-8 w-8 text-gray-400" />
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
            <p className="text-gray-500">Configure system preferences and agent behavior</p>
          </div>
        </div>
        
        <div className="flex items-center gap-3">
          {hasChanges && (
            <Badge variant="warning">Unsaved Changes</Badge>
          )}
          <button
            onClick={handleReset}
            className="btn btn-outline flex items-center gap-2"
            disabled={!hasChanges}
          >
            <RotateCcw className="h-4 w-4" />
            Reset
          </button>
          <button
            onClick={handleSave}
            className="btn btn-primary flex items-center gap-2"
            disabled={!hasChanges}
          >
            <Save className="h-4 w-4" />
            Save Changes
          </button>
        </div>
      </div>

      {/* Connection Status */}
      <DashboardCard className="mb-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className={cn(
              "p-3 rounded-lg",
              health?.status === 'healthy' ? 'bg-green-100' : 'bg-red-100'
            )}>
              <Server className={cn(
                "h-6 w-6",
                health?.status === 'healthy' ? 'text-green-600' : 'text-red-600'
              )} />
            </div>
            <div>
              <h3 className="font-medium text-gray-900">Backend Connection</h3>
              <p className="text-sm text-gray-500">
                {healthLoading ? 'Checking connection...' : 
                 health?.status === 'healthy' ? 'Connected to API' : 'Connection failed'}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {health?.status === 'healthy' ? (
              <Badge variant="success" className="flex items-center gap-1">
                <CheckCircle className="h-3 w-3" />
                Healthy
              </Badge>
            ) : (
              <Badge variant="error" className="flex items-center gap-1">
                <AlertCircle className="h-3 w-3" />
                Disconnected
              </Badge>
            )}
            <a
              href="http://localhost:8000/api/docs"
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm text-blue-600 hover:text-blue-800 flex items-center gap-1"
            >
              API Docs <ExternalLink className="h-3 w-3" />
            </a>
          </div>
        </div>
      </DashboardCard>

      {/* Settings Sections */}
      <div className="space-y-6">
        {SETTINGS_SECTIONS.map(section => (
          <DashboardCard key={section.id}>
            <div className="flex items-start gap-4 mb-6">
              <div className="p-2 bg-gray-100 rounded-lg">
                <section.icon className="h-5 w-5 text-gray-600" />
              </div>
              <div>
                <h3 className="font-medium text-gray-900">{section.title}</h3>
                <p className="text-sm text-gray-500">{section.description}</p>
              </div>
            </div>

            <div className="space-y-4">
              {section.settings.map(setting => (
                <div
                  key={setting.id}
                  className="flex items-center justify-between py-3 border-b border-gray-100 last:border-0"
                >
                  <div className="flex-1">
                    <label
                      htmlFor={setting.id}
                      className="block font-medium text-gray-700"
                    >
                      {setting.label}
                    </label>
                    <p className="text-sm text-gray-500">{setting.description}</p>
                  </div>

                  <div className="ml-4">
                    {setting.type === 'toggle' && (
                      <button
                        type="button"
                        role="switch"
                        aria-checked={settings[setting.id] as boolean}
                        onClick={() => updateSetting(setting.id, !settings[setting.id])}
                        className={cn(
                          "relative inline-flex h-6 w-11 items-center rounded-full transition-colors",
                          settings[setting.id] ? 'bg-green-600' : 'bg-gray-300'
                        )}
                      >
                        <span
                          className={cn(
                            "inline-block h-4 w-4 transform rounded-full bg-white transition-transform",
                            settings[setting.id] ? 'translate-x-6' : 'translate-x-1'
                          )}
                        />
                      </button>
                    )}

                    {setting.type === 'text' && (
                      <input
                        id={setting.id}
                        type="text"
                        value={settings[setting.id] as string}
                        onChange={e => updateSetting(setting.id, e.target.value)}
                        className="input w-64"
                      />
                    )}

                    {setting.type === 'number' && (
                      <input
                        id={setting.id}
                        type="number"
                        value={settings[setting.id] as number}
                        onChange={e => updateSetting(setting.id, parseInt(e.target.value))}
                        className="input w-32"
                      />
                    )}

                    {setting.type === 'select' && (
                      <select
                        id={setting.id}
                        value={settings[setting.id] as string}
                        onChange={e => updateSetting(setting.id, e.target.value)}
                        className="select w-40"
                      >
                        {setting.options?.map(option => (
                          <option key={option.value} value={option.value}>
                            {option.label}
                          </option>
                        ))}
                      </select>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </DashboardCard>
        ))}
      </div>

      {/* Valid Assessment States Reference */}
      <DashboardCard className="mt-6">
        <div className="flex items-start gap-4 mb-4">
          <div className="p-2 bg-gray-100 rounded-lg">
            <Key className="h-5 w-5 text-gray-600" />
          </div>
          <div>
            <h3 className="font-medium text-gray-900">Valid Assessment States</h3>
            <p className="text-sm text-gray-500">
              Anti-hallucination enforced - only these states are valid
            </p>
          </div>
        </div>

        <div className="flex flex-wrap gap-2">
          <Badge variant="success">PASS</Badge>
          <Badge variant="error">FAIL</Badge>
          <Badge variant="warning">INSUFFICIENT_EVIDENCE</Badge>
          <Badge className="bg-orange-100 text-orange-800">EVIDENCE_GAP</Badge>
          <Badge className="bg-purple-100 text-purple-800">CONFLICTING_EVIDENCE</Badge>
          <Badge className="bg-blue-100 text-blue-800">NEEDS_MANUAL_REVIEW</Badge>
        </div>

        <p className="mt-4 text-sm text-gray-500">
          No hallucinated &quot;likely compliant&quot; or &quot;probably fine&quot; assessments allowed.
          If you can&apos;t prove it, you can&apos;t claim it.
        </p>
      </DashboardCard>
    </DashboardShell>
  );
}
