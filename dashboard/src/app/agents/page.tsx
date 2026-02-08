'use client';

/**
 * Agents Page
 * 
 * Monitor and manage the 4 security agents with detailed status,
 * performance metrics, and configuration options.
 * 
 * @module app/agents/page
 */

import React, { useState, useMemo } from 'react';
import {
  Activity,
  Scan,
  Code,
  FileText,
  CheckSquare,
  RefreshCw,
  Settings,
  Play,
  Pause,
  AlertCircle,
  CheckCircle,
  Clock,
  Zap,
  TrendingUp,
  XCircle,
  Loader2,
} from 'lucide-react';
import { DashboardShell, DashboardCard } from '@/components/dashboard/dashboard-shell';
import { Badge, AgentStatusBadge } from '@/components/ui/badge';
import { ProgressBar } from '@/components/dashboard/progress-bar';
import { StatCard } from '@/components/dashboard/stat-card';
import { useAudits, useAgentStatuses, useAgentStatus } from '@/hooks';
import { cn, formatDuration } from '@/lib/utils';
import { AgentType, AgentStatus, AuditStatus } from '@/types';
import type { AgentStatusResponse } from '@/types';

// Agent configuration
const AGENTS_CONFIG: Record<AgentType, {
  icon: typeof Scan;
  name: string;
  description: string;
  capabilities: string[];
  techStack: string[];
}> = {
  [AgentType.VULNERABILITY_SCANNER]: {
    icon: Scan,
    name: 'Vulnerability Scanner',
    description: 'OWASP ZAP integration for automated web vulnerability scanning',
    capabilities: [
      'Active & Passive Scanning',
      'OWASP Top 10 Detection',
      'SQL Injection Testing',
      'XSS Detection',
      'CSRF Detection',
    ],
    techStack: ['OWASP ZAP API', 'Python zap-api', 'Custom Rules'],
  },
  [AgentType.CODE_ANALYZER]: {
    icon: Code,
    name: 'Code Security Analyzer',
    description: 'Static analysis for security vulnerabilities in source code',
    capabilities: [
      'SAST Analysis',
      'Secret Detection',
      'Dependency Scanning',
      'OWASP Compliance',
      'CWE Mapping',
    ],
    techStack: ['Semgrep', 'Bandit', 'Custom Rules'],
  },
  [AgentType.LOG_ANALYZER]: {
    icon: FileText,
    name: 'Log Analyzer',
    description: 'Anomaly detection and pattern analysis in system logs',
    capabilities: [
      'Anomaly Detection',
      'Pattern Recognition',
      'Threat Detection',
      'Access Log Analysis',
      'Security Event Correlation',
    ],
    techStack: ['ML Models', 'Regex Patterns', 'Statistical Analysis'],
  },
  [AgentType.COMPLIANCE_CHECKER]: {
    icon: CheckSquare,
    name: 'Compliance Checker',
    description: 'RAG-based framework validation for compliance assessment',
    capabilities: [
      'SOC 2 Assessment',
      'GDPR Validation',
      'HIPAA Compliance',
      'NIST 800-53A Mapping',
      'Evidence-Based Verification',
    ],
    techStack: ['RAG Pipeline', 'ChromaDB', 'LangChain'],
  },
};

export default function AgentsPage() {
  const [selectedAuditId, setSelectedAuditId] = useState<string | null>(null);
  const [expandedAgent, setExpandedAgent] = useState<AgentType | null>(null);

  // Fetch audits for dropdown
  const { data: audits, isLoading: auditsLoading } = useAudits({
    limit: 50,
    autoRefresh: true,
  });

  // Auto-select running or most recent audit
  React.useEffect(() => {
    if (audits && audits.length > 0 && !selectedAuditId) {
      const runningAudit = audits.find(a => a.status === AuditStatus.RUNNING);
      setSelectedAuditId(runningAudit?.audit_id || audits[0].audit_id);
    }
  }, [audits, selectedAuditId]);

  // Fetch agent statuses
  const { data: agentStatuses, isLoading: statusLoading, refetch } = useAgentStatuses(
    selectedAuditId
  );

  // Calculate aggregate stats
  const stats = useMemo(() => {
    if (!agentStatuses) {
      return { running: 0, completed: 0, errors: 0, totalFindings: 0 };
    }
    return {
      running: agentStatuses.filter(a => a.status === AgentStatus.RUNNING).length,
      completed: agentStatuses.filter(a => a.status === AgentStatus.COMPLETED).length,
      errors: agentStatuses.filter(a => a.status === AgentStatus.ERROR).length,
      totalFindings: agentStatuses.reduce((sum, a) => sum + a.findings_count, 0),
    };
  }, [agentStatuses]);

  // Map statuses by agent type for easy lookup
  const statusMap = useMemo(() => {
    const map = new Map<AgentType, AgentStatusResponse>();
    agentStatuses?.forEach(s => map.set(s.agent_type, s));
    return map;
  }, [agentStatuses]);

  const isLoading = auditsLoading || statusLoading;

  return (
    <DashboardShell>
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            <Activity className="h-6 w-6 text-blue-600" />
            Agent Monitoring
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Monitor and manage the 4 specialized security agents
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            disabled={isLoading}
            className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={cn('h-4 w-4', isLoading && 'animate-spin')} />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats Row */}
      <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          title="Running"
          value={stats.running}
          icon={Loader2}
          variant={stats.running > 0 ? 'default' : 'default'}
        />
        <StatCard
          title="Completed"
          value={stats.completed}
          icon={CheckCircle}
          variant="success"
        />
        <StatCard
          title="Errors"
          value={stats.errors}
          icon={XCircle}
          variant={stats.errors > 0 ? 'critical' : 'default'}
        />
        <StatCard
          title="Total Findings"
          value={stats.totalFindings}
          icon={AlertCircle}
          variant={stats.totalFindings > 0 ? 'high' : 'default'}
        />
      </div>

      {/* Audit Selector */}
      <div className="mt-6 flex gap-4">
        <select
          value={selectedAuditId || ''}
          onChange={(e) => setSelectedAuditId(e.target.value || null)}
          className="px-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-gray-900"
          disabled={auditsLoading}
        >
          <option value="">Select Audit</option>
          {audits?.map((audit) => (
            <option key={audit.audit_id} value={audit.audit_id}>
              {audit.audit_id} - {audit.target} ({audit.status})
            </option>
          ))}
        </select>
      </div>

      {/* Agent Cards */}
      <div className="mt-6 grid grid-cols-1 md:grid-cols-2 gap-6">
        {Object.entries(AGENTS_CONFIG).map(([agentType, config]) => {
          const status = statusMap.get(agentType as AgentType);
          const isExpanded = expandedAgent === agentType;

          return (
            <AgentCard
              key={agentType}
              agentType={agentType as AgentType}
              config={config}
              status={status}
              isExpanded={isExpanded}
              onToggle={() => setExpandedAgent(isExpanded ? null : agentType as AgentType)}
            />
          );
        })}
      </div>

      {/* Multi-Agent Architecture Note */}
      <div className="mt-8 p-4 bg-gradient-to-r from-blue-50 to-indigo-50 rounded-lg border border-blue-200">
        <h3 className="text-sm font-semibold text-blue-900 mb-2 flex items-center gap-2">
          <Zap className="h-4 w-4" />
          Multi-Agent Architecture
        </h3>
        <p className="text-sm text-blue-800">
          This security auditor uses a LangGraph-orchestrated multi-agent architecture where each 
          specialized agent operates independently while sharing findings through a central state. 
          The orchestrator manages conditional routing based on severity findings and ensures 
          comprehensive evidence collection across all agents.
        </p>
      </div>
    </DashboardShell>
  );
}

interface AgentCardProps {
  agentType: AgentType;
  config: typeof AGENTS_CONFIG[AgentType];
  status?: AgentStatusResponse;
  isExpanded: boolean;
  onToggle: () => void;
}

function AgentCard({ agentType, config, status, isExpanded, onToggle }: AgentCardProps) {
  const { icon: Icon, name, description, capabilities, techStack } = config;
  const currentStatus = status?.status || AgentStatus.IDLE;
  const progress = status?.progress || 0;
  const findingsCount = status?.findings_count || 0;

  const statusColors = {
    [AgentStatus.IDLE]: 'border-l-gray-300',
    [AgentStatus.RUNNING]: 'border-l-blue-500',
    [AgentStatus.COMPLETED]: 'border-l-green-500',
    [AgentStatus.ERROR]: 'border-l-red-500',
  };

  const statusIcons = {
    [AgentStatus.IDLE]: <Clock className="h-5 w-5 text-gray-400" />,
    [AgentStatus.RUNNING]: <Loader2 className="h-5 w-5 text-blue-500 animate-spin" />,
    [AgentStatus.COMPLETED]: <CheckCircle className="h-5 w-5 text-green-500" />,
    [AgentStatus.ERROR]: <XCircle className="h-5 w-5 text-red-500" />,
  };

  return (
    <DashboardCard
      className={cn(
        'border-l-4 transition-all',
        statusColors[currentStatus],
        isExpanded && 'ring-2 ring-blue-200'
      )}
    >
      {/* Header */}
      <div
        className="flex items-start justify-between cursor-pointer"
        onClick={onToggle}
      >
        <div className="flex items-start gap-3">
          <div className={cn(
            'p-3 rounded-lg',
            currentStatus === AgentStatus.RUNNING ? 'bg-blue-100' :
            currentStatus === AgentStatus.COMPLETED ? 'bg-green-100' :
            currentStatus === AgentStatus.ERROR ? 'bg-red-100' : 'bg-gray-100'
          )}>
            <Icon className="h-6 w-6" />
          </div>
          <div>
            <h3 className="font-semibold text-gray-900">{name}</h3>
            <p className="text-sm text-gray-500 mt-0.5">{description}</p>
            <div className="flex items-center gap-2 mt-2">
              <AgentStatusBadge status={currentStatus} />
              {findingsCount > 0 && (
                <span className="px-2 py-0.5 text-xs bg-orange-100 text-orange-700 rounded-full">
                  {findingsCount} findings
                </span>
              )}
            </div>
          </div>
        </div>
        {statusIcons[currentStatus]}
      </div>

      {/* Progress Bar (if running) */}
      {currentStatus === AgentStatus.RUNNING && (
        <div className="mt-4">
          <ProgressBar value={progress} variant="default" size="md" />
        </div>
      )}

      {/* Error Message */}
      {status?.error_message && (
        <div className="mt-4 p-3 bg-red-50 rounded-lg text-sm text-red-700">
          {status.error_message}
        </div>
      )}

      {/* Expanded Details */}
      {isExpanded && (
        <div className="mt-4 pt-4 border-t border-gray-100 space-y-4">
          {/* Capabilities */}
          <div>
            <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">
              Capabilities
            </h4>
            <div className="flex flex-wrap gap-1">
              {capabilities.map((cap) => (
                <span
                  key={cap}
                  className="px-2 py-1 text-xs bg-gray-100 text-gray-600 rounded"
                >
                  {cap}
                </span>
              ))}
            </div>
          </div>

          {/* Tech Stack */}
          <div>
            <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">
              Technology Stack
            </h4>
            <div className="flex flex-wrap gap-1">
              {techStack.map((tech) => (
                <span
                  key={tech}
                  className="px-2 py-1 text-xs bg-blue-50 text-blue-700 rounded"
                >
                  {tech}
                </span>
              ))}
            </div>
          </div>

          {/* Last Activity */}
          {status?.last_activity && (
            <div className="text-xs text-gray-500">
              Last activity: {new Date(status.last_activity).toLocaleString()}
            </div>
          )}
        </div>
      )}
    </DashboardCard>
  );
}
