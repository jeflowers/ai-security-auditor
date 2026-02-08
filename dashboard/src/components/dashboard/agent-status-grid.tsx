'use client';

/**
 * Agent Status Grid Component
 * 
 * Displays status cards for all 4 security agents showing their
 * current state, progress, and findings count.
 * 
 * @module components/dashboard/agent-status-grid
 */

import React from 'react';
import {
  Scan,
  Code,
  FileText,
  CheckSquare,
  Loader2,
  CheckCircle,
  XCircle,
  Pause,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { ProgressBar } from './progress-bar';
import { AgentStatusBadge } from '@/components/ui/badge';
import type { AgentStatusResponse, AgentType, AgentStatus } from '@/types';

interface AgentStatusGridProps {
  agentStatuses: AgentStatusResponse[];
  isLoading?: boolean;
  className?: string;
}

// Agent configuration for icons and labels
const AGENT_CONFIG: Record<AgentType, { icon: typeof Scan; label: string; description: string }> = {
  vulnerability_scanner: {
    icon: Scan,
    label: 'Vulnerability Scanner',
    description: 'OWASP ZAP integration for web vulnerability scanning',
  },
  code_analyzer: {
    icon: Code,
    label: 'Code Analyzer',
    description: 'Static analysis for OWASP Top 10 compliance',
  },
  log_analyzer: {
    icon: FileText,
    label: 'Log Analyzer',
    description: 'Anomaly detection in system and security logs',
  },
  compliance_checker: {
    icon: CheckSquare,
    label: 'Compliance Checker',
    description: 'RAG-based framework validation (SOC2, GDPR, HIPAA)',
  },
};

// Default agent types to show even if not in the response
const DEFAULT_AGENTS: AgentType[] = [
  'vulnerability_scanner' as AgentType,
  'code_analyzer' as AgentType,
  'log_analyzer' as AgentType,
  'compliance_checker' as AgentType,
];

export function AgentStatusGrid({
  agentStatuses,
  isLoading,
  className,
}: AgentStatusGridProps) {
  // Create a map for quick lookup
  const statusMap = new Map(agentStatuses.map((s) => [s.agent_type, s]));

  if (isLoading) {
    return (
      <div className={cn('grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4', className)}>
        {DEFAULT_AGENTS.map((agentType) => (
          <AgentCardSkeleton key={agentType} />
        ))}
      </div>
    );
  }

  return (
    <div className={cn('grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4', className)}>
      {DEFAULT_AGENTS.map((agentType) => {
        const status = statusMap.get(agentType);
        const config = AGENT_CONFIG[agentType];
        
        return (
          <AgentStatusCard
            key={agentType}
            agentType={agentType}
            status={status}
            config={config}
          />
        );
      })}
    </div>
  );
}

interface AgentStatusCardProps {
  agentType: AgentType;
  status?: AgentStatusResponse;
  config: { icon: typeof Scan; label: string; description: string };
}

function AgentStatusCard({ agentType, status, config }: AgentStatusCardProps) {
  const { icon: Icon, label, description } = config;
  const currentStatus = status?.status || ('idle' as AgentStatus);
  const progress = status?.progress ?? 0;
  const findingsCount = status?.findings_count ?? 0;
  
  const statusIcon = getStatusIcon(currentStatus);
  const borderColor = getStatusBorderColor(currentStatus);
  
  return (
    <div
      className={cn(
        'bg-white rounded-lg border-l-4 border shadow-sm p-4 transition-all hover:shadow-md',
        borderColor
      )}
    >
      {/* Header */}
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center">
          <div className={cn('p-2 rounded-lg', getIconBackground(currentStatus))}>
            <Icon className="h-5 w-5" />
          </div>
          <div className="ml-3">
            <h3 className="text-sm font-semibold text-gray-900">{label}</h3>
            <AgentStatusBadge status={currentStatus} className="mt-1" />
          </div>
        </div>
        {statusIcon}
      </div>
      
      {/* Description */}
      <p className="text-xs text-gray-500 mb-3">{description}</p>
      
      {/* Progress */}
      {currentStatus === ('running' as AgentStatus) && (
        <div className="mb-3">
          <ProgressBar
            value={progress}
            size="sm"
            variant="default"
            showPercentage={true}
          />
        </div>
      )}
      
      {/* Findings Count */}
      <div className="flex items-center justify-between pt-3 border-t border-gray-100">
        <span className="text-xs text-gray-500">Findings</span>
        <span className={cn(
          'text-sm font-bold',
          findingsCount > 0 ? 'text-orange-600' : 'text-gray-400'
        )}>
          {findingsCount}
        </span>
      </div>
      
      {/* Error Message */}
      {status?.error_message && (
        <div className="mt-2 p-2 bg-red-50 rounded text-xs text-red-700">
          {status.error_message}
        </div>
      )}
    </div>
  );
}

function AgentCardSkeleton() {
  return (
    <div className="bg-white rounded-lg border border-gray-200 shadow-sm p-4 animate-pulse">
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center">
          <div className="w-10 h-10 bg-gray-200 rounded-lg" />
          <div className="ml-3">
            <div className="h-4 w-24 bg-gray-200 rounded" />
            <div className="h-3 w-16 bg-gray-200 rounded mt-2" />
          </div>
        </div>
      </div>
      <div className="h-3 w-full bg-gray-200 rounded mb-3" />
      <div className="h-2 w-full bg-gray-200 rounded mb-3" />
      <div className="flex justify-between pt-3 border-t border-gray-100">
        <div className="h-3 w-16 bg-gray-200 rounded" />
        <div className="h-3 w-8 bg-gray-200 rounded" />
      </div>
    </div>
  );
}

function getStatusIcon(status: AgentStatus): React.ReactNode {
  switch (status) {
    case 'running' as AgentStatus:
      return <Loader2 className="h-5 w-5 text-blue-500 animate-spin" />;
    case 'completed' as AgentStatus:
      return <CheckCircle className="h-5 w-5 text-green-500" />;
    case 'error' as AgentStatus:
      return <XCircle className="h-5 w-5 text-red-500" />;
    default:
      return <Pause className="h-5 w-5 text-gray-400" />;
  }
}

function getStatusBorderColor(status: AgentStatus): string {
  switch (status) {
    case 'running' as AgentStatus:
      return 'border-l-blue-500 border-gray-200';
    case 'completed' as AgentStatus:
      return 'border-l-green-500 border-gray-200';
    case 'error' as AgentStatus:
      return 'border-l-red-500 border-gray-200';
    default:
      return 'border-l-gray-300 border-gray-200';
  }
}

function getIconBackground(status: AgentStatus): string {
  switch (status) {
    case 'running' as AgentStatus:
      return 'bg-blue-100 text-blue-600';
    case 'completed' as AgentStatus:
      return 'bg-green-100 text-green-600';
    case 'error' as AgentStatus:
      return 'bg-red-100 text-red-600';
    default:
      return 'bg-gray-100 text-gray-600';
  }
}
