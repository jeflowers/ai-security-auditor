'use client';

/**
 * Main Dashboard Page with Real-Time WebSocket Updates
 * 
 * Primary view showing audit status, agent monitoring, findings overview,
 * and the key anti-hallucination metrics that differentiate this system.
 * 
 * Now integrated with WebSocket for real-time updates when an audit is running.
 * 
 * @module app/page
 */

import React, { useState, useMemo, useCallback, useEffect } from 'react';
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  FileText,
  Activity,
  Clock,
  Target,
  TrendingUp,
  Wifi,
  WifiOff,
} from 'lucide-react';
import { StatCard } from '@/components/dashboard/stat-card';
import { ProgressBar } from '@/components/dashboard/progress-bar';
import { DashboardShell } from '@/components/dashboard/dashboard-shell';
import { AgentStatusGrid } from '@/components/dashboard/agent-status-grid';
import { FindingsTable } from '@/components/dashboard/findings-table';
import { ComplianceMatrix } from '@/components/dashboard/compliance-matrix';
import { AntiHallucinationPanel } from '@/components/dashboard/anti-hallucination-panel';
import { EvidenceGapsList } from '@/components/dashboard/evidence-gaps-list';
import { SeverityChart } from '@/components/dashboard/severity-chart';
import { AuditHeader } from '@/components/dashboard/audit-header';
import { 
  useAudits, 
  useAuditSummary, 
  useAgentStatuses, 
  useFindings, 
  useComplianceStatus,
  useAntiHallucinationMetrics,
  useEvidenceGaps,
} from '@/hooks';
import { 
  useAuditWebSocket, 
  WSConnectionState 
} from '@/hooks/use-websocket';
import { useAuditStore } from '@/lib/store';
import { formatDuration, isAuditActive } from '@/lib/utils';
import { 
  Severity, 
  AuditStatus, 
  AgentType, 
  AgentStatusResponse,
  Finding,
  AuditStatusPayload,
  AgentUpdatePayload,
  FindingAddedPayload,
} from '@/types';

/**
 * Connection status indicator component
 */
function ConnectionIndicator({ state }: { state: WSConnectionState }) {
  const statusConfig = {
    [WSConnectionState.CONNECTED]: {
      icon: Wifi,
      text: 'Live',
      className: 'text-green-600 bg-green-100',
    },
    [WSConnectionState.CONNECTING]: {
      icon: Wifi,
      text: 'Connecting...',
      className: 'text-yellow-600 bg-yellow-100 animate-pulse',
    },
    [WSConnectionState.RECONNECTING]: {
      icon: Wifi,
      text: 'Reconnecting...',
      className: 'text-yellow-600 bg-yellow-100 animate-pulse',
    },
    [WSConnectionState.DISCONNECTED]: {
      icon: WifiOff,
      text: 'Offline',
      className: 'text-gray-500 bg-gray-100',
    },
    [WSConnectionState.ERROR]: {
      icon: WifiOff,
      text: 'Error',
      className: 'text-red-600 bg-red-100',
    },
  };

  const config = statusConfig[state];
  const Icon = config.icon;

  return (
    <div className={`flex items-center gap-1.5 px-2 py-1 rounded-full text-xs font-medium ${config.className}`}>
      <Icon className="h-3 w-3" />
      <span>{config.text}</span>
    </div>
  );
}

export default function DashboardPage() {
  const { selectedAuditId, setSelectedAudit, audits } = useAuditStore();
  
  // Local state for real-time updates
  const [realtimeProgress, setRealtimeProgress] = useState<number | null>(null);
  const [realtimeAgents, setRealtimeAgents] = useState<Map<AgentType, AgentUpdatePayload>>(new Map());
  const [realtimeFindings, setRealtimeFindings] = useState<Finding[]>([]);
  const [currentPhase, setCurrentPhase] = useState<string | null>(null);
  
  // Fetch all audits for selection
  const { data: auditsList, isLoading: auditsLoading, refetch: refetchAudits } = useAudits({ 
    autoRefresh: true,
    limit: 20 
  });
  
  // Get the selected audit from the store
  const selectedAudit = useAuditStore.getState().selectedAudit;
  
  // Determine if we should use WebSocket (only for running audits)
  const shouldUseWebSocket = selectedAudit?.status === AuditStatus.RUNNING && !!selectedAuditId;
  
  // WebSocket callbacks
  const handleStatusUpdate = useCallback((payload: AuditStatusPayload) => {
    console.log('WebSocket status update:', payload);
    setRealtimeProgress(payload.progress);
    
    // If audit completed, refetch data
    if (payload.status === AuditStatus.COMPLETED || payload.status === AuditStatus.FAILED) {
      refetchAudits();
    }
  }, [refetchAudits]);
  
  const handleAgentUpdate = useCallback((payload: AgentUpdatePayload) => {
    console.log('WebSocket agent update:', payload);
    setRealtimeAgents(prev => {
      const updated = new Map(prev);
      updated.set(payload.agent_type, payload);
      return updated;
    });
  }, []);
  
  const handleFindingAdded = useCallback((payload: FindingAddedPayload) => {
    console.log('WebSocket finding added:', payload);
    setRealtimeFindings(prev => [payload.finding, ...prev.slice(0, 9)]);
  }, []);
  
  const handlePhaseChange = useCallback((phase: string) => {
    console.log('WebSocket phase change:', phase);
    setCurrentPhase(phase);
  }, []);
  
  // WebSocket hook - only active for running audits
  const {
    connectionState,
    auditStatus: wsAuditStatus,
    agentUpdates: wsAgentUpdates,
    recentFindings: wsRecentFindings,
    error: wsError,
  } = useAuditWebSocket({
    auditId: selectedAuditId || '',
    autoConnect: shouldUseWebSocket,
    onStatusUpdate: handleStatusUpdate,
    onAgentUpdate: handleAgentUpdate,
    onFindingAdded: handleFindingAdded,
    onPhaseChange: handlePhaseChange,
  });
  
  // Update store when audits load
  useEffect(() => {
    if (auditsList && auditsList.length > 0) {
      useAuditStore.getState().setAudits(auditsList);
      // Auto-select the most recent running audit or first audit
      if (!selectedAuditId) {
        const runningAudit = auditsList.find(a => a.status === AuditStatus.RUNNING);
        const firstAudit = runningAudit || auditsList[0];
        setSelectedAudit(firstAudit);
      }
    }
  }, [auditsList, selectedAuditId, setSelectedAudit]);
  
  // Reset real-time state when audit changes
  useEffect(() => {
    setRealtimeProgress(null);
    setRealtimeAgents(new Map());
    setRealtimeFindings([]);
    setCurrentPhase(null);
  }, [selectedAuditId]);
  
  // Fetch data for selected audit (REST API as baseline)
  const { data: summary, isLoading: summaryLoading, refetch: refetchSummary } = useAuditSummary(selectedAuditId);
  const { data: agentStatuses, isLoading: agentsLoading, refetch: refetchAgents } = useAgentStatuses(selectedAuditId);
  const { data: findings, isLoading: findingsLoading, refetch: refetchFindings } = useFindings(selectedAuditId, { limit: 10 });
  const { data: complianceStatuses, isLoading: complianceLoading } = useComplianceStatus(selectedAuditId);
  
  // Anti-hallucination metrics - fetched from API
  const { 
    data: antiHallucinationMetrics, 
    isLoading: metricsLoading 
  } = useAntiHallucinationMetrics(selectedAuditId);
  
  // Evidence gaps - fetched from API
  const { 
    data: evidenceGaps, 
    isLoading: gapsLoading 
  } = useEvidenceGaps(selectedAuditId);
  
  // Default fallback values for loading states
  const defaultMetrics = {
    llm_overrides: 0,
    forbidden_words_detected: 0,
    evidence_citation_rate: 0,
    average_confidence: 0,
    confidence_distribution: [],
  };
  
  const defaultGaps: Array<{ control: string; requirement: string; priority: 'high' | 'medium' | 'low' }> = [];
  
  const isLoading = summaryLoading || agentsLoading || findingsLoading || complianceLoading || metricsLoading || gapsLoading;
  
  // Merge REST API agent statuses with real-time WebSocket updates
  const mergedAgentStatuses = useMemo((): AgentStatusResponse[] => {
    if (!agentStatuses) return [];
    
    return agentStatuses.map(agent => {
      const realtimeUpdate = realtimeAgents.get(agent.agent_type) || wsAgentUpdates.get(agent.agent_type);
      if (realtimeUpdate) {
        return {
          ...agent,
          status: realtimeUpdate.status as any,
          progress: realtimeUpdate.progress,
          findings_count: realtimeUpdate.findings_count,
        };
      }
      return agent;
    });
  }, [agentStatuses, realtimeAgents, wsAgentUpdates]);
  
  // Merge REST API findings with real-time WebSocket findings
  const mergedFindings = useMemo(() => {
    const wsFindings = wsRecentFindings.length > 0 ? wsRecentFindings : realtimeFindings;
    const baseFindings = findings?.findings || [];
    
    // Combine and deduplicate by finding_id
    const findingMap = new Map<string, Finding>();
    [...baseFindings, ...wsFindings].forEach(f => {
      if (!findingMap.has(f.finding_id)) {
        findingMap.set(f.finding_id, f);
      }
    });
    
    return Array.from(findingMap.values()).slice(0, 10);
  }, [findings, realtimeFindings, wsRecentFindings]);
  
  // Use real-time progress if available, otherwise use summary progress
  const displayProgress = useMemo(() => {
    if (wsAuditStatus?.progress !== undefined) {
      return wsAuditStatus.progress;
    }
    if (realtimeProgress !== null) {
      return realtimeProgress;
    }
    return summary?.progress ?? 0;
  }, [wsAuditStatus, realtimeProgress, summary]);
  
  // Calculate severity distribution for chart
  const severityData = useMemo(() => {
    if (!summary?.findings.by_severity) return [];
    return [
      { name: 'Critical', value: summary.findings.by_severity[Severity.CRITICAL] || 0, color: '#dc2626' },
      { name: 'High', value: summary.findings.by_severity[Severity.HIGH] || 0, color: '#f97316' },
      { name: 'Medium', value: summary.findings.by_severity[Severity.MEDIUM] || 0, color: '#eab308' },
      { name: 'Low', value: summary.findings.by_severity[Severity.LOW] || 0, color: '#3b82f6' },
      { name: 'Info', value: summary.findings.by_severity[Severity.INFO] || 0, color: '#6b7280' },
    ].filter(d => d.value > 0);
  }, [summary]);
  
  // No audit selected state
  if (!selectedAuditId && !auditsLoading) {
    return (
      <DashboardShell>
        <div className="flex flex-col items-center justify-center h-96 text-gray-500">
          <Shield className="h-16 w-16 mb-4 opacity-50" />
          <h2 className="text-xl font-semibold mb-2">No Audit Selected</h2>
          <p className="text-sm">Select an audit from the sidebar or create a new one to get started.</p>
        </div>
      </DashboardShell>
    );
  }

  return (
    <DashboardShell>
      {/* Audit Header with selector and connection status */}
      <div className="flex items-center justify-between">
        <AuditHeader
          audit={selectedAudit}
          audits={auditsList || []}
          onSelectAudit={(audit) => setSelectedAudit(audit)}
          isLoading={auditsLoading}
        />
        
        {/* WebSocket Connection Status */}
        {shouldUseWebSocket && (
          <ConnectionIndicator state={connectionState} />
        )}
      </div>
      
      {/* WebSocket Error Display */}
      {wsError && (
        <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
          <strong>WebSocket Error:</strong> {wsError.message}
        </div>
      )}
      
      {/* Current Phase Indicator (from WebSocket) */}
      {currentPhase && shouldUseWebSocket && (
        <div className="mt-4 p-3 bg-blue-50 border border-blue-200 rounded-lg text-blue-700 text-sm flex items-center gap-2">
          <Activity className="h-4 w-4 animate-pulse" />
          <span><strong>Current Phase:</strong> {currentPhase.replace(/_/g, ' ')}</span>
        </div>
      )}
      
      {/* Summary Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mt-6">
        <StatCard
          title="Total Findings"
          value={summary?.findings.total ?? '—'}
          subtitle={summary ? `${summary.findings.by_severity[Severity.CRITICAL] || 0} critical` : undefined}
          icon={AlertTriangle}
          variant={
            (summary?.findings.by_severity[Severity.CRITICAL] || 0) > 0
              ? 'critical'
              : (summary?.findings.by_severity[Severity.HIGH] || 0) > 0
              ? 'high'
              : 'default'
          }
        />
        <StatCard
          title="Evidence Items"
          value={summary?.evidence.total ?? '—'}
          subtitle="Collected artifacts"
          icon={FileText}
          variant="default"
        />
        <StatCard
          title="Compliance Score"
          value={summary ? `${Math.round(summary.compliance.overall_score)}%` : '—'}
          subtitle={summary?.compliance.frameworks.join(', ')}
          icon={CheckCircle}
          variant={
            (summary?.compliance.overall_score ?? 0) >= 80
              ? 'success'
              : (summary?.compliance.overall_score ?? 0) >= 60
              ? 'medium'
              : 'critical'
          }
        />
        <StatCard
          title="Audit Duration"
          value={summary ? formatDuration(summary.duration_seconds) : '—'}
          subtitle={isAuditActive(summary?.status ?? '') ? 'In progress' : 'Completed'}
          icon={Clock}
          variant="default"
        />
      </div>
      
      {/* Progress Bar for Active Audits - Now with real-time updates */}
      {summary && isAuditActive(summary.status) && (
        <div className="mt-6 bg-white rounded-lg border border-gray-200 p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-gray-700">
              Overall Progress
              {connectionState === WSConnectionState.CONNECTED && (
                <span className="ml-2 text-xs text-green-600">(Live)</span>
              )}
            </span>
            <span className="text-sm text-gray-500">{Math.round(displayProgress)}%</span>
          </div>
          <ProgressBar
            value={displayProgress}
            variant={displayProgress >= 100 ? 'success' : 'default'}
            size="lg"
            showPercentage={false}
          />
        </div>
      )}
      
      {/* Agent Status Grid - Now with real-time updates */}
      <div className="mt-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
          <Activity className="h-5 w-5 mr-2" />
          Agent Status
          {connectionState === WSConnectionState.CONNECTED && (
            <span className="ml-2 text-xs bg-green-100 text-green-700 px-2 py-0.5 rounded-full">
              Live Updates
            </span>
          )}
        </h2>
        <AgentStatusGrid
          agentStatuses={mergedAgentStatuses}
          isLoading={agentsLoading}
        />
      </div>
      
      {/* Two Column Layout: Findings & Anti-Hallucination */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6">
        {/* Findings Section - Now with real-time updates */}
        <div className="bg-white rounded-lg border border-gray-200 p-4">
          <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
            <AlertTriangle className="h-5 w-5 mr-2 text-orange-500" />
            Recent Findings
            {(realtimeFindings.length > 0 || wsRecentFindings.length > 0) && (
              <span className="ml-2 text-xs bg-orange-100 text-orange-700 px-2 py-0.5 rounded-full">
                {realtimeFindings.length + wsRecentFindings.length} new
              </span>
            )}
          </h2>
          <FindingsTable
            findings={mergedFindings}
            isLoading={findingsLoading}
            compact
          />
        </div>
        
        {/* Anti-Hallucination Panel - Key Differentiator */}
        <div className="bg-white rounded-lg border border-gray-200 p-4">
          <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
            <Shield className="h-5 w-5 mr-2 text-green-600" />
            Anti-Hallucination Metrics
            <span className="ml-2 text-xs bg-green-100 text-green-800 px-2 py-0.5 rounded-full">
              Key Feature
            </span>
          </h2>
          <AntiHallucinationPanel 
            metrics={antiHallucinationMetrics || defaultMetrics} 
            isLoading={metricsLoading}
          />
        </div>
      </div>
      
      {/* Severity Distribution Chart */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mt-6">
        <div className="bg-white rounded-lg border border-gray-200 p-4">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">
            Severity Distribution
          </h2>
          <SeverityChart data={severityData} />
        </div>
        
        {/* Evidence Gaps */}
        <div className="bg-white rounded-lg border border-gray-200 p-4 lg:col-span-2">
          <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
            <Target className="h-5 w-5 mr-2 text-orange-500" />
            Evidence Gaps
          </h2>
          <EvidenceGapsList 
            gaps={evidenceGaps || defaultGaps} 
            isLoading={gapsLoading}
          />
        </div>
      </div>
      
      {/* Compliance Matrix */}
      <div className="mt-6 bg-white rounded-lg border border-gray-200 p-4">
        <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
          <TrendingUp className="h-5 w-5 mr-2 text-blue-600" />
          Compliance Overview
        </h2>
        <ComplianceMatrix
          complianceStatuses={complianceStatuses || []}
          isLoading={complianceLoading}
        />
      </div>
    </DashboardShell>
  );
}
