'use client';

/**
 * Audit Detail Page
 * 
 * Displays comprehensive information about a single audit including:
 * - Audit status and progress
 * - Agent statuses
 * - Findings summary
 * - Compliance status
 * - Anti-hallucination metrics
 * 
 * @module app/audits/[id]/page
 */

import React, { useState, useMemo } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  ArrowLeft,
  RefreshCw,
  CheckCircle,
  XCircle,
  Clock,
  Loader2,
  AlertTriangle,
  AlertCircle,
  Shield,
  FileSearch,
  Server,
  Code,
  FileText,
  Activity,
  Target,
  Calendar,
  BarChart3,
  ChevronRight,
  ExternalLink,
  Download,
  Eye,
} from 'lucide-react';
import { DashboardShell, DashboardCard } from '@/components/dashboard/dashboard-shell';
import { StatusBadge, Badge, SeverityBadge } from '@/components/ui/badge';
import { 
  useAudit, 
  useAgentStatuses, 
  useFindings, 
  useComplianceStatus,
  useAntiHallucinationMetrics,
  useEvidenceGaps 
} from '@/hooks';
import { cn, formatDateTime, formatDuration } from '@/lib/utils';
import { AuditStatus, AgentType, Severity } from '@/types';
import type { Finding, AgentStatusResponse, ComplianceStatus as ComplianceStatusType } from '@/types';

// ============================================================================
// Main Page Component
// ============================================================================

export default function AuditDetailPage() {
  const params = useParams();
  const router = useRouter();
  const auditId = params.id as string;

  // Fetch data
  const { data: audit, isLoading: auditLoading, error: auditError, refetch: refetchAudit } = useAudit(auditId);
  const { data: agents, isLoading: agentsLoading, refetch: refetchAgents } = useAgentStatuses(auditId);
  const { data: findingsData, isLoading: findingsLoading, refetch: refetchFindings } = useFindings(auditId, { limit: 100 });
  const { data: compliance, isLoading: complianceLoading, refetch: refetchCompliance } = useComplianceStatus(auditId);
  const { data: antiHallucination, isLoading: ahLoading, refetch: refetchAH } = useAntiHallucinationMetrics(auditId);
  const { data: evidenceGaps, isLoading: gapsLoading } = useEvidenceGaps(auditId);

  const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'compliance' | 'agents'>('overview');

  const isLoading = auditLoading || agentsLoading || findingsLoading || complianceLoading || ahLoading;

  const handleRefresh = async () => {
    await Promise.all([
      refetchAudit(),
      refetchAgents(),
      refetchFindings(),
      refetchCompliance(),
      refetchAH(),
    ]);
  };

  // Calculate findings summary
  const findingsSummary = useMemo(() => {
    if (!findingsData?.findings) return { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
    
    const findings = findingsData.findings;
    return {
      critical: findings.filter(f => f.severity === Severity.CRITICAL).length,
      high: findings.filter(f => f.severity === Severity.HIGH).length,
      medium: findings.filter(f => f.severity === Severity.MEDIUM).length,
      low: findings.filter(f => f.severity === Severity.LOW).length,
      total: findings.length,
    };
  }, [findingsData]);

  // Error state
  if (auditError) {
    return (
      <DashboardShell>
        <div className="flex flex-col items-center justify-center py-12">
          <AlertTriangle className="h-12 w-12 text-red-500 mb-4" />
          <h2 className="text-xl font-semibold text-gray-900 mb-2">Audit Not Found</h2>
          <p className="text-gray-500 mb-4">
            {auditError.message || `Could not find audit with ID: ${auditId}`}
          </p>
          <Link
            href="/audits"
            className="flex items-center gap-2 text-gray-600 hover:text-gray-900"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to Audits
          </Link>
        </div>
      </DashboardShell>
    );
  }

  // Loading state
  if (isLoading && !audit) {
    return (
      <DashboardShell>
        <div className="flex flex-col items-center justify-center py-12">
          <Loader2 className="h-8 w-8 text-gray-400 animate-spin mb-4" />
          <p className="text-gray-500">Loading audit details...</p>
        </div>
      </DashboardShell>
    );
  }

  return (
    <DashboardShell>
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-4">
        <div>
          <Link
            href="/audits"
            className="flex items-center gap-1 text-sm text-gray-500 hover:text-gray-700 mb-2"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to Audits
          </Link>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-gray-900 font-mono">
              {audit?.audit_id}
            </h1>
            {audit && <StatusBadge status={audit.status} />}
          </div>
          {audit && (
            <div className="flex items-center gap-4 mt-2 text-sm text-gray-500">
              <span className="flex items-center gap-1">
                <Target className="h-4 w-4" />
                {audit.target}
              </span>
              <span className="flex items-center gap-1">
                <Calendar className="h-4 w-4" />
                {formatDateTime(audit.created_at)}
              </span>
            </div>
          )}
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleRefresh}
            disabled={isLoading}
            className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={cn('h-4 w-4', isLoading && 'animate-spin')} />
            Refresh
          </button>
        </div>
      </div>

      {/* Progress Bar for Running Audits */}
      {audit?.status === AuditStatus.RUNNING && (
        <div className="mt-4">
          <div className="flex items-center justify-between text-sm mb-1">
            <span className="text-gray-600">Progress: {audit.current_phase}</span>
            <span className="font-medium">{Math.round(audit.progress)}%</span>
          </div>
          <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
            <div
              className="h-full bg-blue-500 transition-all duration-500"
              style={{ width: `${audit.progress}%` }}
            />
          </div>
        </div>
      )}

      {/* Tab Navigation */}
      <div className="mt-6 border-b border-gray-200">
        <nav className="flex gap-6">
          {[
            { id: 'overview', label: 'Overview', icon: BarChart3 },
            { id: 'findings', label: 'Findings', icon: AlertCircle, count: findingsSummary.total },
            { id: 'compliance', label: 'Compliance', icon: Shield, count: compliance?.length },
            { id: 'agents', label: 'Agents', icon: Server, count: agents?.length },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={cn(
                'flex items-center gap-2 pb-3 text-sm font-medium border-b-2 transition-colors',
                activeTab === tab.id
                  ? 'border-gray-900 text-gray-900'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              )}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
              {tab.count !== undefined && (
                <span className="px-2 py-0.5 text-xs bg-gray-100 rounded-full">
                  {tab.count}
                </span>
              )}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="mt-6">
        {activeTab === 'overview' && (
          <OverviewTab
            audit={audit}
            findingsSummary={findingsSummary}
            agents={agents}
            compliance={compliance}
            antiHallucination={antiHallucination}
            evidenceGaps={evidenceGaps}
          />
        )}
        {activeTab === 'findings' && (
          <FindingsTab findings={findingsData?.findings || []} />
        )}
        {activeTab === 'compliance' && (
          <ComplianceTab compliance={compliance || []} auditId={auditId} />
        )}
        {activeTab === 'agents' && (
          <AgentsTab agents={agents || []} />
        )}
      </div>
    </DashboardShell>
  );
}

// ============================================================================
// Overview Tab
// ============================================================================

interface OverviewTabProps {
  audit: any;
  findingsSummary: { critical: number; high: number; medium: number; low: number; total: number };
  agents: AgentStatusResponse[] | null;
  compliance: ComplianceStatusType[] | null;
  antiHallucination: any;
  evidenceGaps: any[] | null;
}

function OverviewTab({ audit, findingsSummary, agents, compliance, antiHallucination, evidenceGaps }: OverviewTabProps) {
  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Findings Summary */}
        <DashboardCard>
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-medium text-gray-700">Findings</h3>
            <AlertCircle className="h-5 w-5 text-gray-400" />
          </div>
          <div className="text-3xl font-bold text-gray-900 mb-2">
            {findingsSummary.total}
          </div>
          <div className="flex gap-2">
            {findingsSummary.critical > 0 && (
              <span className="px-2 py-0.5 text-xs bg-red-100 text-red-700 rounded">
                {findingsSummary.critical} Critical
              </span>
            )}
            {findingsSummary.high > 0 && (
              <span className="px-2 py-0.5 text-xs bg-orange-100 text-orange-700 rounded">
                {findingsSummary.high} High
              </span>
            )}
          </div>
        </DashboardCard>

        {/* Compliance Score */}
        <DashboardCard>
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-medium text-gray-700">Compliance</h3>
            <Shield className="h-5 w-5 text-gray-400" />
          </div>
          <div className="text-3xl font-bold text-gray-900 mb-2">
            {compliance ? `${compliance.filter(c => c.status === 'compliant').length}/${compliance.length}` : '-'}
          </div>
          <div className="text-sm text-gray-500">
            Frameworks assessed
          </div>
        </DashboardCard>

        {/* Agent Status */}
        <DashboardCard>
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-medium text-gray-700">Agents</h3>
            <Server className="h-5 w-5 text-gray-400" />
          </div>
          <div className="text-3xl font-bold text-gray-900 mb-2">
            {agents?.filter(a => a.status === 'completed').length || 0}/{agents?.length || 0}
          </div>
          <div className="text-sm text-gray-500">
            Completed
          </div>
        </DashboardCard>

        {/* Anti-Hallucination */}
        <DashboardCard>
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-medium text-gray-700">Evidence Rate</h3>
            <Eye className="h-5 w-5 text-gray-400" />
          </div>
          <div className="text-3xl font-bold text-gray-900 mb-2">
            {antiHallucination ? `${Math.round(antiHallucination.evidence_citation_rate * 100)}%` : '-'}
          </div>
          <div className="text-sm text-gray-500">
            Citation compliance
          </div>
        </DashboardCard>
      </div>

      {/* Anti-Hallucination Metrics */}
      {antiHallucination && (
        <DashboardCard>
          <h3 className="font-semibold text-gray-900 mb-4 flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Anti-Hallucination Safeguards
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-3 bg-gray-50 rounded-lg">
              <div className="text-sm text-gray-500 mb-1">LLM Overrides</div>
              <div className="text-xl font-bold">{antiHallucination.llm_overrides}</div>
            </div>
            <div className="p-3 bg-gray-50 rounded-lg">
              <div className="text-sm text-gray-500 mb-1">Forbidden Words</div>
              <div className="text-xl font-bold">{antiHallucination.forbidden_words_detected}</div>
            </div>
            <div className="p-3 bg-gray-50 rounded-lg">
              <div className="text-sm text-gray-500 mb-1">Avg Confidence</div>
              <div className="text-xl font-bold">{Math.round(antiHallucination.average_confidence * 100)}%</div>
            </div>
            <div className="p-3 bg-gray-50 rounded-lg">
              <div className="text-sm text-gray-500 mb-1">Citation Rate</div>
              <div className="text-xl font-bold">{Math.round(antiHallucination.evidence_citation_rate * 100)}%</div>
            </div>
          </div>
        </DashboardCard>
      )}

      {/* Evidence Gaps */}
      {evidenceGaps && evidenceGaps.length > 0 && (
        <DashboardCard>
          <h3 className="font-semibold text-gray-900 mb-4 flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-amber-500" />
            Evidence Gaps ({evidenceGaps.length})
          </h3>
          <div className="space-y-2">
            {evidenceGaps.slice(0, 5).map((gap, i) => (
              <div key={i} className="flex items-center justify-between p-3 bg-amber-50 rounded-lg">
                <div>
                  <span className="font-medium text-gray-900">{gap.control}</span>
                  <p className="text-sm text-gray-600">{gap.requirement}</p>
                </div>
                <Badge variant={gap.priority === 'high' ? 'destructive' : gap.priority === 'medium' ? 'warning' : 'default'}>
                  {gap.priority}
                </Badge>
              </div>
            ))}
          </div>
        </DashboardCard>
      )}

      {/* Frameworks */}
      {audit?.frameworks && (
        <DashboardCard>
          <h3 className="font-semibold text-gray-900 mb-4">Compliance Frameworks</h3>
          <div className="flex flex-wrap gap-2">
            {audit.frameworks.map((fw: string) => (
              <span key={fw} className="px-3 py-1.5 bg-gray-100 text-gray-700 rounded-lg text-sm font-medium">
                {fw.toUpperCase()}
              </span>
            ))}
          </div>
        </DashboardCard>
      )}
    </div>
  );
}

// ============================================================================
// Findings Tab
// ============================================================================

function FindingsTab({ findings }: { findings: Finding[] }) {
  const [severityFilter, setSeverityFilter] = useState<Severity | ''>('');

  const filteredFindings = useMemo(() => {
    if (!severityFilter) return findings;
    return findings.filter(f => f.severity === severityFilter);
  }, [findings, severityFilter]);

  if (findings.length === 0) {
    return (
      <DashboardCard className="flex flex-col items-center justify-center py-12">
        <CheckCircle className="h-12 w-12 text-green-500 mb-4" />
        <h3 className="text-lg font-medium text-gray-900 mb-2">No Findings</h3>
        <p className="text-sm text-gray-500">No security findings were detected</p>
      </DashboardCard>
    );
  }

  return (
    <div className="space-y-4">
      {/* Filter */}
      <div className="flex items-center gap-4">
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value as Severity | '')}
          className="px-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-gray-900"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <span className="text-sm text-gray-500">
          Showing {filteredFindings.length} of {findings.length} findings
        </span>
      </div>

      {/* Findings List */}
      <div className="space-y-3">
        {filteredFindings.map((finding) => (
          <DashboardCard key={finding.finding_id} className="hover:shadow-md transition-shadow">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <SeverityBadge severity={finding.severity} />
                  <span className="font-mono text-xs text-gray-500">{finding.finding_id}</span>
                </div>
                <h4 className="font-medium text-gray-900 mb-1">{finding.title}</h4>
                <p className="text-sm text-gray-600 line-clamp-2">{finding.description}</p>
                {finding.cwe_id && (
                  <div className="mt-2 flex items-center gap-2">
                    <span className="text-xs px-2 py-0.5 bg-purple-100 text-purple-700 rounded">
                      {finding.cwe_id}
                    </span>
                    {finding.control_ids && finding.control_ids.length > 0 && (
                      <span className="text-xs px-2 py-0.5 bg-blue-100 text-blue-700 rounded">
                        {finding.control_ids[0]}
                      </span>
                    )}
                  </div>
                )}
              </div>
              <ChevronRight className="h-5 w-5 text-gray-400 flex-shrink-0 ml-4" />
            </div>
          </DashboardCard>
        ))}
      </div>
    </div>
  );
}

// ============================================================================
// Compliance Tab
// ============================================================================

function ComplianceTab({ compliance, auditId }: { compliance: ComplianceStatusType[]; auditId: string }) {
  if (compliance.length === 0) {
    return (
      <DashboardCard className="flex flex-col items-center justify-center py-12">
        <FileSearch className="h-12 w-12 text-gray-400 mb-4" />
        <h3 className="text-lg font-medium text-gray-900 mb-2">No Compliance Data</h3>
        <p className="text-sm text-gray-500">Compliance assessment not yet available</p>
      </DashboardCard>
    );
  }

  return (
    <div className="space-y-4">
      {compliance.map((fw) => {
        // Derive status from compliance percentage
        const complianceStatus = fw.compliance_percentage >= 80 ? 'compliant' : 
          fw.compliance_percentage >= 50 ? 'partial' : 'non_compliant';
        
        return (
          <DashboardCard key={fw.framework}>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <Shield className={cn(
                  'h-6 w-6',
                  complianceStatus === 'compliant' ? 'text-green-500' : 
                  complianceStatus === 'non_compliant' ? 'text-red-500' : 
                  'text-amber-500'
                )} />
                <div>
                  <h3 className="font-semibold text-gray-900">{fw.framework.toUpperCase()}</h3>
                  <p className="text-sm text-gray-500">
                    {fw.compliant}/{fw.total_controls} controls passed
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <div className="text-right">
                  <div className="text-2xl font-bold text-gray-900">
                    {Math.round(fw.compliance_percentage)}%
                  </div>
                  <div className="text-xs text-gray-500">Compliance</div>
                </div>
                <Badge variant={
                  complianceStatus === 'compliant' ? 'success' : 
                  complianceStatus === 'non_compliant' ? 'destructive' : 
                  'warning'
                }>
                  {complianceStatus.replace('_', ' ')}
                </Badge>
              </div>
            </div>
            
            {/* Progress Bar */}
            <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
              <div
                className={cn(
                  'h-full transition-all duration-500',
                  complianceStatus === 'compliant' ? 'bg-green-500' : 
                  complianceStatus === 'non_compliant' ? 'bg-red-500' : 
                  'bg-amber-500'
                )}
                style={{ width: `${fw.compliance_percentage}%` }}
              />
            </div>
            
            <div className="mt-4 grid grid-cols-3 gap-4 text-center text-sm">
              <div className="p-2 bg-green-50 rounded">
                <div className="font-semibold text-green-700">{fw.compliant}</div>
                <div className="text-green-600 text-xs">Compliant</div>
              </div>
              <div className="p-2 bg-red-50 rounded">
                <div className="font-semibold text-red-700">{fw.non_compliant}</div>
                <div className="text-red-600 text-xs">Non-Compliant</div>
              </div>
              <div className="p-2 bg-amber-50 rounded">
                <div className="font-semibold text-amber-700">{fw.not_assessed + (fw.insufficient_evidence || 0)}</div>
                <div className="text-amber-600 text-xs">Not Assessed</div>
              </div>
            </div>
          </DashboardCard>
        );
      })}
    </div>
  );
}

// ============================================================================
// Agents Tab
// ============================================================================

function AgentsTab({ agents }: { agents: AgentStatusResponse[] }) {
  const agentConfig: Record<AgentType, { name: string; icon: any; color: string; bgColor: string }> = {
    [AgentType.VULNERABILITY_SCANNER]: { name: 'Vulnerability Scanner', icon: Shield, color: 'text-red-600', bgColor: 'bg-red-100' },
    [AgentType.CODE_ANALYZER]: { name: 'Code Analyzer', icon: Code, color: 'text-purple-600', bgColor: 'bg-purple-100' },
    [AgentType.LOG_ANALYZER]: { name: 'Log Analyzer', icon: FileText, color: 'text-blue-600', bgColor: 'bg-blue-100' },
    [AgentType.COMPLIANCE_CHECKER]: { name: 'Compliance Checker', icon: CheckCircle, color: 'text-green-600', bgColor: 'bg-green-100' },
  };

  if (agents.length === 0) {
    return (
      <DashboardCard className="flex flex-col items-center justify-center py-12">
        <Server className="h-12 w-12 text-gray-400 mb-4" />
        <h3 className="text-lg font-medium text-gray-900 mb-2">No Agent Data</h3>
        <p className="text-sm text-gray-500">Agent status not yet available</p>
      </DashboardCard>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {agents.map((agent) => {
        const config = agentConfig[agent.agent_type] || { 
          name: agent.agent_type, 
          icon: Server, 
          color: 'text-gray-600', 
          bgColor: 'bg-gray-100' 
        };
        const Icon = config.icon;

        return (
          <DashboardCard key={agent.agent_type}>
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className={cn('p-2 rounded-lg', config.bgColor)}>
                  <Icon className={cn('h-5 w-5', config.color)} />
                </div>
                <div>
                  <h3 className="font-semibold text-gray-900">{config.name}</h3>
                  <p className="text-sm text-gray-500">
                    {agent.last_run ? `Last run: ${formatDateTime(agent.last_run)}` : 'Not started'}
                  </p>
                </div>
              </div>
              <StatusBadge status={agent.status} />
            </div>

            {/* Progress for running agents */}
            {agent.status === 'running' && agent.progress !== undefined && (
              <div className="mb-4">
                <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-blue-500 transition-all duration-500"
                    style={{ width: `${agent.progress}%` }}
                  />
                </div>
                <div className="text-xs text-gray-500 mt-1">{Math.round(agent.progress)}% complete</div>
              </div>
            )}

            <div className="grid grid-cols-2 gap-4 text-sm">
              <div className="p-2 bg-gray-50 rounded">
                <div className="text-gray-500 text-xs">Findings</div>
                <div className="font-semibold">{agent.findings_count}</div>
              </div>
              <div className="p-2 bg-gray-50 rounded">
                <div className="text-gray-500 text-xs">Evidence</div>
                <div className="font-semibold">{agent.evidence_count}</div>
              </div>
            </div>

            {agent.error && (
              <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-lg">
                <div className="flex items-center gap-2 text-red-700 text-sm">
                  <AlertTriangle className="h-4 w-4" />
                  {agent.error}
                </div>
              </div>
            )}
          </DashboardCard>
        );
      })}
    </div>
  );
}
