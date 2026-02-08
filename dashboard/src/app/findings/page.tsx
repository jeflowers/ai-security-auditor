'use client';

/**
 * Findings Page
 * 
 * Comprehensive view of all security findings across audits with
 * filtering, sorting, and detailed analysis capabilities.
 * 
 * @module app/findings/page
 */

import React, { useState, useMemo } from 'react';
import {
  AlertTriangle,
  Search,
  Filter,
  Download,
  ChevronDown,
  ExternalLink,
  RefreshCw,
  Shield,
  Code,
  FileText,
  CheckSquare,
} from 'lucide-react';
import { DashboardShell, DashboardCard } from '@/components/dashboard/dashboard-shell';
import { SeverityBadge, Badge } from '@/components/ui/badge';
import { SeverityChart, SeverityBarChart } from '@/components/dashboard/severity-chart';
import { FindingsTable } from '@/components/dashboard/findings-table';
import { StatCard } from '@/components/dashboard/stat-card';
import { useAudits, useFindings } from '@/hooks';
import { cn, sortBySeverity, calculateSeverityDistribution, severityToChartData } from '@/lib/utils';
import { AuditStatus, Severity } from '@/types';
import type { Finding, AgentType } from '@/types';

export default function FindingsPage() {
  const [selectedAuditId, setSelectedAuditId] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<Severity | ''>('');
  const [agentFilter, setAgentFilter] = useState<AgentType | ''>('');
  const [searchQuery, setSearchQuery] = useState('');
  const [viewMode, setViewMode] = useState<'table' | 'cards'>('table');

  // Fetch audits for dropdown
  const { data: audits, isLoading: auditsLoading } = useAudits({
    limit: 50,
    autoRefresh: false,
  });

  // Auto-select most recent completed audit if none selected
  React.useEffect(() => {
    if (audits && audits.length > 0 && !selectedAuditId) {
      const completedAudit = audits.find(a => a.status === AuditStatus.COMPLETED);
      setSelectedAuditId(completedAudit?.audit_id || audits[0].audit_id);
    }
  }, [audits, selectedAuditId]);

  // Fetch findings for selected audit
  const { data: findingsData, isLoading: findingsLoading, refetch } = useFindings(
    selectedAuditId,
    {
      severity: severityFilter || undefined,
      agent: agentFilter || undefined,
      limit: 100,
    }
  );

  // Filter and process findings
  const processedFindings = useMemo(() => {
    if (!findingsData?.findings) return [];
    
    let filtered = findingsData.findings;
    
    // Apply search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(
        (f) =>
          f.title.toLowerCase().includes(query) ||
          f.description.toLowerCase().includes(query) ||
          f.cwe_id?.toLowerCase().includes(query) ||
          f.owasp_category?.toLowerCase().includes(query)
      );
    }

    return sortBySeverity(filtered);
  }, [findingsData, searchQuery]);

  // Calculate stats
  const stats = useMemo(() => {
    if (!findingsData) {
      return {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      };
    }
    const bySev = findingsData.by_severity;
    return {
      total: findingsData.total,
      critical: bySev[Severity.CRITICAL] || 0,
      high: bySev[Severity.HIGH] || 0,
      medium: bySev[Severity.MEDIUM] || 0,
      low: bySev[Severity.LOW] || 0,
    };
  }, [findingsData]);

  const chartData = useMemo(() => {
    if (!findingsData?.by_severity) return [];
    return severityToChartData(findingsData.by_severity);
  }, [findingsData]);

  const isLoading = auditsLoading || findingsLoading;

  return (
    <DashboardShell>
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            <AlertTriangle className="h-6 w-6 text-orange-500" />
            Security Findings
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            View and analyze security findings across all audits
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors">
            <Download className="h-4 w-4" />
            Export
          </button>
        </div>
      </div>

      {/* Stats Row */}
      <div className="mt-6 grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatCard
          title="Total Findings"
          value={stats.total}
          icon={AlertTriangle}
          variant="default"
        />
        <StatCard
          title="Critical"
          value={stats.critical}
          icon={AlertTriangle}
          variant="critical"
        />
        <StatCard
          title="High"
          value={stats.high}
          icon={AlertTriangle}
          variant="high"
        />
        <StatCard
          title="Medium"
          value={stats.medium}
          icon={AlertTriangle}
          variant="medium"
        />
        <StatCard
          title="Low"
          value={stats.low}
          icon={AlertTriangle}
          variant="default"
        />
      </div>

      {/* Filters Row */}
      <div className="mt-6 flex flex-wrap gap-4">
        {/* Audit Selector */}
        <select
          value={selectedAuditId || ''}
          onChange={(e) => setSelectedAuditId(e.target.value || null)}
          className="px-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-gray-900"
          disabled={auditsLoading}
        >
          <option value="">Select Audit</option>
          {audits?.map((audit) => (
            <option key={audit.audit_id} value={audit.audit_id}>
              {audit.audit_id} - {audit.target}
            </option>
          ))}
        </select>

        {/* Search */}
        <div className="relative flex-1 min-w-64 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
          <input
            type="search"
            placeholder="Search findings (title, CWE, OWASP)..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-gray-900"
          />
        </div>

        {/* Severity Filter */}
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
          <option value="info">Info</option>
        </select>

        {/* Agent Filter */}
        <select
          value={agentFilter}
          onChange={(e) => setAgentFilter(e.target.value as AgentType | '')}
          className="px-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-gray-900"
        >
          <option value="">All Agents</option>
          <option value="vulnerability_scanner">Vulnerability Scanner</option>
          <option value="code_analyzer">Code Analyzer</option>
          <option value="log_analyzer">Log Analyzer</option>
          <option value="compliance_checker">Compliance Checker</option>
        </select>

        {/* Refresh */}
        <button
          onClick={() => refetch()}
          disabled={isLoading}
          className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={cn('h-4 w-4', isLoading && 'animate-spin')} />
        </button>
      </div>

      {/* Content Grid */}
      <div className="mt-6 grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Chart Sidebar */}
        <div className="lg:col-span-1 space-y-6">
          <DashboardCard>
            <h3 className="text-sm font-medium text-gray-700 mb-4">
              Severity Distribution
            </h3>
            <SeverityChart data={chartData} size="sm" />
          </DashboardCard>

          <DashboardCard>
            <h3 className="text-sm font-medium text-gray-700 mb-4">
              By Agent
            </h3>
            <AgentBreakdown findings={processedFindings} />
          </DashboardCard>
        </div>

        {/* Findings Table */}
        <div className="lg:col-span-3">
          <DashboardCard>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-medium text-gray-700">
                {processedFindings.length} Findings
              </h3>
              <div className="flex gap-1">
                <button
                  onClick={() => setViewMode('table')}
                  className={cn(
                    'px-3 py-1 text-xs rounded',
                    viewMode === 'table' ? 'bg-gray-900 text-white' : 'bg-gray-100 text-gray-600'
                  )}
                >
                  Table
                </button>
                <button
                  onClick={() => setViewMode('cards')}
                  className={cn(
                    'px-3 py-1 text-xs rounded',
                    viewMode === 'cards' ? 'bg-gray-900 text-white' : 'bg-gray-100 text-gray-600'
                  )}
                >
                  Cards
                </button>
              </div>
            </div>

            {viewMode === 'table' ? (
              <FindingsTable
                findings={processedFindings}
                isLoading={isLoading}
              />
            ) : (
              <FindingsCardView findings={processedFindings} />
            )}
          </DashboardCard>
        </div>
      </div>
    </DashboardShell>
  );
}

function AgentBreakdown({ findings }: { findings: Finding[] }) {
  const agentCounts = useMemo(() => {
    const counts: Record<string, number> = {
      vulnerability_scanner: 0,
      code_analyzer: 0,
      log_analyzer: 0,
      compliance_checker: 0,
    };
    findings.forEach((f) => {
      if (counts[f.agent_type] !== undefined) {
        counts[f.agent_type]++;
      }
    });
    return counts;
  }, [findings]);

  const agents = [
    { type: 'vulnerability_scanner', label: 'Vuln Scanner', icon: Shield },
    { type: 'code_analyzer', label: 'Code Analyzer', icon: Code },
    { type: 'log_analyzer', label: 'Log Analyzer', icon: FileText },
    { type: 'compliance_checker', label: 'Compliance', icon: CheckSquare },
  ];

  return (
    <div className="space-y-2">
      {agents.map(({ type, label, icon: Icon }) => (
        <div key={type} className="flex items-center justify-between text-sm">
          <div className="flex items-center gap-2 text-gray-600">
            <Icon className="h-4 w-4" />
            {label}
          </div>
          <span className="font-medium">{agentCounts[type]}</span>
        </div>
      ))}
    </div>
  );
}

function FindingsCardView({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return (
      <div className="text-center py-8 text-gray-500">
        No findings match your filters
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {findings.map((finding) => (
        <div
          key={finding.finding_id}
          className="p-4 border border-gray-200 rounded-lg hover:shadow-sm transition-shadow"
        >
          <div className="flex items-start justify-between">
            <div className="flex items-start gap-3">
              <SeverityBadge severity={finding.severity} />
              <div>
                <h4 className="font-medium text-gray-900">{finding.title}</h4>
                <p className="text-sm text-gray-500 mt-1 line-clamp-2">
                  {finding.description}
                </p>
                <div className="flex items-center gap-3 mt-2 text-xs text-gray-400">
                  {finding.cwe_id && (
                    <span className="bg-gray-100 px-2 py-0.5 rounded">
                      {finding.cwe_id}
                    </span>
                  )}
                  {finding.owasp_category && (
                    <span className="bg-gray-100 px-2 py-0.5 rounded">
                      {finding.owasp_category}
                    </span>
                  )}
                  <span className="capitalize">
                    {finding.agent_type.replace(/_/g, ' ')}
                  </span>
                </div>
              </div>
            </div>
            <button className="p-2 hover:bg-gray-100 rounded transition-colors">
              <ExternalLink className="h-4 w-4 text-gray-400" />
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}
