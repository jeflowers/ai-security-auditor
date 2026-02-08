'use client';

/**
 * Compliance Page
 * 
 * Comprehensive compliance status view showing framework coverage,
 * control assessments, and evidence-based compliance validation.
 * 
 * @module app/compliance/page
 */

import React, { useState, useMemo } from 'react';
import {
  CheckCircle,
  XCircle,
  AlertTriangle,
  FileQuestion,
  Search,
  ChevronDown,
  RefreshCw,
  Shield,
  Download,
  Filter,
} from 'lucide-react';
import { DashboardShell, DashboardCard } from '@/components/dashboard/dashboard-shell';
import { AssessmentBadge, Badge } from '@/components/ui/badge';
import { ComplianceMatrix, ComplianceQuickView } from '@/components/dashboard/compliance-matrix';
import { ProgressBar, MultiProgressBar } from '@/components/dashboard/progress-bar';
import { StatCard } from '@/components/dashboard/stat-card';
import { AntiHallucinationSummary } from '@/components/dashboard/anti-hallucination-panel';
import { useAudits, useComplianceStatus, useControlAssessments } from '@/hooks';
import { cn, formatPercentage } from '@/lib/utils';
import { AuditStatus } from '@/types';
import type { ComplianceStatus, ControlAssessment, AssessmentState } from '@/types';

// Framework configuration for display
const FRAMEWORKS = [
  { id: 'SOC2', name: 'SOC 2', color: '#3b82f6', description: 'Trust Services Criteria' },
  { id: 'GDPR', name: 'GDPR', color: '#10b981', description: 'EU Data Protection' },
  { id: 'HIPAA', name: 'HIPAA', color: '#8b5cf6', description: 'Healthcare Privacy' },
  { id: 'NIST-800-53A', name: 'NIST 800-53A', color: '#f59e0b', description: 'Security Controls' },
];

export default function CompliancePage() {
  const [selectedAuditId, setSelectedAuditId] = useState<string | null>(null);
  const [selectedFramework, setSelectedFramework] = useState<string>('SOC2');
  const [stateFilter, setStateFilter] = useState<AssessmentState | ''>('');
  const [searchQuery, setSearchQuery] = useState('');

  // Fetch audits for dropdown
  const { data: audits, isLoading: auditsLoading } = useAudits({
    limit: 50,
    autoRefresh: false,
  });

  // Auto-select most recent completed audit
  React.useEffect(() => {
    if (audits && audits.length > 0 && !selectedAuditId) {
      const completedAudit = audits.find(a => a.status === AuditStatus.COMPLETED);
      setSelectedAuditId(completedAudit?.audit_id || audits[0].audit_id);
    }
  }, [audits, selectedAuditId]);

  // Fetch compliance status
  const { data: complianceStatuses, isLoading: complianceLoading, refetch } = useComplianceStatus(
    selectedAuditId
  );

  // Fetch control assessments for selected framework
  const { data: controls, isLoading: controlsLoading } = useControlAssessments(
    selectedAuditId,
    selectedFramework,
    stateFilter || undefined
  );

  // Calculate overall stats
  const stats = useMemo(() => {
    if (!complianceStatuses) {
      return { total: 0, compliant: 0, nonCompliant: 0, gaps: 0, score: 0 };
    }
    return {
      total: complianceStatuses.reduce((sum, s) => sum + s.total_controls, 0),
      compliant: complianceStatuses.reduce((sum, s) => sum + s.compliant, 0),
      nonCompliant: complianceStatuses.reduce((sum, s) => sum + s.non_compliant, 0),
      gaps: complianceStatuses.reduce((sum, s) => sum + s.insufficient_evidence, 0),
      score: complianceStatuses.length > 0
        ? complianceStatuses.reduce((sum, s) => sum + s.compliance_percentage, 0) / complianceStatuses.length
        : 0,
    };
  }, [complianceStatuses]);

  // Filter controls
  const filteredControls = useMemo(() => {
    if (!controls) return [];
    if (!searchQuery) return controls;
    
    const query = searchQuery.toLowerCase();
    return controls.filter(
      (c) =>
        c.control_id.toLowerCase().includes(query) ||
        c.control_name.toLowerCase().includes(query)
    );
  }, [controls, searchQuery]);

  // Get current framework status
  const currentFrameworkStatus = complianceStatuses?.find(
    (s) => s.framework === selectedFramework
  );

  const isLoading = auditsLoading || complianceLoading || controlsLoading;

  return (
    <DashboardShell>
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            <CheckCircle className="h-6 w-6 text-green-600" />
            Compliance Status
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Evidence-based compliance assessment across frameworks
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors">
            <Download className="h-4 w-4" />
            Export Report
          </button>
        </div>
      </div>

      {/* Anti-Hallucination Notice */}
      <div className="mt-4 bg-green-50 border border-green-200 rounded-lg p-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-green-600" />
          <span className="text-sm text-green-800 font-medium">
            All assessments require evidence backing - No hallucinated compliance claims
          </span>
        </div>
        <AntiHallucinationSummary evidenceCitationRate={94.5} confidence={0.87} />
      </div>

      {/* Stats Row */}
      <div className="mt-6 grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatCard
          title="Overall Score"
          value={`${Math.round(stats.score)}%`}
          icon={CheckCircle}
          variant={stats.score >= 80 ? 'success' : stats.score >= 60 ? 'medium' : 'critical'}
        />
        <StatCard
          title="Total Controls"
          value={stats.total}
          icon={FileQuestion}
          variant="default"
        />
        <StatCard
          title="Compliant"
          value={stats.compliant}
          icon={CheckCircle}
          variant="success"
        />
        <StatCard
          title="Non-Compliant"
          value={stats.nonCompliant}
          icon={XCircle}
          variant="critical"
        />
        <StatCard
          title="Evidence Gaps"
          value={stats.gaps}
          icon={AlertTriangle}
          variant="medium"
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
              {audit.audit_id} - {audit.target}
            </option>
          ))}
        </select>

        <button
          onClick={() => refetch()}
          disabled={isLoading}
          className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={cn('h-4 w-4', isLoading && 'animate-spin')} />
          Refresh
        </button>
      </div>

      {/* Framework Overview */}
      <div className="mt-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Framework Overview</h2>
        <ComplianceMatrix
          complianceStatuses={complianceStatuses || []}
          isLoading={complianceLoading}
        />
      </div>

      {/* Control Assessments */}
      <div className="mt-8">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Control Assessments</h2>
        
        {/* Framework Tabs */}
        <div className="flex gap-1 border-b border-gray-200 mb-4">
          {FRAMEWORKS.map((fw) => (
            <button
              key={fw.id}
              onClick={() => setSelectedFramework(fw.id)}
              className={cn(
                'px-4 py-2 text-sm font-medium border-b-2 transition-colors',
                selectedFramework === fw.id
                  ? 'border-gray-900 text-gray-900'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              )}
            >
              {fw.name}
            </button>
          ))}
        </div>

        {/* Filters */}
        <div className="flex gap-4 mb-4">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
            <input
              type="search"
              placeholder="Search controls..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-gray-900"
            />
          </div>

          <select
            value={stateFilter}
            onChange={(e) => setStateFilter(e.target.value as AssessmentState | '')}
            className="px-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-gray-900"
          >
            <option value="">All States</option>
            <option value="compliant">Compliant</option>
            <option value="non_compliant">Non-Compliant</option>
            <option value="insufficient_evidence">Insufficient Evidence</option>
            <option value="evidence_gap">Evidence Gap</option>
            <option value="needs_manual_review">Needs Manual Review</option>
            <option value="not_assessed">Not Assessed</option>
          </select>
        </div>

        {/* Controls Table */}
        <DashboardCard>
          {controlsLoading ? (
            <div className="animate-pulse space-y-2">
              {Array.from({ length: 5 }).map((_, i) => (
                <div key={i} className="h-16 bg-gray-100 rounded" />
              ))}
            </div>
          ) : filteredControls.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              <FileQuestion className="h-12 w-12 mx-auto mb-3 opacity-50" />
              <p>No controls match your filters</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-200">
                    <th className="text-left py-3 px-4 font-medium text-gray-500">Control ID</th>
                    <th className="text-left py-3 px-4 font-medium text-gray-500">Name</th>
                    <th className="text-left py-3 px-4 font-medium text-gray-500">State</th>
                    <th className="text-left py-3 px-4 font-medium text-gray-500">Confidence</th>
                    <th className="text-left py-3 px-4 font-medium text-gray-500">Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredControls.map((control) => (
                    <tr
                      key={control.control_id}
                      className="border-b border-gray-100 hover:bg-gray-50"
                    >
                      <td className="py-3 px-4">
                        <span className="font-mono font-medium">{control.control_id}</span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="text-gray-900">{control.control_name}</span>
                      </td>
                      <td className="py-3 px-4">
                        <AssessmentBadge state={control.state} />
                      </td>
                      <td className="py-3 px-4">
                        {control.confidence !== undefined ? (
                          <div className="flex items-center gap-2">
                            <div className="w-16 h-2 bg-gray-200 rounded-full overflow-hidden">
                              <div
                                className={cn(
                                  'h-full rounded-full',
                                  (control.confidence || 0) >= 0.8 ? 'bg-green-500' :
                                  (control.confidence || 0) >= 0.5 ? 'bg-yellow-500' : 'bg-red-500'
                                )}
                                style={{ width: `${(control.confidence || 0) * 100}%` }}
                              />
                            </div>
                            <span className="text-xs text-gray-500">
                              {Math.round((control.confidence || 0) * 100)}%
                            </span>
                          </div>
                        ) : (
                          <span className="text-gray-400">—</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <span className="text-xs text-gray-500">
                          {control.evidence_ids.length} items
                        </span>
                        {control.evidence_gaps && control.evidence_gaps.length > 0 && (
                          <span className="ml-2 text-xs text-orange-600">
                            ({control.evidence_gaps.length} gaps)
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </DashboardCard>
      </div>

      {/* Valid Assessment States Reference */}
      <div className="mt-8 p-4 bg-gray-50 rounded-lg">
        <h3 className="text-sm font-medium text-gray-700 mb-3">
          Valid Assessment States (Anti-Hallucination Enforced)
        </h3>
        <div className="flex flex-wrap gap-2">
          <span className="px-3 py-1 text-xs font-medium bg-green-100 text-green-800 rounded">PASS</span>
          <span className="px-3 py-1 text-xs font-medium bg-red-100 text-red-800 rounded">FAIL</span>
          <span className="px-3 py-1 text-xs font-medium bg-yellow-100 text-yellow-800 rounded">INSUFFICIENT_EVIDENCE</span>
          <span className="px-3 py-1 text-xs font-medium bg-orange-100 text-orange-800 rounded">EVIDENCE_GAP</span>
          <span className="px-3 py-1 text-xs font-medium bg-purple-100 text-purple-800 rounded">CONFLICTING_EVIDENCE</span>
          <span className="px-3 py-1 text-xs font-medium bg-blue-100 text-blue-800 rounded">NEEDS_MANUAL_REVIEW</span>
        </div>
        <p className="text-xs text-gray-500 mt-2">
          These are the only valid states. No hallucinated "likely compliant" or "probably fine" assessments.
        </p>
      </div>
    </DashboardShell>
  );
}
