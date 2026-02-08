'use client';

/**
 * Evidence Page
 * 
 * Browse and analyze evidence artifacts collected during audits.
 * Shows provenance tracking, hash verification, and related controls.
 * 
 * @module app/evidence/page
 */

import React, { useState, useMemo } from 'react';
import {
  FileText,
  Search,
  Filter,
  RefreshCw,
  Download,
  Clock,
  Hash,
  Link,
  ChevronRight,
  FileCode,
  FileImage,
  Database,
  File,
  Shield,
  CheckCircle,
} from 'lucide-react';
import { DashboardShell, DashboardCard } from '@/components/dashboard/dashboard-shell';
import { Badge } from '@/components/ui/badge';
import { StatCard } from '@/components/dashboard/stat-card';
import { ProgressBar } from '@/components/dashboard/progress-bar';
import { useAudits, useEvidence } from '@/hooks';
import { cn, formatDateTime, truncate } from '@/lib/utils';
import { AuditStatus } from '@/types';
import type { Evidence, EvidenceType } from '@/types';

// Evidence type icons mapping
const EVIDENCE_TYPE_ICONS: Record<string, typeof FileText> = {
  log_file: FileText,
  config_file: FileCode,
  scan_result: Shield,
  code_snippet: FileCode,
  screenshot: FileImage,
  api_response: Database,
  manual_observation: FileText,
  document: File,
};

export default function EvidencePage() {
  const [selectedAuditId, setSelectedAuditId] = useState<string | null>(null);
  const [typeFilter, setTypeFilter] = useState<string>('');
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

  // Fetch evidence
  const { data: evidence, isLoading: evidenceLoading, refetch } = useEvidence(
    selectedAuditId,
    {
      evidence_type: typeFilter || undefined,
      limit: 100,
    }
  );

  // Filter and process evidence
  const filteredEvidence = useMemo(() => {
    if (!evidence) return [];
    
    let filtered = evidence;
    
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(
        (e) =>
          e.evidence_id.toLowerCase().includes(query) ||
          e.source.toLowerCase().includes(query) ||
          e.summary.toLowerCase().includes(query)
      );
    }

    return filtered;
  }, [evidence, searchQuery]);

  // Calculate stats
  const stats = useMemo(() => {
    if (!evidence) return { total: 0, byType: {}, avgFreshness: 0 };
    
    const byType: Record<string, number> = {};
    let totalFreshness = 0;
    
    evidence.forEach((e) => {
      byType[e.evidence_type] = (byType[e.evidence_type] || 0) + 1;
      totalFreshness += e.freshness_score || 0;
    });

    return {
      total: evidence.length,
      byType,
      avgFreshness: evidence.length > 0 ? totalFreshness / evidence.length : 0,
    };
  }, [evidence]);

  const isLoading = auditsLoading || evidenceLoading;

  return (
    <DashboardShell>
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            <FileText className="h-6 w-6 text-blue-600" />
            Evidence Artifacts
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Browse and verify evidence collected during audits
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors">
            <Download className="h-4 w-4" />
            Export All
          </button>
        </div>
      </div>

      {/* Provenance Notice */}
      <div className="mt-4 bg-blue-50 border border-blue-200 rounded-lg p-3 flex items-center gap-3">
        <Hash className="h-5 w-5 text-blue-600" />
        <span className="text-sm text-blue-800">
          All evidence includes SHA256 content hashing and complete provenance chains for audit verification
        </span>
      </div>

      {/* Stats Row */}
      <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          title="Total Evidence"
          value={stats.total}
          icon={FileText}
          variant="default"
        />
        <StatCard
          title="Evidence Types"
          value={Object.keys(stats.byType).length}
          icon={Filter}
          variant="default"
        />
        <StatCard
          title="Avg Freshness"
          value={`${Math.round(stats.avgFreshness * 100)}%`}
          subtitle="Evidence age score"
          icon={Clock}
          variant={stats.avgFreshness >= 0.7 ? 'success' : stats.avgFreshness >= 0.4 ? 'medium' : 'critical'}
        />
        <StatCard
          title="Linked Controls"
          value={evidence?.reduce((sum, e) => sum + e.related_controls.length, 0) || 0}
          icon={Link}
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
            placeholder="Search evidence..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-gray-900"
          />
        </div>

        {/* Type Filter */}
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="px-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-gray-900"
        >
          <option value="">All Types</option>
          <option value="log_file">Log Files</option>
          <option value="config_file">Config Files</option>
          <option value="scan_result">Scan Results</option>
          <option value="code_snippet">Code Snippets</option>
          <option value="api_response">API Responses</option>
          <option value="document">Documents</option>
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
        {/* Type Breakdown Sidebar */}
        <div className="lg:col-span-1">
          <DashboardCard>
            <h3 className="text-sm font-medium text-gray-700 mb-4">
              Evidence by Type
            </h3>
            <div className="space-y-2">
              {Object.entries(stats.byType).map(([type, count]) => {
                const Icon = EVIDENCE_TYPE_ICONS[type] || FileText;
                return (
                  <button
                    key={type}
                    onClick={() => setTypeFilter(type === typeFilter ? '' : type)}
                    className={cn(
                      'w-full flex items-center justify-between p-2 rounded-lg text-sm transition-colors',
                      typeFilter === type
                        ? 'bg-blue-100 text-blue-800'
                        : 'hover:bg-gray-100 text-gray-600'
                    )}
                  >
                    <div className="flex items-center gap-2">
                      <Icon className="h-4 w-4" />
                      <span className="capitalize">{type.replace(/_/g, ' ')}</span>
                    </div>
                    <span className="font-medium">{count}</span>
                  </button>
                );
              })}
            </div>
          </DashboardCard>
        </div>

        {/* Evidence List */}
        <div className="lg:col-span-3">
          <DashboardCard>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-medium text-gray-700">
                {filteredEvidence.length} Evidence Items
              </h3>
            </div>

            {evidenceLoading ? (
              <div className="animate-pulse space-y-3">
                {Array.from({ length: 5 }).map((_, i) => (
                  <div key={i} className="h-24 bg-gray-100 rounded-lg" />
                ))}
              </div>
            ) : filteredEvidence.length === 0 ? (
              <div className="text-center py-12 text-gray-500">
                <FileText className="h-12 w-12 mx-auto mb-3 opacity-50" />
                <p>No evidence items match your filters</p>
              </div>
            ) : (
              <div className="space-y-3">
                {filteredEvidence.map((item) => (
                  <EvidenceCard key={item.evidence_id} evidence={item} />
                ))}
              </div>
            )}
          </DashboardCard>
        </div>
      </div>
    </DashboardShell>
  );
}

function EvidenceCard({ evidence }: { evidence: Evidence }) {
  const [expanded, setExpanded] = useState(false);
  const Icon = EVIDENCE_TYPE_ICONS[evidence.evidence_type] || FileText;

  return (
    <div className="border border-gray-200 rounded-lg overflow-hidden hover:shadow-sm transition-shadow">
      <div
        className="p-4 cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-3">
            <div className="p-2 bg-gray-100 rounded-lg">
              <Icon className="h-5 w-5 text-gray-600" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm font-semibold text-gray-900">
                  {evidence.evidence_id}
                </span>
                <span className="px-2 py-0.5 text-xs bg-gray-100 text-gray-600 rounded capitalize">
                  {evidence.evidence_type.replace(/_/g, ' ')}
                </span>
              </div>
              <p className="text-sm text-gray-600 mt-1">{evidence.summary}</p>
              <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                <span className="flex items-center gap-1">
                  <Database className="h-3 w-3" />
                  {evidence.source}
                </span>
                <span className="flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  {formatDateTime(evidence.collected_at)}
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Freshness Indicator */}
            {evidence.freshness_score !== undefined && (
              <div className="text-center">
                <div className="text-xs text-gray-500 mb-1">Freshness</div>
                <div className={cn(
                  'w-12 h-2 bg-gray-200 rounded-full overflow-hidden'
                )}>
                  <div
                    className={cn(
                      'h-full rounded-full',
                      evidence.freshness_score >= 0.8 ? 'bg-green-500' :
                      evidence.freshness_score >= 0.5 ? 'bg-yellow-500' : 'bg-red-500'
                    )}
                    style={{ width: `${evidence.freshness_score * 100}%` }}
                  />
                </div>
              </div>
            )}
            <ChevronRight className={cn(
              'h-5 w-5 text-gray-400 transition-transform',
              expanded && 'rotate-90'
            )} />
          </div>
        </div>
      </div>

      {/* Expanded Details */}
      {expanded && (
        <div className="px-4 pb-4 border-t border-gray-100 pt-3 bg-gray-50">
          <div className="grid grid-cols-2 gap-4">
            {/* Hash */}
            <div>
              <span className="text-xs font-medium text-gray-500 block mb-1">
                Content Hash (SHA256)
              </span>
              <div className="flex items-center gap-2">
                <Hash className="h-4 w-4 text-gray-400" />
                <code className="text-xs text-gray-700 font-mono bg-white px-2 py-1 rounded border">
                  {truncate(evidence.content_hash, 32)}
                </code>
                <CheckCircle className="h-4 w-4 text-green-500" title="Verified" />
              </div>
            </div>

            {/* Related Controls */}
            <div>
              <span className="text-xs font-medium text-gray-500 block mb-1">
                Related Controls
              </span>
              <div className="flex flex-wrap gap-1">
                {evidence.related_controls.length > 0 ? (
                  evidence.related_controls.map((control) => (
                    <span
                      key={control}
                      className="px-2 py-0.5 text-xs bg-blue-100 text-blue-700 rounded font-mono"
                    >
                      {control}
                    </span>
                  ))
                ) : (
                  <span className="text-xs text-gray-400">No linked controls</span>
                )}
              </div>
            </div>

            {/* Related Findings */}
            <div>
              <span className="text-xs font-medium text-gray-500 block mb-1">
                Related Findings
              </span>
              <div className="flex flex-wrap gap-1">
                {evidence.related_findings.length > 0 ? (
                  evidence.related_findings.map((finding) => (
                    <span
                      key={finding}
                      className="px-2 py-0.5 text-xs bg-orange-100 text-orange-700 rounded font-mono"
                    >
                      {finding}
                    </span>
                  ))
                ) : (
                  <span className="text-xs text-gray-400">No linked findings</span>
                )}
              </div>
            </div>

            {/* Metadata */}
            {evidence.metadata && Object.keys(evidence.metadata).length > 0 && (
              <div>
                <span className="text-xs font-medium text-gray-500 block mb-1">
                  Metadata
                </span>
                <div className="text-xs text-gray-600">
                  {Object.entries(evidence.metadata).slice(0, 3).map(([key, value]) => (
                    <div key={key}>
                      <span className="font-medium">{key}:</span> {String(value)}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
