'use client';

/**
 * Audits List Page
 * 
 * Displays a list of all audits with filtering and search capabilities.
 * 
 * @module app/audits/page
 */

import React, { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  Plus,
  Search,
  Filter,
  RefreshCw,
  ChevronRight,
  Clock,
  Target,
  CheckCircle,
  XCircle,
  Loader2,
  FileSearch,
  Globe,
  FolderOpen,
  AlertTriangle,
} from 'lucide-react';
import { DashboardShell, DashboardCard } from '@/components/dashboard/dashboard-shell';
import { StatusBadge, Badge } from '@/components/ui/badge';
import { Modal, ModalFooter } from '@/components/ui/modal';
import { useAudits } from '@/hooks';
import { api } from '@/lib/api-client';
import { cn, formatDateTime } from '@/lib/utils';
import { AgentType, AuditStatus } from '@/types';
import type { AuditResponse, AuditRequest } from '@/types';

// Available frameworks for selection
const FRAMEWORKS = [
  { id: 'soc2', name: 'SOC 2', description: 'Service Organization Control 2' },
  { id: 'gdpr', name: 'GDPR', description: 'General Data Protection Regulation' },
  { id: 'hipaa', name: 'HIPAA', description: 'Health Insurance Portability and Accountability' },
  { id: 'nist_800_53a', name: 'NIST 800-53A', description: 'Security and Privacy Controls' },
];

// Available agents
const AGENTS = [
  { type: AgentType.VULNERABILITY_SCANNER, name: 'Vulnerability Scanner', description: 'OWASP ZAP scanning' },
  { type: AgentType.CODE_ANALYZER, name: 'Code Analyzer', description: 'Static code analysis' },
  { type: AgentType.LOG_ANALYZER, name: 'Log Analyzer', description: 'Log pattern analysis' },
  { type: AgentType.COMPLIANCE_CHECKER, name: 'Compliance Checker', description: 'Framework validation' },
];

export default function AuditsPage() {
  const router = useRouter();
  const [statusFilter, setStatusFilter] = useState<AuditStatus | ''>('');
  const [searchQuery, setSearchQuery] = useState('');
  const [isNewAuditOpen, setIsNewAuditOpen] = useState(false);
  
  const { data: audits, isLoading, refetch } = useAudits({
    status: statusFilter || undefined,
    autoRefresh: true,
    limit: 50,
  });

  const filteredAudits = React.useMemo(() => {
    if (!audits) return [];
    if (!searchQuery) return audits;
    
    const query = searchQuery.toLowerCase();
    return audits.filter(
      (a) =>
        a.audit_id.toLowerCase().includes(query) ||
        a.target.toLowerCase().includes(query)
    );
  }, [audits, searchQuery]);

  return (
    <DashboardShell>
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Audits</h1>
          <p className="text-sm text-gray-500 mt-1">
            View and manage security audits
          </p>
        </div>
        <button 
          onClick={() => setIsNewAuditOpen(true)}
          className="flex items-center gap-2 px-4 py-2 bg-gray-900 text-white rounded-lg hover:bg-gray-800 transition-colors"
        >
          <Plus className="h-4 w-4" />
          New Audit
        </button>
      </div>

      {/* Filters Row */}
      <div className="mt-6 flex flex-col md:flex-row gap-4">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
          <input
            type="search"
            placeholder="Search by audit ID or target..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-gray-900"
          />
        </div>

        {/* Status Filter */}
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as AuditStatus | '')}
          className="px-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-gray-900"
        >
          <option value="">All Statuses</option>
          <option value="pending">Pending</option>
          <option value="running">Running</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
          <option value="cancelled">Cancelled</option>
        </select>

        {/* Refresh */}
        <button
          onClick={() => refetch()}
          disabled={isLoading}
          className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={cn('h-4 w-4', isLoading && 'animate-spin')} />
          Refresh
        </button>
      </div>

      {/* Audits List */}
      <div className="mt-6 space-y-3">
        {isLoading ? (
          Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="h-20 bg-gray-100 rounded-lg animate-pulse" />
          ))
        ) : filteredAudits.length === 0 ? (
          <DashboardCard className="flex flex-col items-center justify-center py-12">
            <FileSearch className="h-12 w-12 text-gray-400 mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">No audits found</h3>
            <p className="text-sm text-gray-500 mb-4">
              {searchQuery || statusFilter
                ? 'Try adjusting your filters'
                : 'Create a new audit to get started'}
            </p>
            {!searchQuery && !statusFilter && (
              <button
                onClick={() => setIsNewAuditOpen(true)}
                className="flex items-center gap-2 px-4 py-2 bg-gray-900 text-white rounded-lg hover:bg-gray-800 transition-colors"
              >
                <Plus className="h-4 w-4" />
                Create First Audit
              </button>
            )}
          </DashboardCard>
        ) : (
          filteredAudits.map((audit) => (
            <AuditCard key={audit.audit_id} audit={audit} />
          ))
        )}
      </div>

      {/* New Audit Modal */}
      <NewAuditModal
        isOpen={isNewAuditOpen}
        onClose={() => setIsNewAuditOpen(false)}
        onSuccess={(auditId) => {
          setIsNewAuditOpen(false);
          refetch();
          // Navigate to the new audit
          router.push(`/audits/${auditId}`);
        }}
      />
    </DashboardShell>
  );
}

// ============================================================================
// New Audit Modal Component
// ============================================================================

interface NewAuditModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (auditId: string) => void;
}

function NewAuditModal({ isOpen, onClose, onSuccess }: NewAuditModalProps) {
  const [target, setTarget] = useState('');
  const [targetType, setTargetType] = useState<'url' | 'path'>('url');
  const [selectedFrameworks, setSelectedFrameworks] = useState<string[]>(['soc2']);
  const [selectedAgents, setSelectedAgents] = useState<AgentType[]>([
    AgentType.VULNERABILITY_SCANNER,
    AgentType.CODE_ANALYZER,
    AgentType.LOG_ANALYZER,
    AgentType.COMPLIANCE_CHECKER,
  ]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    // Validation
    if (!target.trim()) {
      setError('Please enter a target URL or path');
      return;
    }
    if (selectedFrameworks.length === 0) {
      setError('Please select at least one compliance framework');
      return;
    }
    if (selectedAgents.length === 0) {
      setError('Please select at least one agent');
      return;
    }

    setIsSubmitting(true);

    try {
      const request: AuditRequest = {
        target: target.trim(),
        frameworks: selectedFrameworks,
        agents: selectedAgents,
        config: {
          target_type: targetType,
        },
      };

      const response = await api.createAudit(request);
      onSuccess(response.audit_id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create audit');
    } finally {
      setIsSubmitting(false);
    }
  };

  const toggleFramework = (id: string) => {
    setSelectedFrameworks((prev) =>
      prev.includes(id) ? prev.filter((f) => f !== id) : [...prev, id]
    );
  };

  const toggleAgent = (type: AgentType) => {
    setSelectedAgents((prev) =>
      prev.includes(type) ? prev.filter((a) => a !== type) : [...prev, type]
    );
  };

  const handleClose = () => {
    // Reset form
    setTarget('');
    setTargetType('url');
    setSelectedFrameworks(['soc2']);
    setSelectedAgents([
      AgentType.VULNERABILITY_SCANNER,
      AgentType.CODE_ANALYZER,
      AgentType.LOG_ANALYZER,
      AgentType.COMPLIANCE_CHECKER,
    ]);
    setError(null);
    onClose();
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      title="Create New Audit"
      description="Configure and start a new security audit"
      size="lg"
    >
      <form onSubmit={handleSubmit}>
        {/* Error Display */}
        {error && (
          <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg flex items-start gap-2">
            <AlertTriangle className="h-5 w-5 text-red-600 flex-shrink-0 mt-0.5" />
            <p className="text-sm text-red-700">{error}</p>
          </div>
        )}

        {/* Target Type Selection */}
        <div className="mb-4">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Target Type
          </label>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => setTargetType('url')}
              className={cn(
                'flex items-center gap-2 px-4 py-2 rounded-lg border transition-colors',
                targetType === 'url'
                  ? 'bg-gray-900 text-white border-gray-900'
                  : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
              )}
            >
              <Globe className="h-4 w-4" />
              URL
            </button>
            <button
              type="button"
              onClick={() => setTargetType('path')}
              className={cn(
                'flex items-center gap-2 px-4 py-2 rounded-lg border transition-colors',
                targetType === 'path'
                  ? 'bg-gray-900 text-white border-gray-900'
                  : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
              )}
            >
              <FolderOpen className="h-4 w-4" />
              File Path
            </button>
          </div>
        </div>

        {/* Target Input */}
        <div className="mb-6">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            {targetType === 'url' ? 'Target URL' : 'Target Path'}
          </label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={
              targetType === 'url'
                ? 'https://example.com'
                : '/path/to/project'
            }
            className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-gray-900"
          />
          <p className="mt-1 text-xs text-gray-500">
            {targetType === 'url'
              ? 'Enter the URL to scan for vulnerabilities'
              : 'Enter the path to the codebase or logs directory'}
          </p>
        </div>

        {/* Framework Selection */}
        <div className="mb-6">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Compliance Frameworks
          </label>
          <div className="grid grid-cols-2 gap-2">
            {FRAMEWORKS.map((fw) => (
              <button
                key={fw.id}
                type="button"
                onClick={() => toggleFramework(fw.id)}
                className={cn(
                  'p-3 rounded-lg border text-left transition-colors',
                  selectedFrameworks.includes(fw.id)
                    ? 'bg-green-50 border-green-500 text-green-700'
                    : 'bg-white border-gray-200 hover:bg-gray-50'
                )}
              >
                <div className="flex items-center justify-between">
                  <span className="font-medium">{fw.name}</span>
                  {selectedFrameworks.includes(fw.id) && (
                    <CheckCircle className="h-4 w-4 text-green-600" />
                  )}
                </div>
                <p className="text-xs text-gray-500 mt-1">{fw.description}</p>
              </button>
            ))}
          </div>
        </div>

        {/* Agent Selection */}
        <div className="mb-6">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Security Agents
          </label>
          <div className="grid grid-cols-2 gap-2">
            {AGENTS.map((agent) => (
              <button
                key={agent.type}
                type="button"
                onClick={() => toggleAgent(agent.type)}
                className={cn(
                  'p-3 rounded-lg border text-left transition-colors',
                  selectedAgents.includes(agent.type)
                    ? 'bg-blue-50 border-blue-500 text-blue-700'
                    : 'bg-white border-gray-200 hover:bg-gray-50'
                )}
              >
                <div className="flex items-center justify-between">
                  <span className="font-medium text-sm">{agent.name}</span>
                  {selectedAgents.includes(agent.type) && (
                    <CheckCircle className="h-4 w-4 text-blue-600" />
                  )}
                </div>
                <p className="text-xs text-gray-500 mt-1">{agent.description}</p>
              </button>
            ))}
          </div>
        </div>

        {/* Anti-Hallucination Notice */}
        <div className="mb-4 p-3 bg-amber-50 border border-amber-200 rounded-lg">
          <p className="text-xs text-amber-800">
            <strong>Anti-Hallucination Mode:</strong> All assessments will require
            evidence backing. No &quot;likely compliant&quot; or &quot;probably fine&quot; states allowed.
          </p>
        </div>

        {/* Footer */}
        <ModalFooter className="-mx-6 -mb-6">
          <button
            type="button"
            onClick={handleClose}
            className="px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
            disabled={isSubmitting}
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={isSubmitting}
            className="flex items-center gap-2 px-4 py-2 bg-gray-900 text-white rounded-lg hover:bg-gray-800 transition-colors disabled:opacity-50"
          >
            {isSubmitting ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Creating...
              </>
            ) : (
              <>
                <Plus className="h-4 w-4" />
                Create Audit
              </>
            )}
          </button>
        </ModalFooter>
      </form>
    </Modal>
  );
}

// ============================================================================
// Audit Card Component
// ============================================================================

function AuditCard({ audit }: { audit: AuditResponse }) {
  const isActive = audit.status === 'running' || audit.status === 'pending';

  return (
    <Link href={`/audits/${audit.audit_id}`}>
      <DashboardCard className="hover:shadow-md transition-shadow cursor-pointer">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <StatusIndicator status={audit.status} />
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm font-semibold text-gray-900">
                  {audit.audit_id}
                </span>
                <StatusBadge status={audit.status} />
              </div>
              <div className="flex items-center gap-4 mt-1 text-sm text-gray-500">
                <span className="flex items-center gap-1">
                  <Target className="h-3 w-3" />
                  {audit.target}
                </span>
                <span className="flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  {formatDateTime(audit.created_at)}
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-4">
            {isActive && (
              <div className="text-sm text-blue-600 font-medium">
                {Math.round(audit.progress)}%
              </div>
            )}
            <div className="flex gap-1">
              {audit.frameworks.map((fw) => (
                <span
                  key={fw}
                  className="px-2 py-0.5 text-xs bg-gray-100 text-gray-600 rounded"
                >
                  {fw}
                </span>
              ))}
            </div>
            <ChevronRight className="h-5 w-5 text-gray-400" />
          </div>
        </div>
      </DashboardCard>
    </Link>
  );
}

function StatusIndicator({ status }: { status: string }) {
  switch (status) {
    case 'running':
      return (
        <div className="p-2 bg-blue-100 rounded-lg">
          <Loader2 className="h-5 w-5 text-blue-600 animate-spin" />
        </div>
      );
    case 'completed':
      return (
        <div className="p-2 bg-green-100 rounded-lg">
          <CheckCircle className="h-5 w-5 text-green-600" />
        </div>
      );
    case 'failed':
      return (
        <div className="p-2 bg-red-100 rounded-lg">
          <XCircle className="h-5 w-5 text-red-600" />
        </div>
      );
    default:
      return (
        <div className="p-2 bg-gray-100 rounded-lg">
          <Clock className="h-5 w-5 text-gray-600" />
        </div>
      );
  }
}
