'use client';

/**
 * Compliance Matrix Component
 * 
 * Displays compliance status across all assessed frameworks with
 * visual indicators for each framework's compliance percentage.
 * 
 * @module components/dashboard/compliance-matrix
 */

import React from 'react';
import { CheckCircle, XCircle, AlertTriangle, HelpCircle, FileQuestion } from 'lucide-react';
import { cn, formatPercentage } from '@/lib/utils';
import { ProgressBar, MultiProgressBar } from './progress-bar';
import type { ComplianceStatus } from '@/types';

interface ComplianceMatrixProps {
  complianceStatuses: ComplianceStatus[];
  isLoading?: boolean;
  className?: string;
}

// Framework display configuration
const FRAMEWORK_CONFIG: Record<string, { name: string; color: string; description: string }> = {
  SOC2: {
    name: 'SOC 2',
    color: '#3b82f6',
    description: 'Trust Services Criteria',
  },
  GDPR: {
    name: 'GDPR',
    color: '#10b981',
    description: 'EU Data Protection',
  },
  HIPAA: {
    name: 'HIPAA',
    color: '#8b5cf6',
    description: 'Healthcare Privacy',
  },
  'NIST-800-53A': {
    name: 'NIST 800-53A',
    color: '#f59e0b',
    description: 'Security Assessment',
  },
  'ISO-27001': {
    name: 'ISO 27001',
    color: '#ef4444',
    description: 'Information Security',
  },
};

export function ComplianceMatrix({
  complianceStatuses,
  isLoading,
  className,
}: ComplianceMatrixProps) {
  if (isLoading) {
    return <ComplianceMatrixSkeleton />;
  }

  if (complianceStatuses.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-8 text-gray-500">
        <FileQuestion className="h-8 w-8 mb-2 opacity-50" />
        <p className="text-sm">No compliance frameworks assessed</p>
      </div>
    );
  }

  return (
    <div className={cn('space-y-4', className)}>
      {/* Summary Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <SummaryCard
          label="Total Controls"
          value={complianceStatuses.reduce((sum, s) => sum + s.total_controls, 0)}
          icon={FileQuestion}
          color="gray"
        />
        <SummaryCard
          label="Compliant"
          value={complianceStatuses.reduce((sum, s) => sum + s.compliant, 0)}
          icon={CheckCircle}
          color="green"
        />
        <SummaryCard
          label="Non-Compliant"
          value={complianceStatuses.reduce((sum, s) => sum + s.non_compliant, 0)}
          icon={XCircle}
          color="red"
        />
        <SummaryCard
          label="Needs Evidence"
          value={complianceStatuses.reduce((sum, s) => sum + s.insufficient_evidence, 0)}
          icon={AlertTriangle}
          color="yellow"
        />
      </div>

      {/* Framework Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {complianceStatuses.map((status) => (
          <FrameworkCard key={status.framework} status={status} />
        ))}
      </div>
    </div>
  );
}

interface SummaryCardProps {
  label: string;
  value: number;
  icon: typeof CheckCircle;
  color: 'gray' | 'green' | 'red' | 'yellow' | 'blue';
}

function SummaryCard({ label, value, icon: Icon, color }: SummaryCardProps) {
  const colorStyles = {
    gray: 'bg-gray-50 text-gray-700',
    green: 'bg-green-50 text-green-700',
    red: 'bg-red-50 text-red-700',
    yellow: 'bg-yellow-50 text-yellow-700',
    blue: 'bg-blue-50 text-blue-700',
  };

  const iconStyles = {
    gray: 'text-gray-500',
    green: 'text-green-500',
    red: 'text-red-500',
    yellow: 'text-yellow-500',
    blue: 'text-blue-500',
  };

  return (
    <div className={cn('rounded-lg p-3', colorStyles[color])}>
      <div className="flex items-center gap-2 mb-1">
        <Icon className={cn('h-4 w-4', iconStyles[color])} />
        <span className="text-xs font-medium">{label}</span>
      </div>
      <p className="text-2xl font-bold">{value}</p>
    </div>
  );
}

interface FrameworkCardProps {
  status: ComplianceStatus;
}

function FrameworkCard({ status }: FrameworkCardProps) {
  const config = FRAMEWORK_CONFIG[status.framework] || {
    name: status.framework,
    color: '#6b7280',
    description: 'Compliance Framework',
  };

  const segments = [
    { value: status.compliant, color: '#22c55e', label: 'Compliant' },
    { value: status.non_compliant, color: '#ef4444', label: 'Non-Compliant' },
    { value: status.insufficient_evidence, color: '#eab308', label: 'Needs Evidence' },
    { value: status.not_assessed, color: '#d1d5db', label: 'Not Assessed' },
  ].filter((s) => s.value > 0);

  const complianceColor =
    status.compliance_percentage >= 80
      ? 'text-green-600'
      : status.compliance_percentage >= 60
      ? 'text-yellow-600'
      : 'text-red-600';

  return (
    <div className="bg-white border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <div
            className="w-3 h-3 rounded-full"
            style={{ backgroundColor: config.color }}
          />
          <div>
            <h4 className="font-semibold text-gray-900">{config.name}</h4>
            <p className="text-xs text-gray-500">{config.description}</p>
          </div>
        </div>
        <div className={cn('text-xl font-bold', complianceColor)}>
          {formatPercentage(status.compliance_percentage, 0)}
        </div>
      </div>

      {/* Progress Bar */}
      <div className="mb-3">
        <MultiProgressBar segments={segments} />
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-2 text-center">
        <div>
          <p className="text-lg font-bold text-green-600">{status.compliant}</p>
          <p className="text-xs text-gray-500">Pass</p>
        </div>
        <div>
          <p className="text-lg font-bold text-red-600">{status.non_compliant}</p>
          <p className="text-xs text-gray-500">Fail</p>
        </div>
        <div>
          <p className="text-lg font-bold text-yellow-600">{status.insufficient_evidence}</p>
          <p className="text-xs text-gray-500">Evidence</p>
        </div>
        <div>
          <p className="text-lg font-bold text-gray-400">{status.not_assessed}</p>
          <p className="text-xs text-gray-500">Pending</p>
        </div>
      </div>
    </div>
  );
}

function ComplianceMatrixSkeleton() {
  return (
    <div className="animate-pulse space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="h-20 bg-gray-100 rounded-lg" />
        ))}
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="h-40 bg-gray-100 rounded-lg" />
        ))}
      </div>
    </div>
  );
}

// Export a compact version for dashboard widgets
export function ComplianceQuickView({
  complianceStatuses,
}: {
  complianceStatuses: ComplianceStatus[];
}) {
  const totalControls = complianceStatuses.reduce((sum, s) => sum + s.total_controls, 0);
  const totalCompliant = complianceStatuses.reduce((sum, s) => sum + s.compliant, 0);
  const overallPercentage = totalControls > 0 ? (totalCompliant / totalControls) * 100 : 0;

  return (
    <div className="space-y-2">
      <div className="flex justify-between items-center">
        <span className="text-sm text-gray-500">Overall Compliance</span>
        <span className="font-bold text-gray-900">
          {formatPercentage(overallPercentage, 0)}
        </span>
      </div>
      <ProgressBar
        value={overallPercentage}
        variant={
          overallPercentage >= 80
            ? 'success'
            : overallPercentage >= 60
            ? 'warning'
            : 'danger'
        }
        showPercentage={false}
      />
      <div className="flex gap-2 text-xs text-gray-500">
        {complianceStatuses.map((s) => (
          <span key={s.framework} className="flex items-center gap-1">
            <span
              className="w-2 h-2 rounded-full"
              style={{ backgroundColor: FRAMEWORK_CONFIG[s.framework]?.color || '#6b7280' }}
            />
            {FRAMEWORK_CONFIG[s.framework]?.name || s.framework}
          </span>
        ))}
      </div>
    </div>
  );
}
