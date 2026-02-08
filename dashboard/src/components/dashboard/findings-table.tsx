'use client';

/**
 * Findings Table Component
 * 
 * Displays security findings in a sortable, filterable table format
 * with severity indicators and quick actions.
 * 
 * @module components/dashboard/findings-table
 */

import React, { useState } from 'react';
import { ChevronDown, ChevronUp, ExternalLink, AlertCircle } from 'lucide-react';
import { cn, formatDateTime, truncate, sortBySeverity } from '@/lib/utils';
import { SeverityBadge } from '@/components/ui/badge';
import type { Finding, Severity, AgentType } from '@/types';

interface FindingsTableProps {
  findings: Finding[];
  isLoading?: boolean;
  compact?: boolean;
  onFindingClick?: (finding: Finding) => void;
  className?: string;
}

type SortField = 'severity' | 'title' | 'discovered_at' | 'agent_type';
type SortDirection = 'asc' | 'desc';

export function FindingsTable({
  findings,
  isLoading,
  compact = false,
  onFindingClick,
  className,
}: FindingsTableProps) {
  const [sortField, setSortField] = useState<SortField>('severity');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  const sortedFindings = React.useMemo(() => {
    const sorted = [...findings];
    
    if (sortField === 'severity') {
      // Use custom severity sorting
      const severitySorted = sortBySeverity(sorted);
      return sortDirection === 'desc' ? severitySorted : severitySorted.reverse();
    }
    
    sorted.sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'title':
          comparison = a.title.localeCompare(b.title);
          break;
        case 'discovered_at':
          comparison = new Date(a.discovered_at).getTime() - new Date(b.discovered_at).getTime();
          break;
        case 'agent_type':
          comparison = a.agent_type.localeCompare(b.agent_type);
          break;
      }
      return sortDirection === 'asc' ? comparison : -comparison;
    });
    
    return sorted;
  }, [findings, sortField, sortDirection]);

  if (isLoading) {
    return <FindingsTableSkeleton compact={compact} />;
  }

  if (findings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-8 text-gray-500">
        <AlertCircle className="h-8 w-8 mb-2 opacity-50" />
        <p className="text-sm">No findings discovered yet</p>
      </div>
    );
  }

  return (
    <div className={cn('overflow-x-auto', className)}>
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-200">
            <SortableHeader
              label="Severity"
              field="severity"
              currentField={sortField}
              direction={sortDirection}
              onClick={handleSort}
              compact={compact}
            />
            <SortableHeader
              label="Title"
              field="title"
              currentField={sortField}
              direction={sortDirection}
              onClick={handleSort}
              compact={compact}
            />
            {!compact && (
              <>
                <SortableHeader
                  label="Agent"
                  field="agent_type"
                  currentField={sortField}
                  direction={sortDirection}
                  onClick={handleSort}
                  compact={compact}
                />
                <SortableHeader
                  label="Discovered"
                  field="discovered_at"
                  currentField={sortField}
                  direction={sortDirection}
                  onClick={handleSort}
                  compact={compact}
                />
              </>
            )}
            <th className="text-right py-2 px-3 text-gray-500 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody>
          {sortedFindings.map((finding) => (
            <tr
              key={finding.finding_id}
              className={cn(
                'border-b border-gray-100 hover:bg-gray-50 transition-colors',
                onFindingClick && 'cursor-pointer'
              )}
              onClick={() => onFindingClick?.(finding)}
            >
              <td className="py-3 px-3">
                <SeverityBadge severity={finding.severity} />
              </td>
              <td className="py-3 px-3">
                <div>
                  <p className="font-medium text-gray-900">
                    {compact ? truncate(finding.title, 40) : finding.title}
                  </p>
                  {!compact && finding.cwe_id && (
                    <p className="text-xs text-gray-500 mt-0.5">
                      {finding.cwe_id}
                      {finding.owasp_category && ` • ${finding.owasp_category}`}
                    </p>
                  )}
                </div>
              </td>
              {!compact && (
                <>
                  <td className="py-3 px-3">
                    <span className="text-gray-600 capitalize">
                      {formatAgentType(finding.agent_type)}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-gray-500">
                    {formatDateTime(finding.discovered_at)}
                  </td>
                </>
              )}
              <td className="py-3 px-3 text-right">
                <button
                  className="p-1 hover:bg-gray-100 rounded transition-colors"
                  onClick={(e) => {
                    e.stopPropagation();
                    // TODO: Open finding detail modal
                  }}
                  title="View details"
                >
                  <ExternalLink className="h-4 w-4 text-gray-400" />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

interface SortableHeaderProps {
  label: string;
  field: SortField;
  currentField: SortField;
  direction: SortDirection;
  onClick: (field: SortField) => void;
  compact?: boolean;
}

function SortableHeader({
  label,
  field,
  currentField,
  direction,
  onClick,
  compact,
}: SortableHeaderProps) {
  const isActive = currentField === field;
  
  return (
    <th
      className={cn(
        'text-left py-2 px-3 text-gray-500 font-medium cursor-pointer hover:text-gray-700 transition-colors',
        compact && 'text-xs'
      )}
      onClick={() => onClick(field)}
    >
      <div className="flex items-center gap-1">
        {label}
        {isActive && (
          direction === 'desc' ? (
            <ChevronDown className="h-3 w-3" />
          ) : (
            <ChevronUp className="h-3 w-3" />
          )
        )}
      </div>
    </th>
  );
}

function FindingsTableSkeleton({ compact }: { compact?: boolean }) {
  return (
    <div className="animate-pulse">
      <div className="h-8 bg-gray-100 rounded mb-2" />
      {Array.from({ length: compact ? 5 : 10 }).map((_, i) => (
        <div key={i} className="h-12 bg-gray-50 rounded mb-1" />
      ))}
    </div>
  );
}

function formatAgentType(agentType: AgentType): string {
  return agentType.replace(/_/g, ' ');
}

// Export a compact version for use in cards
export function FindingsListCompact({
  findings,
  maxItems = 5,
}: {
  findings: Finding[];
  maxItems?: number;
}) {
  const topFindings = sortBySeverity(findings).slice(0, maxItems);
  
  return (
    <ul className="space-y-2">
      {topFindings.map((finding) => (
        <li
          key={finding.finding_id}
          className="flex items-center gap-3 p-2 bg-gray-50 rounded hover:bg-gray-100 transition-colors"
        >
          <SeverityBadge severity={finding.severity} />
          <span className="text-sm text-gray-700 truncate">{finding.title}</span>
        </li>
      ))}
    </ul>
  );
}
