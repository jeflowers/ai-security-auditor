'use client';

/**
 * Audit Header Component
 * 
 * Displays audit information header with selector dropdown,
 * status indicators, and quick action buttons.
 * 
 * @module components/dashboard/audit-header
 */

import React, { useState, useRef, useEffect } from 'react';
import {
  ChevronDown,
  RefreshCw,
  Download,
  Clock,
  Target,
  CheckCircle,
  XCircle,
  Loader2,
  Play,
  StopCircle,
} from 'lucide-react';
import { cn, formatDateTime, formatDuration, isAuditActive } from '@/lib/utils';
import { StatusBadge } from '@/components/ui/badge';
import type { AuditResponse, AuditStatus } from '@/types';

interface AuditHeaderProps {
  audit: AuditResponse | null;
  audits: AuditResponse[];
  onSelectAudit: (audit: AuditResponse) => void;
  onRefresh?: () => void;
  onExport?: () => void;
  onCancel?: (auditId: string) => void;
  isLoading?: boolean;
  className?: string;
}

export function AuditHeader({
  audit,
  audits,
  onSelectAudit,
  onRefresh,
  onExport,
  onCancel,
  isLoading,
  className,
}: AuditHeaderProps) {
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setDropdownOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  if (!audit) {
    return (
      <div className={cn('bg-white rounded-lg border border-gray-200 p-4', className)}>
        <div className="flex items-center justify-between">
          <div className="animate-pulse flex items-center gap-4">
            <div className="h-8 w-48 bg-gray-200 rounded" />
            <div className="h-6 w-24 bg-gray-200 rounded" />
          </div>
        </div>
      </div>
    );
  }

  const isActive = isAuditActive(audit.status);

  return (
    <div className={cn('bg-white rounded-lg border border-gray-200 p-4', className)}>
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        {/* Left Side - Audit Selector & Info */}
        <div className="flex items-center gap-4 flex-wrap">
          {/* Audit Selector Dropdown */}
          <div className="relative" ref={dropdownRef}>
            <button
              onClick={() => setDropdownOpen(!dropdownOpen)}
              className="flex items-center gap-2 px-3 py-2 bg-gray-50 hover:bg-gray-100 rounded-lg transition-colors border border-gray-200"
            >
              <span className="font-mono text-sm font-medium text-gray-900">
                {audit.audit_id}
              </span>
              <ChevronDown className={cn(
                'h-4 w-4 text-gray-500 transition-transform',
                dropdownOpen && 'rotate-180'
              )} />
            </button>
            
            {dropdownOpen && (
              <div className="absolute z-10 mt-1 w-72 bg-white rounded-lg shadow-lg border border-gray-200 py-1 max-h-64 overflow-y-auto">
                {audits.length === 0 ? (
                  <div className="px-3 py-2 text-sm text-gray-500">No audits available</div>
                ) : (
                  audits.map((a) => (
                    <button
                      key={a.audit_id}
                      onClick={() => {
                        onSelectAudit(a);
                        setDropdownOpen(false);
                      }}
                      className={cn(
                        'w-full text-left px-3 py-2 hover:bg-gray-50 flex items-center justify-between',
                        a.audit_id === audit.audit_id && 'bg-blue-50'
                      )}
                    >
                      <div>
                        <span className="font-mono text-sm font-medium">{a.audit_id}</span>
                        <p className="text-xs text-gray-500 truncate max-w-[200px]">
                          {a.target}
                        </p>
                      </div>
                      <StatusIndicator status={a.status} />
                    </button>
                  ))
                )}
              </div>
            )}
          </div>

          {/* Status Badge */}
          <StatusBadge status={audit.status} />

          {/* Progress for Active Audits */}
          {isActive && (
            <div className="flex items-center gap-2 text-sm text-gray-600">
              <Loader2 className="h-4 w-4 animate-spin text-blue-500" />
              <span>{Math.round(audit.progress)}% complete</span>
            </div>
          )}
        </div>

        {/* Right Side - Meta Info & Actions */}
        <div className="flex items-center gap-4 flex-wrap">
          {/* Meta Info */}
          <div className="flex items-center gap-4 text-sm text-gray-500">
            <div className="flex items-center gap-1">
              <Target className="h-4 w-4" />
              <span className="truncate max-w-[150px]" title={audit.target}>
                {audit.target}
              </span>
            </div>
            <div className="flex items-center gap-1">
              <Clock className="h-4 w-4" />
              <span>{formatDateTime(audit.created_at)}</span>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-2">
            {onRefresh && (
              <button
                onClick={onRefresh}
                disabled={isLoading}
                className="p-2 hover:bg-gray-100 rounded-lg transition-colors disabled:opacity-50"
                title="Refresh data"
              >
                <RefreshCw className={cn('h-4 w-4 text-gray-500', isLoading && 'animate-spin')} />
              </button>
            )}
            
            {onExport && !isActive && (
              <button
                onClick={onExport}
                className="flex items-center gap-2 px-3 py-1.5 text-sm bg-gray-100 hover:bg-gray-200 rounded-lg transition-colors"
              >
                <Download className="h-4 w-4" />
                Export
              </button>
            )}
            
            {onCancel && isActive && (
              <button
                onClick={() => onCancel(audit.audit_id)}
                className="flex items-center gap-2 px-3 py-1.5 text-sm bg-red-50 hover:bg-red-100 text-red-700 rounded-lg transition-colors"
              >
                <StopCircle className="h-4 w-4" />
                Cancel
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Frameworks Row */}
      <div className="mt-3 pt-3 border-t border-gray-100">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs text-gray-500">Frameworks:</span>
          {audit.frameworks.map((framework) => (
            <span
              key={framework}
              className="px-2 py-0.5 text-xs font-medium bg-blue-50 text-blue-700 rounded"
            >
              {framework}
            </span>
          ))}
          {audit.message && (
            <span className="text-xs text-gray-400 ml-auto">{audit.message}</span>
          )}
        </div>
      </div>
    </div>
  );
}

function StatusIndicator({ status }: { status: AuditStatus | string }) {
  switch (status) {
    case 'running':
      return <Loader2 className="h-4 w-4 text-blue-500 animate-spin" />;
    case 'completed':
      return <CheckCircle className="h-4 w-4 text-green-500" />;
    case 'failed':
      return <XCircle className="h-4 w-4 text-red-500" />;
    case 'pending':
      return <Clock className="h-4 w-4 text-gray-400" />;
    default:
      return <div className="h-4 w-4 rounded-full bg-gray-300" />;
  }
}

// Compact version for lists
export function AuditHeaderCompact({
  audit,
  onClick,
}: {
  audit: AuditResponse;
  onClick?: () => void;
}) {
  return (
    <div
      className={cn(
        'flex items-center justify-between p-3 bg-gray-50 rounded-lg',
        onClick && 'cursor-pointer hover:bg-gray-100 transition-colors'
      )}
      onClick={onClick}
    >
      <div className="flex items-center gap-3">
        <StatusIndicator status={audit.status} />
        <div>
          <span className="font-mono text-sm font-medium">{audit.audit_id}</span>
          <p className="text-xs text-gray-500 truncate max-w-[200px]">{audit.target}</p>
        </div>
      </div>
      <div className="text-xs text-gray-400">
        {formatDateTime(audit.created_at)}
      </div>
    </div>
  );
}
