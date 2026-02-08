/**
 * Utility Functions for the Dashboard
 * 
 * Common utilities for styling, formatting, and data manipulation.
 * 
 * @module lib/utils
 */

import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { Severity, AuditStatus, AgentStatus, AssessmentState } from '@/types';

// ============================================================================
// Class Name Utilities
// ============================================================================

/**
 * Merge class names with Tailwind CSS conflict resolution.
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// ============================================================================
// Severity Styling
// ============================================================================

/**
 * Get Tailwind color classes for a severity level.
 */
export function getSeverityColor(severity: Severity | string): string {
  const colors: Record<string, string> = {
    [Severity.CRITICAL]: 'bg-red-600 text-white',
    [Severity.HIGH]: 'bg-orange-500 text-white',
    [Severity.MEDIUM]: 'bg-yellow-500 text-white',
    [Severity.LOW]: 'bg-blue-500 text-white',
    [Severity.INFO]: 'bg-gray-500 text-white',
  };
  return colors[severity] || colors[Severity.INFO];
}

/**
 * Get badge classes for severity.
 */
export function getSeverityBadgeClasses(severity: Severity | string): string {
  const base = 'px-2 py-0.5 text-xs font-bold rounded inline-flex items-center';
  return cn(base, getSeverityColor(severity));
}

/**
 * Get border color for severity.
 */
export function getSeverityBorderColor(severity: Severity | string): string {
  const colors: Record<string, string> = {
    [Severity.CRITICAL]: 'border-red-600',
    [Severity.HIGH]: 'border-orange-500',
    [Severity.MEDIUM]: 'border-yellow-500',
    [Severity.LOW]: 'border-blue-500',
    [Severity.INFO]: 'border-gray-500',
  };
  return colors[severity] || colors[Severity.INFO];
}

// ============================================================================
// Status Styling
// ============================================================================

/**
 * Get badge classes for audit status.
 */
export function getAuditStatusClasses(status: AuditStatus | string): string {
  const classes: Record<string, string> = {
    [AuditStatus.PENDING]: 'bg-gray-100 text-gray-800 border-gray-200',
    [AuditStatus.RUNNING]: 'bg-blue-100 text-blue-800 border-blue-200',
    [AuditStatus.COMPLETED]: 'bg-green-100 text-green-800 border-green-200',
    [AuditStatus.FAILED]: 'bg-red-100 text-red-800 border-red-200',
    [AuditStatus.CANCELLED]: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  };
  return cn(
    'px-2 py-1 text-xs font-medium rounded-full border inline-flex items-center',
    classes[status] || classes[AuditStatus.PENDING]
  );
}

/**
 * Get badge classes for agent status.
 */
export function getAgentStatusClasses(status: AgentStatus | string): string {
  const classes: Record<string, string> = {
    [AgentStatus.IDLE]: 'bg-gray-100 text-gray-800',
    [AgentStatus.RUNNING]: 'bg-blue-100 text-blue-800',
    [AgentStatus.COMPLETED]: 'bg-green-100 text-green-800',
    [AgentStatus.ERROR]: 'bg-red-100 text-red-800',
  };
  return cn(
    'px-2 py-0.5 text-xs font-medium rounded',
    classes[status] || classes[AgentStatus.IDLE]
  );
}

/**
 * Get badge classes for assessment state.
 */
export function getAssessmentStateClasses(state: AssessmentState | string): string {
  const classes: Record<string, string> = {
    [AssessmentState.COMPLIANT]: 'bg-green-100 text-green-800 border-green-200',
    [AssessmentState.NON_COMPLIANT]: 'bg-red-100 text-red-800 border-red-200',
    [AssessmentState.NOT_ASSESSED]: 'bg-gray-100 text-gray-800 border-gray-200',
    [AssessmentState.INSUFFICIENT_EVIDENCE]: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    [AssessmentState.EVIDENCE_GAP]: 'bg-orange-100 text-orange-800 border-orange-200',
    [AssessmentState.CONFLICTING_EVIDENCE]: 'bg-purple-100 text-purple-800 border-purple-200',
    [AssessmentState.NEEDS_MANUAL_REVIEW]: 'bg-blue-100 text-blue-800 border-blue-200',
  };
  return cn(
    'px-2 py-1 text-xs font-medium rounded-full border inline-flex items-center',
    classes[state] || classes[AssessmentState.NOT_ASSESSED]
  );
}

// ============================================================================
// Formatting Utilities
// ============================================================================

/**
 * Format a date string for display.
 */
export function formatDate(dateString: string): string {
  try {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  } catch {
    return dateString;
  }
}

/**
 * Format a date string with time.
 */
export function formatDateTime(dateString: string): string {
  try {
    const date = new Date(dateString);
    return date.toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return dateString;
  }
}

/**
 * Format duration in seconds to human-readable string.
 */
export function formatDuration(seconds: number): string {
  if (seconds < 60) {
    return `${Math.round(seconds)}s`;
  }
  if (seconds < 3600) {
    const mins = Math.floor(seconds / 60);
    const secs = Math.round(seconds % 60);
    return secs > 0 ? `${mins}m ${secs}s` : `${mins}m`;
  }
  const hours = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
}

/**
 * Format a number as a percentage.
 */
export function formatPercentage(value: number, decimals = 1): string {
  return `${value.toFixed(decimals)}%`;
}

/**
 * Format a confidence score (0-1) as percentage.
 */
export function formatConfidence(confidence: number): string {
  return formatPercentage(confidence * 100, 0);
}

/**
 * Truncate text with ellipsis.
 */
export function truncate(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength - 3)}...`;
}

// ============================================================================
// Data Transformation
// ============================================================================

/**
 * Group findings by severity.
 */
export function groupFindingsBySeverity<T extends { severity: Severity | string }>(
  findings: T[]
): Record<string, T[]> {
  return findings.reduce(
    (acc, finding) => {
      const severity = finding.severity;
      if (!acc[severity]) {
        acc[severity] = [];
      }
      acc[severity].push(finding);
      return acc;
    },
    {} as Record<string, T[]>
  );
}

/**
 * Calculate severity distribution.
 */
export function calculateSeverityDistribution(
  findings: Array<{ severity: Severity | string }>
): Record<Severity, number> {
  const distribution: Record<Severity, number> = {
    [Severity.CRITICAL]: 0,
    [Severity.HIGH]: 0,
    [Severity.MEDIUM]: 0,
    [Severity.LOW]: 0,
    [Severity.INFO]: 0,
  };

  findings.forEach((f) => {
    const sev = f.severity as Severity;
    if (sev in distribution) {
      distribution[sev]++;
    }
  });

  return distribution;
}

/**
 * Sort findings by severity (critical first).
 */
export function sortBySeverity<T extends { severity: Severity | string }>(
  findings: T[]
): T[] {
  const order: Record<string, number> = {
    [Severity.CRITICAL]: 0,
    [Severity.HIGH]: 1,
    [Severity.MEDIUM]: 2,
    [Severity.LOW]: 3,
    [Severity.INFO]: 4,
  };

  return [...findings].sort((a, b) => {
    return (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
  });
}

// ============================================================================
// Chart Data Helpers
// ============================================================================

/**
 * Convert severity counts to chart data format.
 */
export function severityToChartData(
  counts: Record<Severity | string, number>
): Array<{ name: string; value: number; color: string }> {
  const colors: Record<string, string> = {
    [Severity.CRITICAL]: '#dc2626',
    [Severity.HIGH]: '#f97316',
    [Severity.MEDIUM]: '#eab308',
    [Severity.LOW]: '#3b82f6',
    [Severity.INFO]: '#6b7280',
  };

  return Object.entries(counts).map(([severity, count]) => ({
    name: severity.charAt(0).toUpperCase() + severity.slice(1),
    value: count,
    color: colors[severity] || '#6b7280',
  }));
}

/**
 * Generate chart colors array.
 */
export const SEVERITY_COLORS = ['#dc2626', '#f97316', '#eab308', '#3b82f6', '#6b7280'];

// ============================================================================
// Validation Helpers
// ============================================================================

/**
 * Check if an audit is still active (can be polled).
 */
export function isAuditActive(status: AuditStatus | string): boolean {
  return status === AuditStatus.RUNNING || status === AuditStatus.PENDING;
}

/**
 * Check if an audit has finished (success or failure).
 */
export function isAuditFinished(status: AuditStatus | string): boolean {
  return (
    status === AuditStatus.COMPLETED ||
    status === AuditStatus.FAILED ||
    status === AuditStatus.CANCELLED
  );
}
