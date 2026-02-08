/**
 * Badge Components
 * 
 * Reusable badge components for status, severity, and other indicators.
 */

import React from 'react';
import {
  getSeverityBadgeClasses,
  getAuditStatusClasses,
  getAgentStatusClasses,
  getAssessmentStateClasses,
} from '@/lib/utils';
import type { Severity, AuditStatus, AgentStatus, AssessmentState } from '@/types';

// ============================================================================
// Severity Badge
// ============================================================================

interface SeverityBadgeProps {
  severity: Severity | string;
  className?: string;
}

export function SeverityBadge({ severity, className = '' }: SeverityBadgeProps) {
  const safeSeverity = severity ?? 'unknown';
  return (
    <span className={`${getSeverityBadgeClasses(safeSeverity)} ${className}`}>
      {safeSeverity.toUpperCase()}
    </span>
  );
}

// ============================================================================
// Status Badge
// ============================================================================

interface StatusBadgeProps {
  status: AuditStatus | string;
  className?: string;
}

export function StatusBadge({ status, className = '' }: StatusBadgeProps) {
  const safeStatus = status ?? 'unknown';
  const displayText = safeStatus.replace(/_/g, ' ').toUpperCase();
  return (
    <span className={`${getAuditStatusClasses(safeStatus)} ${className}`}>
      {displayText}
    </span>
  );
}

// ============================================================================
// Agent Status Badge
// ============================================================================

interface AgentStatusBadgeProps {
  status: AgentStatus | string;
  className?: string;
}

export function AgentStatusBadge({ status, className = '' }: AgentStatusBadgeProps) {
  const safeStatus = status ?? 'unknown';
  return (
    <span className={`${getAgentStatusClasses(safeStatus)} ${className}`}>
      {safeStatus.charAt(0).toUpperCase() + safeStatus.slice(1)}
    </span>
  );
}

// ============================================================================
// Assessment State Badge
// ============================================================================

interface AssessmentBadgeProps {
  state: AssessmentState | string;
  className?: string;
}

export function AssessmentBadge({ state, className = '' }: AssessmentBadgeProps) {
  const safeState = state ?? 'unknown';
  const displayText = safeState.replace(/_/g, ' ');
  return (
    <span className={`${getAssessmentStateClasses(safeState)} ${className}`}>
      {displayText.charAt(0).toUpperCase() + displayText.slice(1).toLowerCase()}
    </span>
  );
}

// ============================================================================
// Generic Badge
// ============================================================================

interface BadgeProps {
  children: React.ReactNode;
  variant?: 'default' | 'outline' | 'secondary' | 'destructive' | 'success' | 'warning';
  className?: string;
}

export function Badge({ children, variant = 'default', className = '' }: BadgeProps) {
  const variants = {
    default: 'bg-gray-900 text-white',
    outline: 'border border-gray-300 text-gray-700',
    secondary: 'bg-gray-100 text-gray-800',
    destructive: 'bg-red-500 text-white',
    success: 'bg-green-500 text-white',
    warning: 'bg-amber-500 text-white',
  };

  return (
    <span
      className={`
        inline-flex items-center px-2 py-0.5 text-xs font-medium rounded
        ${variants[variant]}
        ${className}
      `}
    >
      {children}
    </span>
  );
}
