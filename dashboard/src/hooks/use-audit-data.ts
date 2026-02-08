/**
 * Custom Hooks for Data Fetching and State Management
 * 
 * Provides React hooks for fetching audit data with caching and real-time updates.
 * 
 * @module hooks/use-audit-data
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { api } from '@/lib/api-client';
import { AuditStatus } from '@/types';
import type {
  AuditResponse,
  AgentStatusResponse,
  Finding,
  FindingsResponse,
  ComplianceStatus,
  ControlAssessment,
  Evidence,
  DashboardSummary,
  Severity,
  AgentType,
  AssessmentState,
} from '@/types';

// ============================================================================
// Types
// ============================================================================

export interface DataFetchState<T> {
  data: T | null;
  isLoading: boolean;
  error: Error | null;
  refetch: () => Promise<void>;
}

export interface UseAuditsOptions {
  status?: AuditStatus;
  limit?: number;
  offset?: number;
  autoRefresh?: boolean;
  refreshInterval?: number;
}

export interface UseFindingsOptions {
  severity?: Severity;
  agent?: AgentType;
  limit?: number;
  offset?: number;
}

// ============================================================================
// Base Fetching Hook
// ============================================================================

/**
 * Generic data fetching hook with loading and error states.
 */
export function useFetch<T>(
  fetcher: () => Promise<T>,
  deps: unknown[] = []
): DataFetchState<T> {
  const [data, setData] = useState<T | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const isMounted = useRef(true);

  const fetch = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    
    try {
      const result = await fetcher();
      if (isMounted.current) {
        setData(result);
      }
    } catch (err) {
      if (isMounted.current) {
        setError(err instanceof Error ? err : new Error(String(err)));
      }
    } finally {
      if (isMounted.current) {
        setIsLoading(false);
      }
    }
  }, deps);

  useEffect(() => {
    isMounted.current = true;
    fetch();
    
    return () => {
      isMounted.current = false;
    };
  }, [fetch]);

  return { data, isLoading, error, refetch: fetch };
}

// ============================================================================
// Audit Hooks
// ============================================================================

/**
 * Hook for fetching list of audits.
 */
export function useAudits(options: UseAuditsOptions = {}): DataFetchState<AuditResponse[]> {
  const { status, limit = 10, offset = 0, autoRefresh = false, refreshInterval = 5000 } = options;
  
  const fetcher = useCallback(
    () => api.listAudits({ status, limit, offset }),
    [status, limit, offset]
  );

  const result = useFetch(fetcher, [status, limit, offset]);

  // Auto-refresh when audits are running
  useEffect(() => {
    if (!autoRefresh) return;

    const interval = setInterval(() => {
      if (result.data?.some(a => a.status === AuditStatus.RUNNING)) {
        result.refetch();
      }
    }, refreshInterval);

    return () => clearInterval(interval);
  }, [autoRefresh, refreshInterval, result]);

  return result;
}

/**
 * Hook for fetching a single audit.
 */
export function useAudit(auditId: string | null): DataFetchState<AuditResponse> {
  const fetcher = useCallback(
    () => (auditId ? api.getAudit(auditId) : Promise.reject(new Error('No audit ID'))),
    [auditId]
  );

  return useFetch(fetcher, [auditId]);
}

/**
 * Hook for fetching audit summary for dashboard.
 */
export function useAuditSummary(auditId: string | null): DataFetchState<DashboardSummary> {
  const fetcher = useCallback(
    () => (auditId ? api.getAuditSummary(auditId) : Promise.reject(new Error('No audit ID'))),
    [auditId]
  );

  return useFetch(fetcher, [auditId]);
}

// ============================================================================
// Agent Hooks
// ============================================================================

/**
 * Hook for fetching agent statuses for an audit.
 */
export function useAgentStatuses(auditId: string | null): DataFetchState<AgentStatusResponse[]> {
  const fetcher = useCallback(
    () => (auditId ? api.getAgentStatuses(auditId) : Promise.reject(new Error('No audit ID'))),
    [auditId]
  );

  return useFetch(fetcher, [auditId]);
}

/**
 * Hook for fetching a specific agent status.
 */
export function useAgentStatus(
  auditId: string | null,
  agentType: AgentType
): DataFetchState<AgentStatusResponse> {
  const fetcher = useCallback(
    () =>
      auditId
        ? api.getAgentStatus(auditId, agentType)
        : Promise.reject(new Error('No audit ID')),
    [auditId, agentType]
  );

  return useFetch(fetcher, [auditId, agentType]);
}

// ============================================================================
// Findings Hooks
// ============================================================================

/**
 * Hook for fetching findings for an audit.
 */
export function useFindings(
  auditId: string | null,
  options: UseFindingsOptions = {}
): DataFetchState<FindingsResponse> {
  const { severity, agent, limit = 50, offset = 0 } = options;

  const fetcher = useCallback(
    () =>
      auditId
        ? api.getFindings(auditId, { severity, agent, limit, offset })
        : Promise.reject(new Error('No audit ID')),
    [auditId, severity, agent, limit, offset]
  );

  return useFetch(fetcher, [auditId, severity, agent, limit, offset]);
}

/**
 * Hook for fetching a single finding.
 */
export function useFinding(
  auditId: string | null,
  findingId: string | null
): DataFetchState<Finding> {
  const fetcher = useCallback(
    () =>
      auditId && findingId
        ? api.getFinding(auditId, findingId)
        : Promise.reject(new Error('Missing audit or finding ID')),
    [auditId, findingId]
  );

  return useFetch(fetcher, [auditId, findingId]);
}

// ============================================================================
// Compliance Hooks
// ============================================================================

/**
 * Hook for fetching compliance status.
 */
export function useComplianceStatus(auditId: string | null): DataFetchState<ComplianceStatus[]> {
  const fetcher = useCallback(
    () =>
      auditId
        ? api.getComplianceStatus(auditId)
        : Promise.reject(new Error('No audit ID')),
    [auditId]
  );

  return useFetch(fetcher, [auditId]);
}

/**
 * Hook for fetching control assessments.
 */
export function useControlAssessments(
  auditId: string | null,
  framework: string,
  state?: AssessmentState
): DataFetchState<ControlAssessment[]> {
  const fetcher = useCallback(
    () =>
      auditId
        ? api.getControlAssessments(auditId, framework, state)
        : Promise.reject(new Error('No audit ID')),
    [auditId, framework, state]
  );

  return useFetch(fetcher, [auditId, framework, state]);
}

// ============================================================================
// Evidence Hooks
// ============================================================================

/**
 * Hook for fetching evidence artifacts.
 */
export function useEvidence(
  auditId: string | null,
  options: { evidence_type?: string; limit?: number; offset?: number } = {}
): DataFetchState<Evidence[]> {
  const { evidence_type, limit = 50, offset = 0 } = options;

  const fetcher = useCallback(
    () =>
      auditId
        ? api.getEvidence(auditId, { evidence_type, limit, offset })
        : Promise.reject(new Error('No audit ID')),
    [auditId, evidence_type, limit, offset]
  );

  return useFetch(fetcher, [auditId, evidence_type, limit, offset]);
}

/**
 * Hook for fetching a single evidence artifact.
 */
export function useEvidenceDetail(
  auditId: string | null,
  evidenceId: string | null
): DataFetchState<Evidence> {
  const fetcher = useCallback(
    () =>
      auditId && evidenceId
        ? api.getEvidenceDetail(auditId, evidenceId)
        : Promise.reject(new Error('Missing audit or evidence ID')),
    [auditId, evidenceId]
  );

  return useFetch(fetcher, [auditId, evidenceId]);
}

// ============================================================================
// Anti-Hallucination & Evidence Gaps Hooks
// ============================================================================

/**
 * Anti-hallucination metrics type.
 */
export interface AntiHallucinationMetrics {
  llm_overrides: number;
  forbidden_words_detected: number;
  evidence_citation_rate: number;
  average_confidence: number;
  confidence_distribution: Array<{ range: string; count: number }>;
}

/**
 * Evidence gap type.
 */
export interface EvidenceGap {
  control: string;
  requirement: string;
  priority: 'high' | 'medium' | 'low';
}

/**
 * Hook for fetching anti-hallucination metrics.
 */
export function useAntiHallucinationMetrics(
  auditId: string | null
): DataFetchState<AntiHallucinationMetrics> {
  const fetcher = useCallback(
    () =>
      auditId
        ? api.getAntiHallucinationMetrics(auditId)
        : Promise.reject(new Error('No audit ID')),
    [auditId]
  );

  return useFetch(fetcher, [auditId]);
}

/**
 * Hook for fetching evidence gaps.
 */
export function useEvidenceGaps(auditId: string | null): DataFetchState<EvidenceGap[]> {
  const fetcher = useCallback(
    () =>
      auditId
        ? api.getEvidenceGaps(auditId)
        : Promise.reject(new Error('No audit ID')),
    [auditId]
  );

  return useFetch(fetcher, [auditId]);
}

/**
 * Hook for fetching all dashboard data in one call (performance optimization).
 */
export function useDashboardData(auditId: string | null) {
  const fetcher = useCallback(
    () =>
      auditId
        ? api.getDashboardData(auditId)
        : Promise.reject(new Error('No audit ID')),
    [auditId]
  );

  return useFetch(fetcher, [auditId]);
}

// ============================================================================
// Health Hooks
// ============================================================================

/**
 * Hook for checking API health.
 */
export function useHealth() {
  return useFetch(() => api.getHealth(), []);
}

/**
 * Hook for system status with auto-refresh.
 */
export function useSystemStatus(refreshInterval = 30000) {
  const result = useFetch(() => api.getSystemStatus(), []);

  useEffect(() => {
    const interval = setInterval(result.refetch, refreshInterval);
    return () => clearInterval(interval);
  }, [refreshInterval, result]);

  return result;
}
