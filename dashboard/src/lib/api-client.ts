/**
 * API Client for AI Security Auditor FastAPI Backend
 * 
 * Provides typed HTTP methods for all API endpoints.
 * Handles authentication, error handling, and request/response serialization.
 * 
 * @module lib/api-client
 */

import {
  AuditRequest,
  AuditResponse,
  AuditStatus,
  AgentStatusResponse,
  AgentType,
  Finding,
  FindingsResponse,
  Severity,
  ComplianceStatus,
  ControlAssessment,
  AssessmentState,
  Evidence,
  HealthResponse,
  DashboardSummary,
  APIError,
} from '@/types';

// ============================================================================
// Configuration
// ============================================================================

/**
 * API client configuration.
 */
export interface APIClientConfig {
  /** Base URL for the API (default: /api) */
  baseUrl?: string;
  
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  
  /** Additional headers to include in all requests */
  headers?: Record<string, string>;
}

const DEFAULT_CONFIG: Required<APIClientConfig> = {
  baseUrl: '/api',
  timeout: 30000,
  headers: {},
};

// ============================================================================
// API Error Handling
// ============================================================================

/**
 * Custom API error class.
 */
export class APIClientError extends Error {
  constructor(
    message: string,
    public statusCode: number,
    public detail?: string
  ) {
    super(message);
    this.name = 'APIClientError';
  }
}

/**
 * Check if error is an API client error.
 */
export function isAPIClientError(error: unknown): error is APIClientError {
  return error instanceof APIClientError;
}

// ============================================================================
// API Client Class
// ============================================================================

/**
 * Main API client for the Security Auditor backend.
 */
export class SecurityAuditorAPI {
  private config: Required<APIClientConfig>;
  private abortControllers: Map<string, AbortController> = new Map();

  constructor(config: APIClientConfig = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  // --------------------------------------------------------------------------
  // Base Request Methods
  // --------------------------------------------------------------------------

  /**
   * Make an HTTP request to the API.
   */
  private async request<T>(
    method: string,
    path: string,
    options: {
      body?: unknown;
      params?: Record<string, string | number | boolean | undefined>;
      signal?: AbortSignal;
    } = {}
  ): Promise<T> {
    const url = new URL(`${this.config.baseUrl}${path}`, window.location.origin);
    
    // Add query parameters
    if (options.params) {
      Object.entries(options.params).forEach(([key, value]) => {
        if (value !== undefined) {
          url.searchParams.append(key, String(value));
        }
      });
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...this.config.headers,
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const response = await fetch(url.toString(), {
        method,
        headers,
        body: options.body ? JSON.stringify(options.body) : undefined,
        signal: options.signal || controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: response.statusText }));
        throw new APIClientError(
          `API request failed: ${response.status}`,
          response.status,
          error.detail
        );
      }

      return response.json();
    } catch (error) {
      clearTimeout(timeoutId);
      
      if (error instanceof APIClientError) {
        throw error;
      }
      
      if (error instanceof Error && error.name === 'AbortError') {
        throw new APIClientError('Request timeout', 408, 'The request timed out');
      }
      
      throw new APIClientError(
        'Network error',
        0,
        error instanceof Error ? error.message : 'Unknown error'
      );
    }
  }

  private get<T>(path: string, params?: Record<string, string | number | boolean | undefined>) {
    return this.request<T>('GET', path, { params });
  }

  private post<T>(path: string, body?: unknown) {
    return this.request<T>('POST', path, { body });
  }

  // --------------------------------------------------------------------------
  // Health & Status Endpoints
  // --------------------------------------------------------------------------

  /**
   * Get system health status.
   */
  async getHealth(): Promise<HealthResponse> {
    return this.get<HealthResponse>('/health');
  }

  /**
   * Get system status.
   */
  async getSystemStatus(): Promise<{
    version: string;
    uptime_seconds: number;
    active_audits: number;
    total_audits: number;
    timestamp: string;
  }> {
    return this.get('/status');
  }

  // --------------------------------------------------------------------------
  // Audit Management Endpoints
  // --------------------------------------------------------------------------

  /**
   * Create and start a new audit.
   */
  async createAudit(request: AuditRequest): Promise<AuditResponse> {
    return this.post<AuditResponse>('/audits', request);
  }

  /**
   * List all audits with optional filtering.
   */
  async listAudits(options: {
    status?: AuditStatus;
    limit?: number;
    offset?: number;
  } = {}): Promise<AuditResponse[]> {
    return this.get<AuditResponse[]>('/audits', {
      status: options.status,
      limit: options.limit,
      offset: options.offset,
    });
  }

  /**
   * Get audit details by ID.
   */
  async getAudit(auditId: string): Promise<AuditResponse> {
    return this.get<AuditResponse>(`/audits/${auditId}`);
  }

  /**
   * Cancel a running audit.
   */
  async cancelAudit(auditId: string): Promise<AuditResponse> {
    return this.post<AuditResponse>(`/audits/${auditId}/cancel`);
  }

  /**
   * Get comprehensive audit summary for dashboard.
   */
  async getAuditSummary(auditId: string): Promise<DashboardSummary> {
    return this.get<DashboardSummary>(`/audits/${auditId}/summary`);
  }

  // --------------------------------------------------------------------------
  // Agent Monitoring Endpoints
  // --------------------------------------------------------------------------

  /**
   * Get status of all agents for an audit.
   */
  async getAgentStatuses(auditId: string): Promise<AgentStatusResponse[]> {
    return this.get<AgentStatusResponse[]>(`/audits/${auditId}/agents`);
  }

  /**
   * Get status of a specific agent.
   */
  async getAgentStatus(auditId: string, agentType: AgentType): Promise<AgentStatusResponse> {
    return this.get<AgentStatusResponse>(`/audits/${auditId}/agents/${agentType}`);
  }

  // --------------------------------------------------------------------------
  // Findings Endpoints
  // --------------------------------------------------------------------------

  /**
   * Get findings for an audit with optional filtering.
   */
  async getFindings(
    auditId: string,
    options: {
      severity?: Severity;
      agent?: AgentType;
      limit?: number;
      offset?: number;
    } = {}
  ): Promise<FindingsResponse> {
    return this.get<FindingsResponse>(`/audits/${auditId}/findings`, {
      severity: options.severity,
      agent: options.agent,
      limit: options.limit,
      offset: options.offset,
    });
  }

  /**
   * Get a specific finding by ID.
   */
  async getFinding(auditId: string, findingId: string): Promise<Finding> {
    return this.get<Finding>(`/audits/${auditId}/findings/${findingId}`);
  }

  // --------------------------------------------------------------------------
  // Compliance Endpoints
  // --------------------------------------------------------------------------

  /**
   * Get compliance status for all frameworks.
   */
  async getComplianceStatus(auditId: string): Promise<ComplianceStatus[]> {
    return this.get<ComplianceStatus[]>(`/audits/${auditId}/compliance`);
  }

  /**
   * Get control assessments for a specific framework.
   */
  async getControlAssessments(
    auditId: string,
    framework: string,
    state?: AssessmentState
  ): Promise<ControlAssessment[]> {
    return this.get<ControlAssessment[]>(
      `/audits/${auditId}/compliance/${framework}/controls`,
      { state }
    );
  }

  // --------------------------------------------------------------------------
  // Evidence Endpoints
  // --------------------------------------------------------------------------

  /**
   * Get evidence artifacts for an audit.
   */
  async getEvidence(
    auditId: string,
    options: {
      evidence_type?: string;
      limit?: number;
      offset?: number;
    } = {}
  ): Promise<Evidence[]> {
    return this.get<Evidence[]>(`/audits/${auditId}/evidence`, {
      evidence_type: options.evidence_type,
      limit: options.limit,
      offset: options.offset,
    });
  }

  /**
   * Get a specific evidence artifact.
   */
  async getEvidenceDetail(auditId: string, evidenceId: string): Promise<Evidence> {
    return this.get<Evidence>(`/audits/${auditId}/evidence/${evidenceId}`);
  }

  // --------------------------------------------------------------------------
  // Anti-Hallucination & Evidence Gaps Endpoints
  // --------------------------------------------------------------------------

  /**
   * Get anti-hallucination metrics for an audit.
   */
  async getAntiHallucinationMetrics(auditId: string): Promise<{
    llm_overrides: number;
    forbidden_words_detected: number;
    evidence_citation_rate: number;
    average_confidence: number;
    confidence_distribution: Array<{ range: string; count: number }>;
  }> {
    return this.get(`/audits/${auditId}/anti-hallucination`);
  }

  /**
   * Get evidence gaps for an audit.
   */
  async getEvidenceGaps(auditId: string): Promise<Array<{
    control: string;
    requirement: string;
    priority: 'high' | 'medium' | 'low';
  }>> {
    return this.get(`/audits/${auditId}/evidence-gaps`);
  }

  /**
   * Get all dashboard data in one call (performance optimization).
   */
  async getDashboardData(auditId: string): Promise<{
    summary: DashboardSummary;
    agents: AgentStatusResponse[];
    findings: FindingsResponse;
    compliance: ComplianceStatus[];
    anti_hallucination: {
      llm_overrides: number;
      forbidden_words_detected: number;
      evidence_citation_rate: number;
      average_confidence: number;
      confidence_distribution: Array<{ range: string; count: number }>;
    };
    evidence_gaps: Array<{
      control: string;
      requirement: string;
      priority: 'high' | 'medium' | 'low';
    }>;
  }> {
    return this.get(`/audits/${auditId}/dashboard`);
  }

  // --------------------------------------------------------------------------
  // Utility Methods
  // --------------------------------------------------------------------------

  /**
   * Cancel all pending requests.
   */
  cancelAllRequests(): void {
    this.abortControllers.forEach((controller) => controller.abort());
    this.abortControllers.clear();
  }
}

// ============================================================================
// Singleton Instance
// ============================================================================

/**
 * Default API client instance.
 * Use this for most cases, or create a new instance with custom config.
 */
export const api = new SecurityAuditorAPI();

// ============================================================================
// Convenience Functions
// ============================================================================

/**
 * Quick helper functions that use the default API instance.
 */
export const audits = {
  create: (request: AuditRequest) => api.createAudit(request),
  list: (options?: Parameters<typeof api.listAudits>[0]) => api.listAudits(options),
  get: (id: string) => api.getAudit(id),
  cancel: (id: string) => api.cancelAudit(id),
  summary: (id: string) => api.getAuditSummary(id),
};

export const agents = {
  list: (auditId: string) => api.getAgentStatuses(auditId),
  get: (auditId: string, type: AgentType) => api.getAgentStatus(auditId, type),
};

export const findings = {
  list: (auditId: string, options?: Parameters<typeof api.getFindings>[1]) =>
    api.getFindings(auditId, options),
  get: (auditId: string, findingId: string) => api.getFinding(auditId, findingId),
};

export const compliance = {
  status: (auditId: string) => api.getComplianceStatus(auditId),
  controls: (auditId: string, framework: string, state?: AssessmentState) =>
    api.getControlAssessments(auditId, framework, state),
};

export const evidence = {
  list: (auditId: string, options?: Parameters<typeof api.getEvidence>[1]) =>
    api.getEvidence(auditId, options),
  get: (auditId: string, evidenceId: string) => api.getEvidenceDetail(auditId, evidenceId),
};

export const health = {
  check: () => api.getHealth(),
  status: () => api.getSystemStatus(),
};
