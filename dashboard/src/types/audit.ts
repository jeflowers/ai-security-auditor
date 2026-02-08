/**
 * TypeScript Type Definitions for AI Security Auditor
 * 
 * These types mirror the Python dataclasses and Pydantic models in:
 * - agents/orchestrator.py (AuditState, AgentResult)
 * - api/routes.py (Pydantic models)
 * - utils/anti_hallucination.py (Evidence, Finding models)
 * 
 * @module types/audit
 */

// ============================================================================
// Enums - Match Python Enums
// ============================================================================

/**
 * Phases of the security audit workflow.
 * Maps to: agents/orchestrator.py::AuditPhase
 */
export enum AuditPhase {
  INITIALIZATION = 'initialization',
  EVIDENCE_COLLECTION = 'evidence_collection',
  VULNERABILITY_SCAN = 'vulnerability_scan',
  CODE_ANALYSIS = 'code_analysis',
  LOG_ANALYSIS = 'log_analysis',
  COMPLIANCE_CHECK = 'compliance_check',
  REPORT_GENERATION = 'report_generation',
  COMPLETED = 'completed',
  ERROR = 'error',
}

/**
 * Audit execution status.
 * Maps to: api/routes.py::AuditStatus
 */
export enum AuditStatus {
  PENDING = 'pending',
  RUNNING = 'running',
  COMPLETED = 'completed',
  FAILED = 'failed',
  CANCELLED = 'cancelled',
}

/**
 * Finding severity levels.
 * Maps to: api/routes.py::Severity
 */
export enum Severity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info',
}

/**
 * Types of security agents.
 * Maps to: api/routes.py::AgentType
 */
export enum AgentType {
  VULNERABILITY_SCANNER = 'vulnerability_scanner',
  CODE_ANALYZER = 'code_analyzer',
  LOG_ANALYZER = 'log_analyzer',
  COMPLIANCE_CHECKER = 'compliance_checker',
}

/**
 * Agent execution status.
 * Maps to: api/routes.py::AgentStatus
 */
export enum AgentStatus {
  IDLE = 'idle',
  RUNNING = 'running',
  COMPLETED = 'completed',
  ERROR = 'error',
}

/**
 * Compliance assessment states.
 * Maps to: api/routes.py::AssessmentState
 * 
 * These are the ONLY valid states per anti-hallucination rules:
 * PASS, FAIL, INSUFFICIENT_EVIDENCE, EVIDENCE_GAP, CONFLICTING_EVIDENCE, NEEDS_MANUAL_REVIEW
 */
export enum AssessmentState {
  COMPLIANT = 'compliant',
  NON_COMPLIANT = 'non_compliant',
  NOT_ASSESSED = 'not_assessed',
  INSUFFICIENT_EVIDENCE = 'insufficient_evidence',
  EVIDENCE_GAP = 'evidence_gap',
  CONFLICTING_EVIDENCE = 'conflicting_evidence',
  NEEDS_MANUAL_REVIEW = 'needs_manual_review',
}

/**
 * Evidence types supported by the system.
 */
export enum EvidenceType {
  LOG_FILE = 'log_file',
  CONFIG_FILE = 'config_file',
  SCAN_RESULT = 'scan_result',
  CODE_SNIPPET = 'code_snippet',
  SCREENSHOT = 'screenshot',
  API_RESPONSE = 'api_response',
  MANUAL_OBSERVATION = 'manual_observation',
  DOCUMENT = 'document',
}

// ============================================================================
// Evidence Types - Core Anti-Hallucination Models
// ============================================================================

/**
 * Evidence artifact with provenance tracking.
 * Maps to: Python Evidence dataclass with SHA256 hashing
 * 
 * Per anti-hallucination rules:
 * - Every evidence must have a unique ID
 * - Content hash is required for integrity
 * - Collected timestamp for freshness scoring
 */
export interface Evidence {
  /** Unique identifier for the evidence (e.g., EVD-xxx) */
  evidence_id: string;
  
  /** Type classification of the evidence */
  evidence_type: EvidenceType | string;
  
  /** Source system/location where evidence was collected */
  source: string;
  
  /** Human-readable summary of the evidence */
  summary: string;
  
  /** Raw content or reference to content */
  content?: string;
  
  /** When the evidence was collected (ISO 8601) */
  collected_at: string;
  
  /** SHA256 hash of the content for integrity verification */
  content_hash: string;
  
  /** Freshness score (0.0-1.0, decay over time) */
  freshness_score?: number;
  
  /** Related finding IDs */
  related_findings: string[];
  
  /** Related control IDs */
  related_controls: string[];
  
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Evidence provenance chain for audit trail.
 * Tracks the complete lineage of evidence transformation.
 */
export interface EvidenceProvenance {
  /** Source evidence ID */
  source_id: string;
  
  /** Chain of transformations applied */
  transformations: ProvenanceStep[];
  
  /** Final evidence ID after all transformations */
  final_id: string;
  
  /** Complete hash chain for verification */
  hash_chain: string[];
}

/**
 * Single step in provenance chain.
 */
export interface ProvenanceStep {
  /** Type of transformation */
  action: 'collected' | 'parsed' | 'normalized' | 'enriched' | 'validated';
  
  /** When the transformation occurred */
  timestamp: string;
  
  /** Agent or system that performed the transformation */
  actor: string;
  
  /** Input hash before transformation */
  input_hash: string;
  
  /** Output hash after transformation */
  output_hash: string;
}

// ============================================================================
// Finding Types
// ============================================================================

/**
 * Security finding from any agent.
 * Maps to: api/routes.py::Finding
 */
export interface Finding {
  /** Unique finding identifier (e.g., FND-xxx) */
  finding_id: string;
  
  /** Agent that discovered this finding */
  agent_type: AgentType;
  
  /** Severity classification */
  severity: Severity;
  
  /** Short title describing the finding */
  title: string;
  
  /** Detailed description of the finding */
  description: string;
  
  /** Evidence IDs supporting this finding */
  evidence_ids: string[];
  
  /** Related compliance control IDs */
  control_ids: string[];
  
  /** Recommended remediation steps */
  remediation?: string;
  
  /** When the finding was discovered (ISO 8601) */
  discovered_at: string;
  
  /** CWE identifier if applicable */
  cwe_id?: string;
  
  /** OWASP category if applicable */
  owasp_category?: string;
  
  /** Confidence score (0.0-1.0) */
  confidence?: number;
  
  /** Additional context */
  metadata?: Record<string, unknown>;
}

/**
 * Grouped findings response from API.
 */
export interface FindingsResponse {
  /** Total number of findings (before pagination) */
  total: number;
  
  /** Paginated findings list */
  findings: Finding[];
  
  /** Count breakdown by severity */
  by_severity: Record<Severity, number>;
}

// ============================================================================
// Compliance Types
// ============================================================================

/**
 * Assessment of a single compliance control.
 * Maps to: api/routes.py::ControlAssessment
 */
export interface ControlAssessment {
  /** Control identifier (e.g., CC6.1, A.9.1.1) */
  control_id: string;
  
  /** Human-readable control name */
  control_name: string;
  
  /** Framework this control belongs to */
  framework: string;
  
  /** Assessment state - must be one of valid states */
  state: AssessmentState;
  
  /** Compliance score (0.0-1.0) */
  score?: number;
  
  /** Confidence in the assessment (0.0-1.0) */
  confidence?: number;
  
  /** Evidence IDs supporting this assessment */
  evidence_ids: string[];
  
  /** Finding IDs related to this control */
  finding_ids: string[];
  
  /** When the control was assessed (ISO 8601) */
  assessed_at?: string;
  
  /** Reasoning for the assessment */
  reasoning?: string;
  
  /** Any evidence gaps identified */
  evidence_gaps?: string[];
}

/**
 * Overall compliance status for a framework.
 * Maps to: api/routes.py::ComplianceStatus
 */
export interface ComplianceStatus {
  /** Framework identifier (e.g., SOC2, GDPR) */
  framework: string;
  
  /** Total number of controls in framework */
  total_controls: number;
  
  /** Number of compliant controls */
  compliant: number;
  
  /** Number of non-compliant controls */
  non_compliant: number;
  
  /** Number of controls not yet assessed */
  not_assessed: number;
  
  /** Number of controls with insufficient evidence */
  insufficient_evidence: number;
  
  /** Overall compliance percentage */
  compliance_percentage: number;
}

/**
 * Control mapping between CWE, OWASP, and compliance frameworks.
 */
export interface ControlMapping {
  /** CWE identifier */
  cwe_id: string;
  
  /** OWASP Top 10 category */
  owasp_category?: string;
  
  /** Mapped compliance control IDs */
  control_ids: string[];
  
  /** Frameworks these controls belong to */
  frameworks: string[];
}

// ============================================================================
// Audit Types
// ============================================================================

/**
 * Audit scope definition.
 */
export interface AuditScope {
  /** Target systems to audit */
  systems?: string[];
  
  /** Target URL if web scanning */
  target_url?: string;
  
  /** Target path if code analysis */
  target_path?: string;
  
  /** Audit period start (ISO 8601) */
  period_start?: string;
  
  /** Audit period end (ISO 8601) */
  period_end?: string;
  
  /** Additional scope parameters */
  [key: string]: unknown;
}

/**
 * Request to start a new audit.
 * Maps to: api/routes.py::AuditRequest
 */
export interface AuditRequest {
  /** Target to audit (URL, path, etc.) */
  target: string;
  
  /** Compliance frameworks to assess */
  frameworks: string[];
  
  /** Agents to run */
  agents: AgentType[];
  
  /** Additional configuration */
  config?: Record<string, unknown>;
}

/**
 * Audit response/status.
 * Maps to: api/routes.py::AuditResponse
 */
export interface AuditResponse {
  /** Unique audit identifier */
  audit_id: string;
  
  /** Current status */
  status: AuditStatus;
  
  /** Target being audited */
  target: string;
  
  /** Frameworks being assessed */
  frameworks: string[];
  
  /** When the audit was created (ISO 8601) */
  created_at: string;
  
  /** When the audit was last updated (ISO 8601) */
  updated_at: string;
  
  /** Overall progress percentage (0-100) */
  progress: number;
  
  /** Status message */
  message: string;
}

/**
 * Full audit state (matches LangGraph state pattern).
 * Maps to: agents/orchestrator.py::AuditState
 */
export interface AuditState {
  // Audit metadata
  audit_id: string;
  framework: string;
  scope: AuditScope;
  started_at: string;
  
  // Current state
  current_phase: AuditPhase;
  phase_history: PhaseTransition[];
  
  // Results from each agent
  vulnerability_findings: Finding[];
  code_analysis_findings: Finding[];
  log_analysis_findings: Finding[];
  compliance_findings: ControlAssessment[];
  
  // Aggregated metrics
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  
  // Evidence tracking
  evidence_collected: string[];
  evidence_gaps: string[];
  
  // Paths
  target_path: string;
  evidence_path: string;
  output_path: string;
  
  // Final output
  overall_status: string;
  final_report: AuditReport;
  
  // Error handling
  errors: AuditError[];
}

/**
 * Phase transition record.
 */
export interface PhaseTransition {
  /** Phase transitioned from */
  from: AuditPhase;
  
  /** Phase transitioned to */
  to: AuditPhase;
  
  /** When the transition occurred (ISO 8601) */
  timestamp: string;
  
  /** Number of findings discovered in the phase */
  findings_count: number;
  
  /** Status of the transition */
  status: 'success' | 'partial' | 'failed' | 'transition';
}

/**
 * Audit error record.
 */
export interface AuditError {
  /** Phase where error occurred */
  phase: AuditPhase;
  
  /** Error message */
  error: string;
  
  /** When the error occurred (ISO 8601) */
  timestamp: string;
  
  /** Stack trace if available */
  stack_trace?: string;
}

// ============================================================================
// Agent Types
// ============================================================================

/**
 * Status of a single agent.
 * Maps to: api/routes.py::AgentStatusResponse
 */
export interface AgentStatusResponse {
  /** Type of agent */
  agent_type: AgentType;
  
  /** Current status */
  status: AgentStatus;
  
  /** Progress percentage (0-100) */
  progress: number;
  
  /** Number of findings discovered */
  findings_count: number;
  
  /** Last activity timestamp (ISO 8601) */
  last_activity?: string;
  
  /** Error message if status is ERROR */
  error_message?: string;
}

/**
 * Standard result format from any agent.
 * Maps to: agents/orchestrator.py::AgentResult
 */
export interface AgentResult {
  /** Name of the agent */
  agent_name: string;
  
  /** Phase the agent ran in */
  phase: AuditPhase;
  
  /** Result status */
  status: 'success' | 'partial' | 'failed';
  
  /** Findings discovered */
  findings: Finding[];
  
  /** Evidence collected */
  evidence_collected: string[];
  
  /** Evidence gaps identified */
  evidence_gaps: string[];
  
  /** Additional metadata */
  metadata: Record<string, unknown>;
  
  /** Error message if failed */
  error?: string;
}

// ============================================================================
// Report Types
// ============================================================================

/**
 * Summary statistics for an audit.
 */
export interface AuditSummary {
  /** Total findings across all agents */
  total_findings: number;
  
  /** Count by severity */
  critical: number;
  high: number;
  medium: number;
  low: number;
  
  /** Evidence statistics */
  evidence_collected: number;
  evidence_gaps: number;
  
  /** Control statistics */
  controls_assessed?: number;
  controls_passed?: number;
  controls_failed?: number;
  controls_needs_review?: number;
}

/**
 * Anti-hallucination metrics.
 */
export interface AntiHallucinationMetrics {
  /** Number of LLM responses overridden due to validation failure */
  llm_overrides: number;
  
  /** Number of weasel words detected and removed */
  forbidden_words_detected: number;
  
  /** Percentage of claims with proper evidence citation */
  evidence_citation_rate: number;
  
  /** Average confidence across all assessments */
  average_confidence: number;
  
  /** Distribution of confidence scores */
  confidence_distribution: ConfidenceBucket[];
}

/**
 * Confidence score distribution bucket.
 */
export interface ConfidenceBucket {
  /** Range label (e.g., "0.9-1.0") */
  range: string;
  
  /** Count of assessments in this range */
  count: number;
}

/**
 * Final audit report.
 */
export interface AuditReport {
  /** Audit identifier */
  audit_id: string;
  
  /** Framework assessed */
  framework: string;
  
  /** Scope of the audit */
  scope: AuditScope;
  
  /** Start time (ISO 8601) */
  started_at: string;
  
  /** Completion time (ISO 8601) */
  completed_at: string;
  
  /** Overall status determination */
  overall_status: string;
  
  /** Summary statistics */
  summary: AuditSummary;
  
  /** Findings grouped by category */
  findings_by_category: {
    vulnerability: Finding[];
    code_security: Finding[];
    log_analysis: Finding[];
    compliance: ControlAssessment[];
  };
  
  /** Evidence gaps requiring attention */
  evidence_gaps: EvidenceGap[];
  
  /** Phase history for audit trail */
  phase_history: PhaseTransition[];
  
  /** Any errors encountered */
  errors: AuditError[];
  
  /** Anti-hallucination validation metrics */
  anti_hallucination_metrics?: AntiHallucinationMetrics;
}

/**
 * Evidence gap requiring attention.
 */
export interface EvidenceGap {
  /** Related control ID */
  control: string;
  
  /** Description of required evidence */
  requirement: string;
  
  /** Priority level */
  priority: 'high' | 'medium' | 'low';
}

// ============================================================================
// WebSocket Types
// ============================================================================

/**
 * WebSocket message types.
 */
export enum WSMessageType {
  AUDIT_STATUS = 'audit_status',
  AGENT_UPDATE = 'agent_update',
  FINDING_ADDED = 'finding_added',
  EVIDENCE_COLLECTED = 'evidence_collected',
  PHASE_CHANGE = 'phase_change',
  ERROR = 'error',
  HEARTBEAT = 'heartbeat',
}

/**
 * Base WebSocket message structure.
 */
export interface WSMessage<T = unknown> {
  /** Message type */
  type: WSMessageType;
  
  /** Audit ID this message relates to */
  audit_id: string;
  
  /** Timestamp of the message */
  timestamp: string;
  
  /** Message payload */
  payload: T;
}

/**
 * Audit status update payload.
 */
export interface AuditStatusPayload {
  status: AuditStatus;
  progress: number;
  current_phase: AuditPhase;
  message: string;
}

/**
 * Agent update payload.
 */
export interface AgentUpdatePayload {
  agent_type: AgentType;
  status: AgentStatus;
  progress: number;
  findings_count: number;
}

/**
 * Finding added payload.
 */
export interface FindingAddedPayload {
  finding: Finding;
  agent_type: AgentType;
}

// ============================================================================
// API Health Types
// ============================================================================

/**
 * System health response.
 * Maps to: api/routes.py::HealthResponse
 */
export interface HealthResponse {
  /** Overall status */
  status: 'healthy' | 'degraded' | 'unhealthy';
  
  /** Timestamp of the health check */
  timestamp: string;
  
  /** Component health details */
  components: Record<string, ComponentHealth>;
}

/**
 * Individual component health.
 */
export interface ComponentHealth {
  /** Component status */
  status: 'healthy' | 'degraded' | 'unhealthy';
  
  /** Latency in milliseconds */
  latency_ms?: number;
  
  /** Additional metrics */
  [key: string]: unknown;
}

// ============================================================================
// Dashboard Summary Types
// ============================================================================

/**
 * Comprehensive audit summary for dashboard.
 */
export interface DashboardSummary {
  audit_id: string;
  status: AuditStatus;
  target: string;
  progress: number;
  duration_seconds: number;
  
  findings: {
    total: number;
    by_severity: Record<Severity, number>;
  };
  
  evidence: {
    total: number;
  };
  
  agents: AgentProgress[];
  
  compliance: {
    frameworks: string[];
    overall_score: number;
  };
}

/**
 * Agent progress for dashboard.
 */
export interface AgentProgress {
  agent: AgentType;
  status: AgentStatus;
  progress: number;
  findings: number;
}

// ============================================================================
// Type Guards
// ============================================================================

/**
 * Type guard for Severity enum.
 */
export function isSeverity(value: string): value is Severity {
  return Object.values(Severity).includes(value as Severity);
}

/**
 * Type guard for AssessmentState enum.
 */
export function isAssessmentState(value: string): value is AssessmentState {
  return Object.values(AssessmentState).includes(value as AssessmentState);
}

/**
 * Type guard for AuditStatus enum.
 */
export function isAuditStatus(value: string): value is AuditStatus {
  return Object.values(AuditStatus).includes(value as AuditStatus);
}

// ============================================================================
// Utility Types
// ============================================================================

/**
 * Pagination parameters for list endpoints.
 */
export interface PaginationParams {
  limit?: number;
  offset?: number;
}

/**
 * Sort order for list endpoints.
 */
export type SortOrder = 'asc' | 'desc';

/**
 * API error response structure.
 */
export interface APIError {
  detail: string;
  status_code?: number;
}
