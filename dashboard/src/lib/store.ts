/**
 * Global State Store using Zustand
 * 
 * Manages global application state including selected audit,
 * user preferences, and real-time data.
 * 
 * @module lib/store
 */

import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import {
  AuditResponse,
  AuditStatus,
  AgentType,
  AgentStatusResponse,
  Finding,
  Severity,
} from '@/types';

// ============================================================================
// Store Types
// ============================================================================

interface AuditStore {
  // Selected audit
  selectedAuditId: string | null;
  selectedAudit: AuditResponse | null;
  setSelectedAudit: (audit: AuditResponse | null) => void;
  
  // Audits list
  audits: AuditResponse[];
  setAudits: (audits: AuditResponse[]) => void;
  updateAudit: (audit: AuditResponse) => void;
  
  // Agent statuses for selected audit
  agentStatuses: Map<AgentType, AgentStatusResponse>;
  setAgentStatuses: (statuses: AgentStatusResponse[]) => void;
  updateAgentStatus: (status: AgentStatusResponse) => void;
  
  // Recent findings (real-time)
  recentFindings: Finding[];
  addFinding: (finding: Finding) => void;
  clearFindings: () => void;
  
  // Notifications
  notifications: Notification[];
  addNotification: (notification: Omit<Notification, 'id' | 'timestamp'>) => void;
  removeNotification: (id: string) => void;
  clearNotifications: () => void;
  
  // Actions
  reset: () => void;
}

interface Notification {
  id: string;
  type: 'info' | 'success' | 'warning' | 'error';
  title: string;
  message?: string;
  timestamp: string;
}

interface UIStore {
  // Sidebar
  sidebarOpen: boolean;
  toggleSidebar: () => void;
  setSidebarOpen: (open: boolean) => void;
  
  // Theme
  theme: 'light' | 'dark' | 'system';
  setTheme: (theme: 'light' | 'dark' | 'system') => void;
  
  // View preferences
  findingsView: 'table' | 'cards';
  setFindingsView: (view: 'table' | 'cards') => void;
  
  // Filters
  severityFilter: Severity | null;
  setSeverityFilter: (severity: Severity | null) => void;
  agentFilter: AgentType | null;
  setAgentFilter: (agent: AgentType | null) => void;
  
  // Reset
  resetFilters: () => void;
}

// ============================================================================
// Audit Store
// ============================================================================

export const useAuditStore = create<AuditStore>()((set, get) => ({
  // Selected audit
  selectedAuditId: null,
  selectedAudit: null,
  setSelectedAudit: (audit) =>
    set({
      selectedAudit: audit,
      selectedAuditId: audit?.audit_id || null,
    }),
  
  // Audits list
  audits: [],
  setAudits: (audits) => set({ audits }),
  updateAudit: (audit) =>
    set((state) => ({
      audits: state.audits.map((a) =>
        a.audit_id === audit.audit_id ? audit : a
      ),
      selectedAudit:
        state.selectedAuditId === audit.audit_id ? audit : state.selectedAudit,
    })),
  
  // Agent statuses
  agentStatuses: new Map(),
  setAgentStatuses: (statuses) =>
    set({
      agentStatuses: new Map(statuses.map((s) => [s.agent_type, s])),
    }),
  updateAgentStatus: (status) =>
    set((state) => {
      const updated = new Map(state.agentStatuses);
      updated.set(status.agent_type, status);
      return { agentStatuses: updated };
    }),
  
  // Recent findings
  recentFindings: [],
  addFinding: (finding) =>
    set((state) => ({
      recentFindings: [finding, ...state.recentFindings.slice(0, 99)],
    })),
  clearFindings: () => set({ recentFindings: [] }),
  
  // Notifications
  notifications: [],
  addNotification: (notification) =>
    set((state) => ({
      notifications: [
        {
          ...notification,
          id: `notif-${Date.now()}-${Math.random().toString(36).slice(2)}`,
          timestamp: new Date().toISOString(),
        },
        ...state.notifications.slice(0, 49),
      ],
    })),
  removeNotification: (id) =>
    set((state) => ({
      notifications: state.notifications.filter((n) => n.id !== id),
    })),
  clearNotifications: () => set({ notifications: [] }),
  
  // Reset
  reset: () =>
    set({
      selectedAuditId: null,
      selectedAudit: null,
      audits: [],
      agentStatuses: new Map(),
      recentFindings: [],
      notifications: [],
    }),
}));

// ============================================================================
// UI Store (Persisted)
// ============================================================================

export const useUIStore = create<UIStore>()(
  persist(
    (set) => ({
      // Sidebar
      sidebarOpen: true,
      toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
      setSidebarOpen: (open) => set({ sidebarOpen: open }),
      
      // Theme
      theme: 'system',
      setTheme: (theme) => set({ theme }),
      
      // View preferences
      findingsView: 'table',
      setFindingsView: (view) => set({ findingsView: view }),
      
      // Filters
      severityFilter: null,
      setSeverityFilter: (severity) => set({ severityFilter: severity }),
      agentFilter: null,
      setAgentFilter: (agent) => set({ agentFilter: agent }),
      
      // Reset filters
      resetFilters: () =>
        set({
          severityFilter: null,
          agentFilter: null,
        }),
    }),
    {
      name: 'security-auditor-ui',
      partialize: (state) => ({
        sidebarOpen: state.sidebarOpen,
        theme: state.theme,
        findingsView: state.findingsView,
      }),
    }
  )
);

// ============================================================================
// Selectors
// ============================================================================

/**
 * Get findings filtered by current UI filters.
 */
export function useFilteredFindings(): Finding[] {
  const { recentFindings } = useAuditStore();
  const { severityFilter, agentFilter } = useUIStore();

  let filtered = recentFindings;

  if (severityFilter) {
    filtered = filtered.filter((f) => f.severity === severityFilter);
  }

  if (agentFilter) {
    filtered = filtered.filter((f) => f.agent_type === agentFilter);
  }

  return filtered;
}

/**
 * Get active audits count.
 */
export function useActiveAuditsCount(): number {
  const { audits } = useAuditStore();
  return audits.filter(
    (a) => a.status === AuditStatus.RUNNING || a.status === AuditStatus.PENDING
  ).length;
}

/**
 * Get agent progress percentage for selected audit.
 */
export function useOverallProgress(): number {
  const { agentStatuses } = useAuditStore();
  
  if (agentStatuses.size === 0) return 0;
  
  let total = 0;
  agentStatuses.forEach((status) => {
    total += status.progress;
  });
  
  return total / agentStatuses.size;
}
