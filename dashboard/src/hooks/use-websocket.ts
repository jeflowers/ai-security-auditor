/**
 * WebSocket Hooks for Real-Time Audit Updates
 * 
 * Provides React hooks for subscribing to audit status updates
 * via WebSocket connection to the FastAPI backend.
 * 
 * @module hooks/use-websocket
 */

import { useEffect, useRef, useCallback, useState } from 'react';
import {
  WSMessage,
  WSMessageType,
  AuditStatusPayload,
  AgentUpdatePayload,
  FindingAddedPayload,
  AuditStatus,
  AgentType,
  Finding,
} from '@/types';

// ============================================================================
// Types
// ============================================================================

/**
 * WebSocket connection state.
 */
export enum WSConnectionState {
  CONNECTING = 'connecting',
  CONNECTED = 'connected',
  DISCONNECTED = 'disconnected',
  RECONNECTING = 'reconnecting',
  ERROR = 'error',
}

/**
 * WebSocket hook options.
 */
export interface UseAuditWebSocketOptions {
  /** Audit ID to subscribe to */
  auditId: string;
  
  /** Whether to auto-connect on mount (default: true) */
  autoConnect?: boolean;
  
  /** Reconnect on disconnect (default: true) */
  autoReconnect?: boolean;
  
  /** Maximum reconnect attempts (default: 5) */
  maxReconnectAttempts?: number;
  
  /** Reconnect interval in ms (default: 3000) */
  reconnectInterval?: number;
  
  /** Heartbeat interval in ms (default: 30000) */
  heartbeatInterval?: number;
  
  /** Callback when status updates */
  onStatusUpdate?: (payload: AuditStatusPayload) => void;
  
  /** Callback when agent updates */
  onAgentUpdate?: (payload: AgentUpdatePayload) => void;
  
  /** Callback when finding is added */
  onFindingAdded?: (payload: FindingAddedPayload) => void;
  
  /** Callback when phase changes */
  onPhaseChange?: (phase: string) => void;
  
  /** Callback on connection state change */
  onConnectionChange?: (state: WSConnectionState) => void;
  
  /** Callback on error */
  onError?: (error: Error) => void;
}

/**
 * WebSocket hook return value.
 */
export interface UseAuditWebSocketReturn {
  /** Current connection state */
  connectionState: WSConnectionState;
  
  /** Latest audit status */
  auditStatus: AuditStatusPayload | null;
  
  /** Latest agent updates by type */
  agentUpdates: Map<AgentType, AgentUpdatePayload>;
  
  /** Recently added findings */
  recentFindings: Finding[];
  
  /** Current phase */
  currentPhase: string | null;
  
  /** Connect to WebSocket */
  connect: () => void;
  
  /** Disconnect from WebSocket */
  disconnect: () => void;
  
  /** Send a message */
  send: (message: unknown) => void;
  
  /** Last error */
  error: Error | null;
}

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_OPTIONS = {
  autoConnect: true,
  autoReconnect: true,
  maxReconnectAttempts: 5,
  reconnectInterval: 3000,
  heartbeatInterval: 30000,
};

// ============================================================================
// Main Hook
// ============================================================================

/**
 * Hook for subscribing to real-time audit updates via WebSocket.
 * 
 * @example
 * ```tsx
 * const {
 *   connectionState,
 *   auditStatus,
 *   agentUpdates,
 *   recentFindings,
 * } = useAuditWebSocket({
 *   auditId: 'AUDIT-001',
 *   onStatusUpdate: (status) => console.log('Status:', status),
 *   onFindingAdded: (finding) => console.log('New finding:', finding),
 * });
 * ```
 */
export function useAuditWebSocket(
  options: UseAuditWebSocketOptions
): UseAuditWebSocketReturn {
  const {
    auditId,
    autoConnect = DEFAULT_OPTIONS.autoConnect,
    autoReconnect = DEFAULT_OPTIONS.autoReconnect,
    maxReconnectAttempts = DEFAULT_OPTIONS.maxReconnectAttempts,
    reconnectInterval = DEFAULT_OPTIONS.reconnectInterval,
    heartbeatInterval = DEFAULT_OPTIONS.heartbeatInterval,
    onStatusUpdate,
    onAgentUpdate,
    onFindingAdded,
    onPhaseChange,
    onConnectionChange,
    onError,
  } = options;

  // State
  const [connectionState, setConnectionState] = useState<WSConnectionState>(
    WSConnectionState.DISCONNECTED
  );
  const [auditStatus, setAuditStatus] = useState<AuditStatusPayload | null>(null);
  const [agentUpdates, setAgentUpdates] = useState<Map<AgentType, AgentUpdatePayload>>(
    new Map()
  );
  const [recentFindings, setRecentFindings] = useState<Finding[]>([]);
  const [currentPhase, setCurrentPhase] = useState<string | null>(null);
  const [error, setError] = useState<Error | null>(null);

  // Refs
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const heartbeatIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // Update connection state with callback
  const updateConnectionState = useCallback(
    (state: WSConnectionState) => {
      setConnectionState(state);
      onConnectionChange?.(state);
    },
    [onConnectionChange]
  );

  // Handle incoming messages
  const handleMessage = useCallback(
    (event: MessageEvent) => {
      try {
        const message: WSMessage = JSON.parse(event.data);

        switch (message.type) {
          case WSMessageType.AUDIT_STATUS: {
            const payload = message.payload as AuditStatusPayload;
            setAuditStatus(payload);
            onStatusUpdate?.(payload);
            break;
          }

          case WSMessageType.AGENT_UPDATE: {
            const payload = message.payload as AgentUpdatePayload;
            setAgentUpdates((prev) => {
              const updated = new Map(prev);
              updated.set(payload.agent_type, payload);
              return updated;
            });
            onAgentUpdate?.(payload);
            break;
          }

          case WSMessageType.FINDING_ADDED: {
            const payload = message.payload as FindingAddedPayload;
            setRecentFindings((prev) => [payload.finding, ...prev.slice(0, 49)]);
            onFindingAdded?.(payload);
            break;
          }

          case WSMessageType.PHASE_CHANGE: {
            const phase = message.payload as string;
            setCurrentPhase(phase);
            onPhaseChange?.(phase);
            break;
          }

          case WSMessageType.ERROR: {
            const errorPayload = message.payload as { message: string };
            const err = new Error(errorPayload.message);
            setError(err);
            onError?.(err);
            break;
          }

          case WSMessageType.HEARTBEAT:
            // Heartbeat received, connection is alive
            break;

          default:
            console.warn('Unknown WebSocket message type:', message.type);
        }
      } catch (err) {
        console.error('Failed to parse WebSocket message:', err);
      }
    },
    [onStatusUpdate, onAgentUpdate, onFindingAdded, onPhaseChange, onError]
  );

  // Connect to WebSocket
  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return;
    }

    updateConnectionState(WSConnectionState.CONNECTING);

    // Construct WebSocket URL - connect to API server on port 8000
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.hostname;
    const wsUrl = `${protocol}//${host}:8000/ws/audits/${auditId}`;

    console.log('Connecting to WebSocket:', wsUrl);

    try {
      const ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        updateConnectionState(WSConnectionState.CONNECTED);
        reconnectAttemptsRef.current = 0;
        setError(null);

        // Start heartbeat
        heartbeatIntervalRef.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ping' }));
          }
        }, heartbeatInterval);
      };

      ws.onclose = () => {
        updateConnectionState(WSConnectionState.DISCONNECTED);
        
        // Clear heartbeat
        if (heartbeatIntervalRef.current) {
          clearInterval(heartbeatIntervalRef.current);
          heartbeatIntervalRef.current = null;
        }

        // Attempt reconnection
        if (autoReconnect && reconnectAttemptsRef.current < maxReconnectAttempts) {
          updateConnectionState(WSConnectionState.RECONNECTING);
          reconnectAttemptsRef.current += 1;
          reconnectTimeoutRef.current = setTimeout(() => {
            connect();
          }, reconnectInterval);
        }
      };

      ws.onerror = (event) => {
        const err = new Error('WebSocket error');
        setError(err);
        onError?.(err);
        updateConnectionState(WSConnectionState.ERROR);
      };

      ws.onmessage = handleMessage;

      wsRef.current = ws;
    } catch (err) {
      const error = err instanceof Error ? err : new Error('Failed to connect');
      setError(error);
      onError?.(error);
      updateConnectionState(WSConnectionState.ERROR);
    }
  }, [
    auditId,
    autoReconnect,
    maxReconnectAttempts,
    reconnectInterval,
    heartbeatInterval,
    handleMessage,
    onError,
    updateConnectionState,
  ]);

  // Disconnect from WebSocket
  const disconnect = useCallback(() => {
    // Clear timeouts
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    if (heartbeatIntervalRef.current) {
      clearInterval(heartbeatIntervalRef.current);
      heartbeatIntervalRef.current = null;
    }

    // Close connection
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }

    reconnectAttemptsRef.current = 0;
    updateConnectionState(WSConnectionState.DISCONNECTED);
  }, [updateConnectionState]);

  // Send a message
  const send = useCallback((message: unknown) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message));
    } else {
      console.warn('WebSocket is not connected');
    }
  }, []);

  // Auto-connect on mount
  useEffect(() => {
    if (autoConnect) {
      connect();
    }

    return () => {
      disconnect();
    };
  }, [auditId]); // Reconnect when auditId changes

  return {
    connectionState,
    auditStatus,
    agentUpdates,
    recentFindings,
    currentPhase,
    connect,
    disconnect,
    send,
    error,
  };
}

// ============================================================================
// Simplified Hooks
// ============================================================================

/**
 * Simple hook for just the connection state.
 */
export function useAuditConnectionState(auditId: string): WSConnectionState {
  const { connectionState } = useAuditWebSocket({ auditId });
  return connectionState;
}

/**
 * Hook for subscribing to audit status updates only.
 */
export function useAuditStatusUpdates(
  auditId: string,
  onUpdate?: (status: AuditStatusPayload) => void
): AuditStatusPayload | null {
  const { auditStatus } = useAuditWebSocket({
    auditId,
    onStatusUpdate: onUpdate,
  });
  return auditStatus;
}

/**
 * Hook for subscribing to agent updates only.
 */
export function useAgentUpdates(
  auditId: string,
  onUpdate?: (update: AgentUpdatePayload) => void
): Map<AgentType, AgentUpdatePayload> {
  const { agentUpdates } = useAuditWebSocket({
    auditId,
    onAgentUpdate: onUpdate,
  });
  return agentUpdates;
}

/**
 * Hook for subscribing to new findings.
 */
export function useFindingsStream(
  auditId: string,
  onFinding?: (payload: FindingAddedPayload) => void
): Finding[] {
  const { recentFindings } = useAuditWebSocket({
    auditId,
    onFindingAdded: onFinding,
  });
  return recentFindings;
}
