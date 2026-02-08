/**
 * useAuditData Hook
 * 
 * Provides real-time audit data via WebSocket connection.
 * Features:
 * - Automatic reconnection with exponential backoff
 * - Connection state tracking
 * - Error handling
 * - Graceful cleanup
 */

import { useState, useEffect, useRef, useCallback } from 'react';

// API base URL from environment or default to localhost
const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

/**
 * Convert HTTP URL to WebSocket URL
 * Handles both http→ws and https→wss
 */
const getWebSocketUrl = (baseUrl, auditId) => {
  const wsUrl = baseUrl.replace(/^http/, 'ws');
  return `${wsUrl}/ws/audit/${auditId}`;
};

/**
 * Audit data hook for real-time WebSocket updates
 * 
 * @param {string} auditId - The audit ID to subscribe to
 * @param {Object} options - Configuration options
 * @param {number} options.maxReconnectAttempts - Maximum reconnection attempts (default: 5)
 * @param {number} options.initialReconnectDelay - Initial reconnection delay in ms (default: 1000)
 * @param {number} options.maxReconnectDelay - Maximum reconnection delay in ms (default: 30000)
 * @returns {Object} - { data, connected, error, reconnecting, reconnectAttempts }
 */
export function useAuditData(auditId, options = {}) {
  const {
    maxReconnectAttempts = 5,
    initialReconnectDelay = 1000,
    maxReconnectDelay = 30000,
  } = options;

  const [data, setData] = useState(null);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState(null);
  const [reconnecting, setReconnecting] = useState(false);
  
  // Use refs for values that shouldn't trigger re-renders
  const wsRef = useRef(null);
  const reconnectAttemptsRef = useRef(0);
  const reconnectTimeoutRef = useRef(null);
  const isMountedRef = useRef(true);

  /**
   * Calculate exponential backoff delay
   */
  const getReconnectDelay = useCallback((attempt) => {
    const delay = Math.min(
      initialReconnectDelay * Math.pow(2, attempt),
      maxReconnectDelay
    );
    // Add jitter to prevent thundering herd
    return delay + Math.random() * 1000;
  }, [initialReconnectDelay, maxReconnectDelay]);

  /**
   * Connect to WebSocket
   */
  const connect = useCallback(() => {
    if (!auditId || !isMountedRef.current) return;

    const wsUrl = getWebSocketUrl(API_BASE, auditId);
    console.log(`[WebSocket] Connecting to ${wsUrl}`);

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!isMountedRef.current) return;
        console.log('[WebSocket] Connected');
        setConnected(true);
        setError(null);
        setReconnecting(false);
        reconnectAttemptsRef.current = 0;
      };

      ws.onmessage = (event) => {
        if (!isMountedRef.current) return;
        
        try {
          const message = JSON.parse(event.data);
          
          switch (message.type) {
            case 'connected':
              console.log('[WebSocket] Connection confirmed:', message.data);
              break;
              
            case 'status_update':
              setData(message.data);
              break;
              
            case 'phase_change':
              console.log('[WebSocket] Phase change:', message.data);
              break;
              
            case 'audit_complete':
              console.log('[WebSocket] Audit complete:', message.data);
              // Update data one final time
              if (message.data) {
                setData(prev => ({ ...prev, ...message.data }));
              }
              break;
              
            case 'ping':
              // Heartbeat - no action needed, but could log for debugging
              break;
              
            case 'error':
              console.error('[WebSocket] Server error:', message.error);
              setError(message.error);
              break;
              
            default:
              console.log('[WebSocket] Unknown message type:', message.type);
          }
        } catch (e) {
          console.error('[WebSocket] Failed to parse message:', e);
        }
      };

      ws.onerror = (event) => {
        console.error('[WebSocket] Error:', event);
        if (isMountedRef.current) {
          setError('WebSocket connection error');
        }
      };

      ws.onclose = (event) => {
        if (!isMountedRef.current) return;
        
        console.log(`[WebSocket] Closed: code=${event.code}, reason=${event.reason}`);
        setConnected(false);
        wsRef.current = null;

        // Don't reconnect if:
        // - Component unmounted
        // - Server intentionally closed (code 4004 = audit not found)
        // - Normal closure after audit complete
        if (event.code === 4004 || event.code === 1000) {
          console.log('[WebSocket] Not reconnecting - intentional close');
          return;
        }

        // Attempt reconnection with exponential backoff
        if (reconnectAttemptsRef.current < maxReconnectAttempts) {
          const delay = getReconnectDelay(reconnectAttemptsRef.current);
          console.log(`[WebSocket] Reconnecting in ${Math.round(delay)}ms (attempt ${reconnectAttemptsRef.current + 1}/${maxReconnectAttempts})`);
          
          setReconnecting(true);
          reconnectTimeoutRef.current = setTimeout(() => {
            reconnectAttemptsRef.current++;
            connect();
          }, delay);
        } else {
          console.log('[WebSocket] Max reconnection attempts reached');
          setError('Unable to connect. Please refresh the page.');
          setReconnecting(false);
        }
      };
    } catch (e) {
      console.error('[WebSocket] Failed to create connection:', e);
      setError('Failed to create WebSocket connection');
    }
  }, [auditId, maxReconnectAttempts, getReconnectDelay]);

  /**
   * Manual reconnect function
   */
  const reconnect = useCallback(() => {
    // Clear any pending reconnection
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    
    // Close existing connection
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    
    // Reset state and reconnect
    reconnectAttemptsRef.current = 0;
    setError(null);
    connect();
  }, [connect]);

  /**
   * Effect: Connect when auditId changes
   */
  useEffect(() => {
    isMountedRef.current = true;
    
    if (auditId) {
      connect();
    }
    
    // Cleanup on unmount or auditId change
    return () => {
      isMountedRef.current = false;
      
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = null;
      }
      
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [auditId, connect]);

  return {
    data,
    connected,
    error,
    reconnecting,
    reconnectAttempts: reconnectAttemptsRef.current,
    reconnect,
  };
}

/**
 * Hook to start a new audit and get its ID
 * 
 * @returns {Object} - { startAudit, auditId, loading, error }
 */
export function useStartAudit() {
  const [auditId, setAuditId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const startAudit = useCallback(async (config) => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch(`${API_BASE}/api/v1/audits`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(config),
      });
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `HTTP error: ${response.status}`);
      }
      
      const data = await response.json();
      setAuditId(data.audit_id);
      return data.audit_id;
    } catch (e) {
      console.error('[API] Failed to start audit:', e);
      setError(e.message);
      throw e;
    } finally {
      setLoading(false);
    }
  }, []);

  return {
    startAudit,
    auditId,
    loading,
    error,
    setAuditId,
  };
}

/**
 * Hook to fetch list of all audits
 * 
 * @returns {Object} - { audits, loading, error, refresh }
 */
export function useAuditList() {
  const [audits, setAudits] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchAudits = useCallback(async () => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch(`${API_BASE}/api/v1/audits`);
      
      if (!response.ok) {
        throw new Error(`HTTP error: ${response.status}`);
      }
      
      const data = await response.json();
      setAudits(data.audits || []);
    } catch (e) {
      console.error('[API] Failed to fetch audits:', e);
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAudits();
  }, [fetchAudits]);

  return {
    audits,
    loading,
    error,
    refresh: fetchAudits,
  };
}

export default useAuditData;
