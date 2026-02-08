# AI Security Auditor - Session Continuation Guide

## Overview

This document provides a comprehensive guide for continuing development of the AI Security Auditor project. It covers:
1. Remaining deprecation warning fixes
2. API route testing implementation
3. React/Next.js dashboard development

---

## 1. Deprecation Warning Fixes

### Completed
- ✅ `agents/compliance_checker/anti_hallucination.py` - Updated to use `datetime.now(timezone.utc)`

### Remaining Files to Update

#### `utils/resilience.py`
Replace all `datetime.utcnow()` calls with timezone-aware datetime:

```python
# Add at top of file
from datetime import datetime, timezone

def utc_now() -> datetime:
    """Get current UTC time (timezone-aware)."""
    return datetime.now(timezone.utc)
```

**Lines to update:**
- Line 296: `elapsed = (datetime.utcnow() - self.last_failure_time).total_seconds()`
- Line 314: `self.last_failure_time = datetime.utcnow()`
- Line 504: `age = (datetime.utcnow() - timestamp).total_seconds()`
- Line 517: `age = (datetime.utcnow() - timestamp).total_seconds()`
- Line 526: `self._cache[key] = (value, datetime.utcnow())`
- Line 782: `"timestamp": datetime.utcnow().isoformat()`

#### `tests/test_anti_hallucination.py`
- Line 59, 71, 83: Test fixtures using `datetime.utcnow()`
- Line 819: Integration test using `datetime.utcnow()`

#### `tests/test_resilience.py`
- Dataclass default values using `datetime.utcnow()`

---

## 2. API Route Tests

### Test File Structure

Create `tests/test_api_routes.py` with the following test coverage:

### Endpoints to Test

| Endpoint | Method | Description | Test Cases |
|----------|--------|-------------|------------|
| `/health` | GET | Health check | Basic response, status fields |
| `/api/v1/audits` | POST | Start audit | Valid request, missing fields, invalid target |
| `/api/v1/audits` | GET | List audits | Empty list, with results, pagination |
| `/api/v1/audits/{id}` | GET | Get audit | Valid ID, not found, invalid format |
| `/api/v1/audits/{id}/cancel` | POST | Cancel audit | Running audit, completed audit |
| `/api/v1/agents` | GET | List agents | All agents returned |
| `/api/v1/agents/{name}` | GET | Get agent | Valid name, not found |
| `/api/v1/agents/{name}/status` | GET | Agent status | Running, idle, error states |
| `/api/v1/findings` | GET | List findings | Filters, severity, pagination |
| `/api/v1/findings/{id}` | GET | Get finding | Valid ID, not found |
| `/api/v1/findings/summary` | GET | Summary stats | Counts by severity |
| `/api/v1/compliance` | GET | Compliance status | All frameworks |
| `/api/v1/compliance/{framework}` | GET | Framework status | SOC2, GDPR, HIPAA, NIST |
| `/api/v1/compliance/{framework}/controls` | GET | Control details | With evidence |
| `/api/v1/evidence` | GET | List evidence | Filters, pagination |
| `/api/v1/evidence/{id}` | GET | Get evidence | Valid ID, not found |
| `/ws/audit/{id}` | WebSocket | Real-time updates | Connection, messages |

### Test Implementation Pattern

```python
"""Tests for API Routes."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch, AsyncMock
from api.main import app
from api.models import AuditRequest, AuditStatus

@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)

@pytest.fixture
def mock_orchestrator():
    """Mock the security audit orchestrator."""
    with patch('api.routes.orchestrator') as mock:
        mock.start_audit = AsyncMock(return_value="audit-123")
        mock.get_audit_status = Mock(return_value={
            "id": "audit-123",
            "status": "running",
            "progress": 50
        })
        yield mock

class TestHealthEndpoint:
    """Test health check endpoint."""
    
    def test_health_returns_ok(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "timestamp" in data
    
    def test_health_includes_components(self, client):
        response = client.get("/health")
        data = response.json()
        assert "components" in data
        assert "database" in data["components"]
        assert "vector_store" in data["components"]

class TestAuditEndpoints:
    """Test audit management endpoints."""
    
    def test_start_audit_success(self, client, mock_orchestrator):
        response = client.post("/api/v1/audits", json={
            "target": "https://example.com",
            "frameworks": ["SOC2"],
            "scan_types": ["vulnerability", "code"]
        })
        assert response.status_code == 201
        data = response.json()
        assert "audit_id" in data
        assert data["status"] == "started"
    
    def test_start_audit_missing_target(self, client):
        response = client.post("/api/v1/audits", json={
            "frameworks": ["SOC2"]
        })
        assert response.status_code == 422
    
    def test_list_audits_empty(self, client):
        response = client.get("/api/v1/audits")
        assert response.status_code == 200
        data = response.json()
        assert data["items"] == []
        assert data["total"] == 0
    
    def test_get_audit_not_found(self, client):
        response = client.get("/api/v1/audits/nonexistent-id")
        assert response.status_code == 404

class TestAgentEndpoints:
    """Test agent status endpoints."""
    
    def test_list_agents(self, client):
        response = client.get("/api/v1/agents")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 4  # vulnerability, code, log, compliance
        agent_names = [a["name"] for a in data]
        assert "vulnerability_scanner" in agent_names
        assert "code_analyzer" in agent_names
    
    def test_get_agent_status(self, client):
        response = client.get("/api/v1/agents/vulnerability_scanner/status")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "last_run" in data

class TestFindingsEndpoints:
    """Test findings endpoints."""
    
    def test_list_findings_with_severity_filter(self, client):
        response = client.get("/api/v1/findings?severity=critical")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
    
    def test_findings_summary(self, client):
        response = client.get("/api/v1/findings/summary")
        assert response.status_code == 200
        data = response.json()
        assert "critical" in data
        assert "high" in data
        assert "medium" in data
        assert "low" in data

class TestComplianceEndpoints:
    """Test compliance endpoints."""
    
    def test_get_compliance_status(self, client):
        response = client.get("/api/v1/compliance")
        assert response.status_code == 200
        data = response.json()
        assert "frameworks" in data
    
    def test_get_framework_controls(self, client):
        response = client.get("/api/v1/compliance/SOC2/controls")
        assert response.status_code == 200
        data = response.json()
        assert "controls" in data
    
    def test_invalid_framework(self, client):
        response = client.get("/api/v1/compliance/INVALID")
        assert response.status_code == 404

class TestEvidenceEndpoints:
    """Test evidence endpoints."""
    
    def test_list_evidence(self, client):
        response = client.get("/api/v1/evidence")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
    
    def test_get_evidence_not_found(self, client):
        response = client.get("/api/v1/evidence/EVD-nonexistent")
        assert response.status_code == 404

class TestWebSocket:
    """Test WebSocket endpoints."""
    
    def test_websocket_connection(self, client):
        with client.websocket_connect("/ws/audit/test-audit-id") as websocket:
            # Send subscription message
            websocket.send_json({"action": "subscribe"})
            # Should receive acknowledgment
            data = websocket.receive_json()
            assert data["type"] == "subscribed"
```

---

## 3. React Dashboard Implementation

### Technology Decision: Next.js with TypeScript

**Recommendation: Use Next.js with TypeScript (TSX)** instead of plain React.

#### Reasons for Next.js + TypeScript:

| Feature | Next.js + TS | Plain React |
|---------|--------------|-------------|
| **Type Safety** | ✅ Full TypeScript support | ⚠️ Optional, requires setup |
| **File-based Routing** | ✅ Built-in | ❌ Requires react-router |
| **API Routes** | ✅ Built-in `/api` folder | ❌ Separate backend needed |
| **SSR/SSG** | ✅ Built-in | ❌ Requires additional setup |
| **Code Splitting** | ✅ Automatic | ⚠️ Manual configuration |
| **Image Optimization** | ✅ Built-in `next/image` | ❌ Third-party library |
| **Production Ready** | ✅ Zero config | ⚠️ Build setup required |
| **Enterprise Adoption** | ✅ Widely used | ✅ Industry standard |

#### For NVIDIA Interview Context:
- Next.js demonstrates knowledge of modern full-stack patterns
- TypeScript shows attention to code quality and maintainability
- Aligns with enterprise development practices

### Dashboard Architecture

```
dashboard/
├── app/                          # Next.js 14 App Router
│   ├── layout.tsx               # Root layout with providers
│   ├── page.tsx                 # Dashboard home
│   ├── audits/
│   │   ├── page.tsx            # Audit list
│   │   ├── [id]/
│   │   │   └── page.tsx        # Audit detail
│   │   └── new/
│   │       └── page.tsx        # New audit form
│   ├── findings/
│   │   ├── page.tsx            # Findings list
│   │   └── [id]/
│   │       └── page.tsx        # Finding detail
│   ├── compliance/
│   │   ├── page.tsx            # Compliance overview
│   │   └── [framework]/
│   │       └── page.tsx        # Framework detail
│   ├── agents/
│   │   └── page.tsx            # Agent monitoring
│   └── api/                     # API routes (proxy to FastAPI)
│       └── [...path]/
│           └── route.ts
├── components/
│   ├── ui/                      # Shadcn/ui components
│   │   ├── button.tsx
│   │   ├── card.tsx
│   │   ├── badge.tsx
│   │   └── ...
│   ├── dashboard/
│   │   ├── Sidebar.tsx
│   │   ├── Header.tsx
│   │   ├── StatsCards.tsx
│   │   └── RecentActivity.tsx
│   ├── audits/
│   │   ├── AuditCard.tsx
│   │   ├── AuditProgress.tsx
│   │   ├── AuditTimeline.tsx
│   │   └── NewAuditForm.tsx
│   ├── findings/
│   │   ├── FindingsTable.tsx
│   │   ├── FindingCard.tsx
│   │   ├── SeverityBadge.tsx
│   │   └── FindingsChart.tsx
│   ├── compliance/
│   │   ├── ComplianceMatrix.tsx
│   │   ├── ControlCard.tsx
│   │   ├── FrameworkProgress.tsx
│   │   └── EvidencePanel.tsx
│   └── agents/
│       ├── AgentStatusCard.tsx
│       ├── AgentMetrics.tsx
│       └── AgentLogs.tsx
├── lib/
│   ├── api.ts                   # API client
│   ├── websocket.ts             # WebSocket client
│   ├── types.ts                 # TypeScript types
│   └── utils.ts                 # Utility functions
├── hooks/
│   ├── useAudit.ts
│   ├── useFindings.ts
│   ├── useCompliance.ts
│   ├── useAgents.ts
│   └── useWebSocket.ts
├── styles/
│   └── globals.css              # Tailwind CSS
├── public/
│   └── ...
├── next.config.js
├── tailwind.config.js
├── tsconfig.json
└── package.json
```

### Key Components to Implement

#### 1. Dashboard Overview (`app/page.tsx`)

```tsx
// Main dashboard with key metrics
- Total audits (completed/running)
- Critical findings count
- Compliance score by framework
- Agent status indicators
- Recent activity feed
```

#### 2. Audit Management (`app/audits/`)

```tsx
// Audit list with filters
- Status filter (running, completed, failed)
- Date range filter
- Framework filter
- Search by target

// Audit detail page
- Real-time progress via WebSocket
- Agent execution timeline
- Findings discovered
- Compliance impact
```

#### 3. Findings Analysis (`app/findings/`)

```tsx
// Findings table
- Sortable columns
- Severity filtering
- Export functionality
- Bulk actions

// Finding detail
- Full description
- Evidence chain
- Remediation steps
- Related controls
```

#### 4. Compliance Dashboard (`app/compliance/`)

```tsx
// Framework overview
- SOC 2, GDPR, HIPAA, NIST cards
- Overall compliance percentage
- Control status breakdown

// Framework detail
- Control matrix
- Evidence status
- Gap analysis
- Trend charts
```

#### 5. Agent Monitoring (`app/agents/`)

```tsx
// Agent cards
- Status (idle, running, error)
- Last execution time
- Success/failure rate
- Resource utilization

// Agent detail
- Execution history
- Error logs
- Configuration
- Performance metrics
```

### TypeScript Types (`lib/types.ts`)

```typescript
// Core types matching API models

export type AuditStatus = 
  | 'pending' 
  | 'running' 
  | 'completed' 
  | 'failed' 
  | 'cancelled';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Framework = 'SOC2' | 'GDPR' | 'HIPAA' | 'NIST';

export type AssessmentState = 
  | 'pass' 
  | 'fail' 
  | 'insufficient_evidence' 
  | 'evidence_gap' 
  | 'conflicting_evidence' 
  | 'needs_manual_review';

export interface Audit {
  id: string;
  target: string;
  status: AuditStatus;
  frameworks: Framework[];
  scan_types: string[];
  started_at: string;
  completed_at?: string;
  progress: number;
  findings_count: number;
}

export interface Finding {
  id: string;
  audit_id: string;
  title: string;
  description: string;
  severity: Severity;
  category: string;
  source_agent: string;
  evidence_ids: string[];
  remediation: string;
  cwe_id?: string;
  owasp_category?: string;
  affected_controls: string[];
  created_at: string;
}

export interface Control {
  id: string;
  framework: Framework;
  name: string;
  description: string;
  status: AssessmentState;
  evidence_ids: string[];
  findings_ids: string[];
  last_assessed: string;
}

export interface Evidence {
  id: string;
  type: string;
  source: string;
  content_hash: string;
  summary: string;
  collected_at: string;
  collector: string;
}

export interface Agent {
  name: string;
  display_name: string;
  status: 'idle' | 'running' | 'error';
  last_run?: string;
  success_rate: number;
  total_runs: number;
}

export interface ComplianceStatus {
  framework: Framework;
  total_controls: number;
  passed: number;
  failed: number;
  not_assessed: number;
  compliance_percentage: number;
}

// WebSocket message types
export interface WSMessage {
  type: 'progress' | 'finding' | 'agent_status' | 'completed' | 'error';
  audit_id: string;
  data: unknown;
  timestamp: string;
}
```

### API Client (`lib/api.ts`)

```typescript
const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

class ApiClient {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  private async request<T>(
    endpoint: string,
    options?: RequestInit
  ): Promise<T> {
    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    });

    if (!response.ok) {
      throw new ApiError(response.status, await response.text());
    }

    return response.json();
  }

  // Audits
  async listAudits(params?: AuditListParams) { ... }
  async getAudit(id: string) { ... }
  async startAudit(request: AuditRequest) { ... }
  async cancelAudit(id: string) { ... }

  // Findings
  async listFindings(params?: FindingListParams) { ... }
  async getFinding(id: string) { ... }
  async getFindingsSummary() { ... }

  // Compliance
  async getComplianceStatus() { ... }
  async getFrameworkStatus(framework: Framework) { ... }
  async getFrameworkControls(framework: Framework) { ... }

  // Evidence
  async listEvidence(params?: EvidenceListParams) { ... }
  async getEvidence(id: string) { ... }

  // Agents
  async listAgents() { ... }
  async getAgentStatus(name: string) { ... }
}

export const api = new ApiClient(API_BASE);
```

### WebSocket Hook (`hooks/useWebSocket.ts`)

```typescript
import { useEffect, useRef, useState, useCallback } from 'react';
import type { WSMessage } from '@/lib/types';

export function useAuditWebSocket(auditId: string) {
  const [messages, setMessages] = useState<WSMessage[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  const connect = useCallback(() => {
    const ws = new WebSocket(
      `${process.env.NEXT_PUBLIC_WS_URL}/ws/audit/${auditId}`
    );

    ws.onopen = () => setIsConnected(true);
    ws.onclose = () => setIsConnected(false);
    ws.onmessage = (event) => {
      const message = JSON.parse(event.data) as WSMessage;
      setMessages((prev) => [...prev, message]);
    };

    wsRef.current = ws;
  }, [auditId]);

  useEffect(() => {
    connect();
    return () => wsRef.current?.close();
  }, [connect]);

  return { messages, isConnected };
}
```

### Setup Commands

```bash
# Create Next.js project with TypeScript
npx create-next-app@latest dashboard --typescript --tailwind --eslint --app

cd dashboard

# Install dependencies
npm install @tanstack/react-query axios recharts date-fns
npm install lucide-react class-variance-authority clsx tailwind-merge

# Install shadcn/ui
npx shadcn-ui@latest init
npx shadcn-ui@latest add button card badge table tabs
npx shadcn-ui@latest add dialog dropdown-menu input label
npx shadcn-ui@latest add progress select skeleton toast

# Development
npm run dev
```

### Environment Variables

```env
# .env.local
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_WS_URL=ws://localhost:8000
```

---

## 4. Project Integration

### Directory Structure After Dashboard Addition

```
ai-security-auditor/
├── agents/                      # Python agents
├── api/                         # FastAPI backend
├── dashboard/                   # Next.js frontend (NEW)
├── frameworks/                  # Compliance frameworks
├── tests/                       # Python tests
├── utils/                       # Python utilities
├── docker-compose.yml           # Full stack deployment
└── README.md
```

### Docker Compose for Full Stack

```yaml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/auditor
      - CHROMA_HOST=chromadb
    depends_on:
      - db
      - chromadb

  dashboard:
    build: ./dashboard
    ports:
      - "3000:3000"
    environment:
      - NEXT_PUBLIC_API_URL=http://api:8000
      - NEXT_PUBLIC_WS_URL=ws://api:8000
    depends_on:
      - api

  db:
    image: postgres:15
    environment:
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
      - POSTGRES_DB=auditor
    volumes:
      - postgres_data:/var/lib/postgresql/data

  chromadb:
    image: chromadb/chroma:latest
    ports:
      - "8001:8000"
    volumes:
      - chroma_data:/chroma/chroma

volumes:
  postgres_data:
  chroma_data:
```

---

## 5. Quick Start for Next Session

### Priority Order

1. **Fix remaining deprecation warnings** (~10 min)
   - Update `utils/resilience.py`
   - Update test files

2. **Create API tests** (~30 min)
   - Create `tests/test_api_routes.py`
   - Run full test suite

3. **Initialize Next.js dashboard** (~20 min)
   - Create project structure
   - Set up Tailwind + shadcn/ui
   - Create base layout

4. **Implement core components** (~2-3 hours)
   - Dashboard overview
   - Audit management
   - Findings display
   - Compliance matrix

### Commands to Run

```bash
# 1. Run tests to verify everything works
cd /Users/chitownj/Desktop/development/ai-security-auditor
pytest tests/ -v --tb=short

# 2. Start FastAPI backend
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

# 3. In another terminal, create and start dashboard
npx create-next-app@latest dashboard --typescript --tailwind --eslint --app
cd dashboard
npm run dev
```

---

## Summary

| Task | Status | Priority |
|------|--------|----------|
| Fix anti_hallucination.py deprecations | ✅ Done | - |
| Fix resilience.py deprecations | ⏳ Pending | High |
| Fix test file deprecations | ⏳ Pending | High |
| Create API route tests | ⏳ Pending | High |
| Initialize Next.js dashboard | ⏳ Pending | Medium |
| Implement dashboard components | ⏳ Pending | Medium |
| Docker compose setup | ⏳ Pending | Low |

**Recommended Technology:** Next.js 14 with TypeScript (App Router) + Tailwind CSS + shadcn/ui

This combination provides:
- Type safety for complex data models
- Modern React patterns (Server Components, Suspense)
- Production-ready build system
- Excellent developer experience
- Enterprise-grade architecture for NVIDIA interview presentation
