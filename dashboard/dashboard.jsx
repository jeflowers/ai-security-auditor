import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { 
  Shield, AlertTriangle, CheckCircle, XCircle, Clock, 
  FileText, Server, Code, Activity, Eye, AlertOctagon,
  ChevronDown, ChevronRight, RefreshCw, Download, Loader2,
  Search, Filter, ExternalLink
} from 'lucide-react';
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, 
  ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line,
  RadialBarChart, RadialBar
} from 'recharts';

// =============================================================================
// API CONFIGURATION & TYPES
// =============================================================================

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

// Assessment status types matching backend AssessmentStatus enum
const AssessmentStatus = {
  PASS: 'PASS',
  FAIL: 'FAIL',
  INSUFFICIENT_EVIDENCE: 'INSUFFICIENT_EVIDENCE',
  EVIDENCE_GAP: 'EVIDENCE_GAP',
  CONFLICTING_EVIDENCE: 'CONFLICTING_EVIDENCE',
  NEEDS_MANUAL_REVIEW: 'NEEDS_MANUAL_REVIEW'
};

// Framework identifiers
const Frameworks = {
  SOC2: 'SOC2',
  GDPR: 'GDPR',
  HIPAA: 'HIPAA',
  NIST: 'NIST-800-53A'
};

// =============================================================================
// FRAMEWORK-SPECIFIC CONTROL DATA (Fallback when API unavailable)
// =============================================================================

const frameworkControls = {
  [Frameworks.SOC2]: {
    name: 'SOC 2 Type II',
    description: 'Trust Service Criteria for Service Organizations',
    controls: [
      { id: 'CC6.1', name: 'Logical Access Security', category: 'Common Criteria', status: AssessmentStatus.FAIL, confidence: 0.85, evidence_count: 0, description: 'The entity implements logical access security software, infrastructure, and architectures over protected information assets.' },
      { id: 'CC6.2', name: 'User Registration', category: 'Common Criteria', status: AssessmentStatus.PASS, confidence: 0.85, evidence_count: 0, description: 'Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users.' },
      { id: 'CC6.3', name: 'User Access Removal', category: 'Common Criteria', status: AssessmentStatus.PASS, confidence: 0.85, evidence_count: 0, description: 'The entity removes access to protected information assets when appropriate.' },
      { id: 'CC6.6', name: 'External Threat Protection', category: 'Common Criteria', status: AssessmentStatus.FAIL, confidence: 0.85, evidence_count: 0, description: 'The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software.' },
      { id: 'CC6.7', name: 'Information Transmission', category: 'Common Criteria', status: AssessmentStatus.NEEDS_MANUAL_REVIEW, confidence: 0.85, evidence_count: 0, description: 'The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes.' },
      { id: 'CC7.1', name: 'Security Event Detection', category: 'Common Criteria', status: AssessmentStatus.FAIL, confidence: 0.85, evidence_count: 0, description: 'To meet its objectives, the entity uses detection and monitoring procedures to identify anomalies that could indicate attacks.' },
      { id: 'CC7.2', name: 'System Monitoring', category: 'Common Criteria', status: AssessmentStatus.PASS, confidence: 0.85, evidence_count: 0, description: 'The entity monitors system components and the operation of those components for anomalies.' },
      { id: 'CC7.3', name: 'Security Event Evaluation', category: 'Common Criteria', status: AssessmentStatus.NEEDS_MANUAL_REVIEW, confidence: 0.85, evidence_count: 0, description: 'The entity evaluates security events to determine whether they could or have resulted in a failure of the entity to meet its objectives.' },
      { id: 'CC8.1', name: 'Change Management', category: 'Common Criteria', status: AssessmentStatus.PASS, confidence: 0.85, evidence_count: 0, description: 'The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures.' },
      { id: 'CC9.1', name: 'Risk Assessment', category: 'Common Criteria', status: AssessmentStatus.PASS, confidence: 0.85, evidence_count: 0, description: 'The entity identifies and assesses risk that could affect the achievement of its objectives.' },
      { id: 'A1.1', name: 'Availability Commitments', category: 'Availability', status: AssessmentStatus.PASS, confidence: 0.85, evidence_count: 0, description: 'The entity maintains, monitors, and evaluates current processing capacity and use of system components.' },
      { id: 'C1.1', name: 'Confidentiality Commitments', category: 'Confidentiality', status: AssessmentStatus.PASS, confidence: 0.85, evidence_count: 0, description: 'The entity identifies and maintains confidential information to meet the entity\'s objectives related to confidentiality.' },
    ]
  },
  [Frameworks.GDPR]: {
    name: 'GDPR',
    description: 'General Data Protection Regulation (EU)',
    controls: [
      { id: 'Art.5', name: 'Principles of Processing', category: 'Core Principles', status: AssessmentStatus.PASS, confidence: 0.82, evidence_count: 0, description: 'Personal data shall be processed lawfully, fairly and in a transparent manner.' },
      { id: 'Art.6', name: 'Lawfulness of Processing', category: 'Core Principles', status: AssessmentStatus.PASS, confidence: 0.88, evidence_count: 0, description: 'Processing shall be lawful only if and to the extent that at least one legal basis applies.' },
      { id: 'Art.7', name: 'Conditions for Consent', category: 'Consent', status: AssessmentStatus.NEEDS_MANUAL_REVIEW, confidence: 0.75, evidence_count: 0, description: 'Where processing is based on consent, the controller shall be able to demonstrate that the data subject has consented.' },
      { id: 'Art.12', name: 'Transparent Information', category: 'Data Subject Rights', status: AssessmentStatus.PASS, confidence: 0.90, evidence_count: 0, description: 'The controller shall take appropriate measures to provide information in a concise, transparent, intelligible and easily accessible form.' },
      { id: 'Art.13', name: 'Information at Collection', category: 'Data Subject Rights', status: AssessmentStatus.PASS, confidence: 0.87, evidence_count: 0, description: 'Where personal data are collected from the data subject, the controller shall provide specified information.' },
      { id: 'Art.15', name: 'Right of Access', category: 'Data Subject Rights', status: AssessmentStatus.PASS, confidence: 0.85, evidence_count: 0, description: 'The data subject shall have the right to obtain confirmation as to whether personal data concerning them is being processed.' },
      { id: 'Art.17', name: 'Right to Erasure', category: 'Data Subject Rights', status: AssessmentStatus.NEEDS_MANUAL_REVIEW, confidence: 0.72, evidence_count: 0, description: 'The data subject shall have the right to obtain erasure of personal data (right to be forgotten).' },
      { id: 'Art.25', name: 'Data Protection by Design', category: 'Technical Measures', status: AssessmentStatus.FAIL, confidence: 0.68, evidence_count: 0, description: 'The controller shall implement appropriate technical and organisational measures designed to implement data-protection principles.' },
      { id: 'Art.30', name: 'Records of Processing', category: 'Documentation', status: AssessmentStatus.PASS, confidence: 0.91, evidence_count: 0, description: 'Each controller shall maintain a record of processing activities under its responsibility.' },
      { id: 'Art.32', name: 'Security of Processing', category: 'Technical Measures', status: AssessmentStatus.FAIL, confidence: 0.65, evidence_count: 0, description: 'The controller and processor shall implement appropriate technical and organisational measures to ensure security.' },
      { id: 'Art.33', name: 'Breach Notification', category: 'Incident Response', status: AssessmentStatus.NEEDS_MANUAL_REVIEW, confidence: 0.78, evidence_count: 0, description: 'In case of a personal data breach, the controller shall notify the supervisory authority within 72 hours.' },
      { id: 'Art.35', name: 'Data Protection Impact Assessment', category: 'Risk Assessment', status: AssessmentStatus.EVIDENCE_GAP, confidence: 0.55, evidence_count: 0, description: 'Where processing is likely to result in high risk, the controller shall carry out an assessment of the impact.' },
    ]
  },
  [Frameworks.HIPAA]: {
    name: 'HIPAA Security Rule',
    description: 'Health Insurance Portability and Accountability Act',
    controls: [
      { id: '§164.308(a)(1)', name: 'Security Management Process', category: 'Administrative Safeguards', status: AssessmentStatus.PASS, confidence: 0.86, evidence_count: 0, description: 'Implement policies and procedures to prevent, detect, contain, and correct security violations.' },
      { id: '§164.308(a)(3)', name: 'Workforce Security', category: 'Administrative Safeguards', status: AssessmentStatus.PASS, confidence: 0.84, evidence_count: 0, description: 'Implement policies and procedures to ensure appropriate access to ePHI by workforce members.' },
      { id: '§164.308(a)(4)', name: 'Information Access Management', category: 'Administrative Safeguards', status: AssessmentStatus.NEEDS_MANUAL_REVIEW, confidence: 0.76, evidence_count: 0, description: 'Implement policies and procedures for authorizing access to ePHI consistent with applicable requirements.' },
      { id: '§164.308(a)(5)', name: 'Security Awareness Training', category: 'Administrative Safeguards', status: AssessmentStatus.PASS, confidence: 0.89, evidence_count: 0, description: 'Implement a security awareness and training program for all workforce members.' },
      { id: '§164.308(a)(6)', name: 'Security Incident Procedures', category: 'Administrative Safeguards', status: AssessmentStatus.FAIL, confidence: 0.62, evidence_count: 0, description: 'Implement policies and procedures to address security incidents.' },
      { id: '§164.308(a)(7)', name: 'Contingency Plan', category: 'Administrative Safeguards', status: AssessmentStatus.NEEDS_MANUAL_REVIEW, confidence: 0.71, evidence_count: 0, description: 'Establish policies and procedures for responding to an emergency or other occurrence.' },
      { id: '§164.310(a)(1)', name: 'Facility Access Controls', category: 'Physical Safeguards', status: AssessmentStatus.PASS, confidence: 0.88, evidence_count: 0, description: 'Implement policies and procedures to limit physical access to electronic information systems.' },
      { id: '§164.310(b)', name: 'Workstation Use', category: 'Physical Safeguards', status: AssessmentStatus.PASS, confidence: 0.85, evidence_count: 0, description: 'Implement policies and procedures that specify proper functions and physical attributes of workstations.' },
      { id: '§164.310(d)(1)', name: 'Device and Media Controls', category: 'Physical Safeguards', status: AssessmentStatus.EVIDENCE_GAP, confidence: 0.58, evidence_count: 0, description: 'Implement policies and procedures that govern the receipt and removal of hardware and electronic media.' },
      { id: '§164.312(a)(1)', name: 'Access Control', category: 'Technical Safeguards', status: AssessmentStatus.FAIL, confidence: 0.67, evidence_count: 0, description: 'Implement technical policies and procedures for electronic information systems that maintain ePHI.' },
      { id: '§164.312(b)', name: 'Audit Controls', category: 'Technical Safeguards', status: AssessmentStatus.PASS, confidence: 0.83, evidence_count: 0, description: 'Implement hardware, software, and procedural mechanisms that record and examine activity.' },
      { id: '§164.312(c)(1)', name: 'Integrity Controls', category: 'Technical Safeguards', status: AssessmentStatus.PASS, confidence: 0.87, evidence_count: 0, description: 'Implement policies and procedures to protect ePHI from improper alteration or destruction.' },
      { id: '§164.312(d)', name: 'Authentication', category: 'Technical Safeguards', status: AssessmentStatus.PASS, confidence: 0.90, evidence_count: 0, description: 'Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed.' },
      { id: '§164.312(e)(1)', name: 'Transmission Security', category: 'Technical Safeguards', status: AssessmentStatus.FAIL, confidence: 0.64, evidence_count: 0, description: 'Implement technical security measures to guard against unauthorized access to ePHI being transmitted.' },
    ]
  },
  [Frameworks.NIST]: {
    name: 'NIST 800-53A',
    description: 'Security and Privacy Controls Assessment',
    controls: [
      { id: 'AC-1', name: 'Policy and Procedures', category: 'Access Control', status: AssessmentStatus.PASS, confidence: 0.88, evidence_count: 0, description: 'Develop and document access control policy and procedures.' },
      { id: 'AC-2', name: 'Account Management', category: 'Access Control', status: AssessmentStatus.PASS, confidence: 0.85, evidence_count: 0, description: 'Define and document account types and establish conditions for membership.' },
      { id: 'AC-3', name: 'Access Enforcement', category: 'Access Control', status: AssessmentStatus.FAIL, confidence: 0.72, evidence_count: 0, description: 'Enforce approved authorizations for logical access to information and system resources.' },
      { id: 'AC-6', name: 'Least Privilege', category: 'Access Control', status: AssessmentStatus.NEEDS_MANUAL_REVIEW, confidence: 0.78, evidence_count: 0, description: 'Employ the principle of least privilege, allowing only authorized access.' },
      { id: 'AU-2', name: 'Event Logging', category: 'Audit and Accountability', status: AssessmentStatus.PASS, confidence: 0.91, evidence_count: 0, description: 'Identify events that the system is capable of logging in support of the audit function.' },
      { id: 'AU-3', name: 'Content of Audit Records', category: 'Audit and Accountability', status: AssessmentStatus.PASS, confidence: 0.89, evidence_count: 0, description: 'Ensure that audit records contain information that establishes what event occurred.' },
      { id: 'AU-6', name: 'Audit Record Review', category: 'Audit and Accountability', status: AssessmentStatus.NEEDS_MANUAL_REVIEW, confidence: 0.74, evidence_count: 0, description: 'Review and analyze system audit records for indications of inappropriate activity.' },
      { id: 'AU-12', name: 'Audit Record Generation', category: 'Audit and Accountability', status: AssessmentStatus.PASS, confidence: 0.87, evidence_count: 0, description: 'Provide audit record generation capability for auditable events.' },
      { id: 'RA-5', name: 'Vulnerability Monitoring', category: 'Risk Assessment', status: AssessmentStatus.FAIL, confidence: 0.65, evidence_count: 0, description: 'Monitor and scan for vulnerabilities in the system and applications.' },
      { id: 'SI-2', name: 'Flaw Remediation', category: 'System and Information Integrity', status: AssessmentStatus.FAIL, confidence: 0.68, evidence_count: 0, description: 'Identify, report, and correct system flaws in a timely manner.' },
      { id: 'SI-3', name: 'Malicious Code Protection', category: 'System and Information Integrity', status: AssessmentStatus.PASS, confidence: 0.86, evidence_count: 0, description: 'Implement malicious code protection mechanisms at system entry and exit points.' },
      { id: 'SI-4', name: 'System Monitoring', category: 'System and Information Integrity', status: AssessmentStatus.NEEDS_MANUAL_REVIEW, confidence: 0.76, evidence_count: 0, description: 'Monitor the system to detect attacks and indicators of potential attacks.' },
      { id: 'SC-7', name: 'Boundary Protection', category: 'System and Communications Protection', status: AssessmentStatus.PASS, confidence: 0.84, evidence_count: 0, description: 'Monitor and control communications at the external managed interfaces.' },
      { id: 'SC-8', name: 'Transmission Confidentiality', category: 'System and Communications Protection', status: AssessmentStatus.PASS, confidence: 0.88, evidence_count: 0, description: 'Protect the confidentiality and integrity of transmitted information.' },
    ]
  }
};

// =============================================================================
// CUSTOM HOOKS FOR API INTEGRATION
// =============================================================================

/**
 * Custom hook for fetching control assessments from the backend API
 * Falls back to mock data if API is unavailable
 */
const useControlAssessments = (framework, auditId = null) => {
  const [controls, setControls] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [source, setSource] = useState('mock'); // 'api' or 'mock'

  const fetchControls = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      // Try to fetch from API
      const endpoint = auditId 
        ? `${API_BASE_URL}/api/audit/${auditId}/controls?framework=${framework}`
        : `${API_BASE_URL}/api/frameworks/${framework}/controls`;
      
      const response = await fetch(endpoint, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
        // Timeout after 5 seconds
        signal: AbortSignal.timeout(5000),
      });

      if (!response.ok) {
        throw new Error(`API returned ${response.status}`);
      }

      const data = await response.json();
      setControls(data.controls || data);
      setSource('api');
    } catch (err) {
      // Fallback to mock data
      console.warn(`API unavailable (${err.message}), using mock data for ${framework}`);
      const mockData = frameworkControls[framework];
      if (mockData) {
        setControls(mockData.controls);
        setSource('mock');
      } else {
        setError(`Unknown framework: ${framework}`);
      }
    } finally {
      setLoading(false);
    }
  }, [framework, auditId]);

  useEffect(() => {
    fetchControls();
  }, [fetchControls]);

  return { controls, loading, error, source, refresh: fetchControls };
};

/**
 * Custom hook for WebSocket-based real-time audit updates
 */
const useAuditWebSocket = (auditId, onUpdate) => {
  const [connected, setConnected] = useState(false);
  const [ws, setWs] = useState(null);

  useEffect(() => {
    if (!auditId) return;

    const wsUrl = `${API_BASE_URL.replace('http', 'ws')}/api/audit/${auditId}/ws`;
    const socket = new WebSocket(wsUrl);

    socket.onopen = () => {
      setConnected(true);
      console.log('WebSocket connected');
    };

    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        onUpdate?.(data);
      } catch (err) {
        console.error('Failed to parse WebSocket message:', err);
      }
    };

    socket.onclose = () => {
      setConnected(false);
      console.log('WebSocket disconnected');
    };

    socket.onerror = (err) => {
      console.error('WebSocket error:', err);
      setConnected(false);
    };

    setWs(socket);

    return () => {
      socket.close();
    };
  }, [auditId, onUpdate]);

  return { connected, ws };
};

// =============================================================================
// UI COMPONENTS
// =============================================================================

const StatusBadge = ({ status }) => {
  const styles = {
    [AssessmentStatus.PASS]: "bg-emerald-100 text-emerald-800 border-emerald-300",
    [AssessmentStatus.FAIL]: "bg-red-100 text-red-800 border-red-300",
    [AssessmentStatus.NEEDS_MANUAL_REVIEW]: "bg-amber-100 text-amber-800 border-amber-300",
    [AssessmentStatus.EVIDENCE_GAP]: "bg-orange-100 text-orange-800 border-orange-300",
    [AssessmentStatus.INSUFFICIENT_EVIDENCE]: "bg-slate-100 text-slate-800 border-slate-300",
    [AssessmentStatus.CONFLICTING_EVIDENCE]: "bg-purple-100 text-purple-800 border-purple-300",
    completed: "bg-emerald-100 text-emerald-800 border-emerald-300",
    running: "bg-blue-100 text-blue-800 border-blue-300",
    error: "bg-red-100 text-red-800 border-red-300",
    pending: "bg-slate-100 text-slate-800 border-slate-300"
  };
  
  const labels = {
    [AssessmentStatus.PASS]: 'Pass',
    [AssessmentStatus.FAIL]: 'Fail',
    [AssessmentStatus.NEEDS_MANUAL_REVIEW]: 'Needs review',
    [AssessmentStatus.EVIDENCE_GAP]: 'Evidence gap',
    [AssessmentStatus.INSUFFICIENT_EVIDENCE]: 'Insufficient',
    [AssessmentStatus.CONFLICTING_EVIDENCE]: 'Conflicting',
  };

  return (
    <span className={`px-2.5 py-1 text-xs font-semibold rounded-full border ${styles[status] || styles.pending}`}>
      {labels[status] || status?.replace(/_/g, ' ')}
    </span>
  );
};

const SeverityBadge = ({ severity }) => {
  const styles = {
    critical: "bg-red-600 text-white",
    high: "bg-orange-500 text-white",
    medium: "bg-yellow-500 text-white",
    low: "bg-blue-500 text-white"
  };
  return (
    <span className={`px-2 py-0.5 text-xs font-bold rounded ${styles[severity]}`}>
      {severity.toUpperCase()}
    </span>
  );
};

const ConfidenceBar = ({ confidence }) => {
  const percentage = Math.round(confidence * 100);
  const getColor = (pct) => {
    if (pct >= 80) return 'bg-emerald-500';
    if (pct >= 60) return 'bg-amber-500';
    return 'bg-red-500';
  };

  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-2 bg-slate-200 rounded-full overflow-hidden">
        <div 
          className={`h-full rounded-full transition-all duration-300 ${getColor(percentage)}`} 
          style={{ width: `${percentage}%` }} 
        />
      </div>
      <span className="text-xs font-medium text-slate-600 w-10">{percentage}%</span>
    </div>
  );
};

const FrameworkTab = ({ framework, isActive, onClick, controlCount }) => {
  const frameworkColors = {
    [Frameworks.SOC2]: 'from-blue-500 to-indigo-600',
    [Frameworks.GDPR]: 'from-emerald-500 to-teal-600',
    [Frameworks.HIPAA]: 'from-rose-500 to-pink-600',
    [Frameworks.NIST]: 'from-violet-500 to-purple-600',
  };

  const labels = {
    [Frameworks.SOC2]: 'SOC 2',
    [Frameworks.GDPR]: 'GDPR',
    [Frameworks.HIPAA]: 'HIPAA',
    [Frameworks.NIST]: 'NIST 800-53A',
  };

  return (
    <button
      onClick={() => onClick(framework)}
      className={`
        relative px-4 py-2.5 font-medium text-sm rounded-lg transition-all duration-200
        ${isActive 
          ? `bg-gradient-to-r ${frameworkColors[framework]} text-white shadow-lg shadow-${framework.toLowerCase()}-500/25` 
          : 'bg-white text-slate-600 hover:bg-slate-50 border border-slate-200'
        }
      `}
    >
      <span>{labels[framework]}</span>
      {controlCount !== undefined && (
        <span className={`ml-2 px-1.5 py-0.5 text-xs rounded-full ${
          isActive ? 'bg-white/20' : 'bg-slate-100'
        }`}>
          {controlCount}
        </span>
      )}
    </button>
  );
};

const LoadingSpinner = () => (
  <div className="flex items-center justify-center p-12">
    <Loader2 className="w-8 h-8 animate-spin text-indigo-500" />
    <span className="ml-3 text-slate-600">Loading controls...</span>
  </div>
);

const ErrorState = ({ error, onRetry }) => (
  <div className="flex flex-col items-center justify-center p-12 text-center">
    <AlertTriangle className="w-12 h-12 text-amber-500 mb-4" />
    <h3 className="text-lg font-semibold text-slate-800 mb-2">Failed to Load Controls</h3>
    <p className="text-slate-600 mb-4">{error}</p>
    <button 
      onClick={onRetry}
      className="px-4 py-2 bg-indigo-500 text-white rounded-lg hover:bg-indigo-600 transition-colors flex items-center gap-2"
    >
      <RefreshCw className="w-4 h-4" />
      Retry
    </button>
  </div>
);

// =============================================================================
// CONTROL ASSESSMENTS COMPONENT
// =============================================================================

const ControlAssessments = ({ auditId = null }) => {
  const [selectedFramework, setSelectedFramework] = useState(Frameworks.SOC2);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('All States');
  const [expandedControl, setExpandedControl] = useState(null);

  // Fetch controls using the custom hook
  const { controls, loading, error, source, refresh } = useControlAssessments(selectedFramework, auditId);

  // Get framework metadata
  const frameworkMeta = frameworkControls[selectedFramework] || {};

  // Filter controls based on search and status
  const filteredControls = useMemo(() => {
    return controls.filter(control => {
      const matchesSearch = searchQuery === '' || 
        control.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        control.name.toLowerCase().includes(searchQuery.toLowerCase());
      
      const matchesStatus = statusFilter === 'All States' || control.status === statusFilter;
      
      return matchesSearch && matchesStatus;
    });
  }, [controls, searchQuery, statusFilter]);

  // Calculate summary statistics
  const stats = useMemo(() => {
    const total = controls.length;
    const passed = controls.filter(c => c.status === AssessmentStatus.PASS).length;
    const failed = controls.filter(c => c.status === AssessmentStatus.FAIL).length;
    const needsReview = controls.filter(c => c.status === AssessmentStatus.NEEDS_MANUAL_REVIEW).length;
    const evidenceGaps = controls.filter(c => c.status === AssessmentStatus.EVIDENCE_GAP).length;
    
    return { total, passed, failed, needsReview, evidenceGaps };
  }, [controls]);

  // Handle framework tab click
  const handleFrameworkChange = (framework) => {
    setSelectedFramework(framework);
    setSearchQuery('');
    setStatusFilter('All States');
    setExpandedControl(null);
  };

  // Handle control row click for expansion
  const handleControlClick = (controlId) => {
    setExpandedControl(expandedControl === controlId ? null : controlId);
  };

  return (
    <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b border-slate-200 bg-gradient-to-r from-slate-50 to-white">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-xl font-bold text-slate-800 flex items-center gap-2">
              <Shield className="w-6 h-6 text-indigo-500" />
              Control Assessments
            </h2>
            <p className="text-sm text-slate-500 mt-1">
              {frameworkMeta.description || 'Compliance framework assessment results'}
            </p>
          </div>
          
          <div className="flex items-center gap-3">
            {/* Data source indicator */}
            <span className={`text-xs px-2 py-1 rounded-full ${
              source === 'api' 
                ? 'bg-emerald-100 text-emerald-700' 
                : 'bg-amber-100 text-amber-700'
            }`}>
              {source === 'api' ? '● Live Data' : '○ Mock Data'}
            </span>
            
            <button 
              onClick={refresh}
              className="p-2 hover:bg-slate-100 rounded-lg transition-colors"
              title="Refresh data"
            >
              <RefreshCw className={`w-4 h-4 text-slate-500 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {/* Framework Tabs */}
        <div className="flex gap-2 flex-wrap">
          {Object.values(Frameworks).map(framework => (
            <FrameworkTab
              key={framework}
              framework={framework}
              isActive={selectedFramework === framework}
              onClick={handleFrameworkChange}
              controlCount={frameworkControls[framework]?.controls?.length}
            />
          ))}
        </div>
      </div>

      {/* Stats Bar */}
      <div className="px-6 py-3 bg-slate-50 border-b border-slate-200">
        <div className="flex items-center gap-6 text-sm">
          <div className="flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-emerald-500" />
            <span className="text-slate-600">Passed:</span>
            <span className="font-semibold text-emerald-600">{stats.passed}</span>
          </div>
          <div className="flex items-center gap-2">
            <XCircle className="w-4 h-4 text-red-500" />
            <span className="text-slate-600">Failed:</span>
            <span className="font-semibold text-red-600">{stats.failed}</span>
          </div>
          <div className="flex items-center gap-2">
            <Eye className="w-4 h-4 text-amber-500" />
            <span className="text-slate-600">Needs Review:</span>
            <span className="font-semibold text-amber-600">{stats.needsReview}</span>
          </div>
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-orange-500" />
            <span className="text-slate-600">Evidence Gaps:</span>
            <span className="font-semibold text-orange-600">{stats.evidenceGaps}</span>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="px-6 py-3 border-b border-slate-200 flex gap-4">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search controls..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
          />
        </div>
        
        <div className="relative">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="appearance-none pl-4 pr-10 py-2 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent bg-white cursor-pointer"
          >
            <option>All States</option>
            {Object.values(AssessmentStatus).map(status => (
              <option key={status} value={status}>
                {status.replace(/_/g, ' ')}
              </option>
            ))}
          </select>
          <ChevronDown className="absolute right-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
        </div>
      </div>

      {/* Content */}
      {loading ? (
        <LoadingSpinner />
      ) : error ? (
        <ErrorState error={error} onRetry={refresh} />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-slate-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">
                  Control ID
                </th>
                <th className="px-6 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">
                  Name
                </th>
                <th className="px-6 py-3 text-center text-xs font-semibold text-slate-500 uppercase tracking-wider">
                  State
                </th>
                <th className="px-6 py-3 text-center text-xs font-semibold text-slate-500 uppercase tracking-wider">
                  Confidence
                </th>
                <th className="px-6 py-3 text-center text-xs font-semibold text-slate-500 uppercase tracking-wider">
                  Evidence
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filteredControls.map(control => (
                <React.Fragment key={control.id}>
                  <tr 
                    className="hover:bg-slate-50 cursor-pointer transition-colors"
                    onClick={() => handleControlClick(control.id)}
                  >
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <span className={`transform transition-transform duration-200 ${
                          expandedControl === control.id ? 'rotate-90' : ''
                        }`}>
                          <ChevronRight className="w-4 h-4 text-slate-400" />
                        </span>
                        <span className="font-mono text-sm font-semibold text-indigo-600">
                          {control.id}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div>
                        <p className="text-sm font-medium text-slate-800">{control.name}</p>
                        {control.category && (
                          <p className="text-xs text-slate-500 mt-0.5">{control.category}</p>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 text-center">
                      <StatusBadge status={control.status} />
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex justify-center">
                        <ConfidenceBar confidence={control.confidence} />
                      </div>
                    </td>
                    <td className="px-6 py-4 text-center">
                      <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${
                        control.evidence_count > 0 
                          ? 'bg-emerald-100 text-emerald-700' 
                          : 'bg-slate-100 text-slate-500'
                      }`}>
                        <FileText className="w-3 h-3" />
                        {control.evidence_count} items
                      </span>
                    </td>
                  </tr>
                  
                  {/* Expanded Details Row */}
                  {expandedControl === control.id && (
                    <tr className="bg-slate-50">
                      <td colSpan={5} className="px-6 py-4">
                        <div className="pl-6 border-l-2 border-indigo-200">
                          <p className="text-sm text-slate-600 mb-3">{control.description}</p>
                          <div className="flex gap-4 text-xs">
                            <span className="text-slate-500">
                              Category: <span className="font-medium text-slate-700">{control.category}</span>
                            </span>
                            <span className="text-slate-500">
                              Framework: <span className="font-medium text-slate-700">{selectedFramework}</span>
                            </span>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
          
          {filteredControls.length === 0 && (
            <div className="text-center py-12">
              <Search className="w-12 h-12 text-slate-300 mx-auto mb-4" />
              <p className="text-slate-500">No controls match your search criteria</p>
            </div>
          )}
        </div>
      )}

      {/* Footer */}
      <div className="px-6 py-3 bg-slate-50 border-t border-slate-200 flex items-center justify-between">
        <span className="text-xs text-slate-500">
          Showing {filteredControls.length} of {controls.length} controls
        </span>
        <span className="text-xs text-slate-400">
          {frameworkMeta.name} • AI-Powered Security Auditor
        </span>
      </div>
    </div>
  );
};

// =============================================================================
// FULL DASHBOARD COMPONENT (UPDATED)
// =============================================================================

// Mock data representing a realistic audit
const mockAuditData = {
  audit_id: "AUDIT-20260113-142530",
  framework: "SOC2",
  report_type: "type2",
  scope: {
    systems: ["app-server-01", "db-server-01", "api-gateway"],
    period_start: "2025-10-01",
    period_end: "2025-12-31"
  },
  started_at: "2026-01-13T14:25:30Z",
  completed_at: "2026-01-13T14:32:15Z",
  current_phase: "completed",
  overall_status: "PASS WITH EXCEPTIONS",
  summary: {
    total_findings: 23,
    critical: 1,
    high: 4,
    medium: 8,
    low: 10,
    evidence_collected: 47,
    evidence_gaps: 3,
    controls_assessed: 12,
    controls_passed: 8,
    controls_failed: 1,
    controls_needs_review: 3
  },
  agents: {
    vulnerability_scanner: {
      status: "completed",
      last_run: "2026-01-13T14:26:45Z",
      findings_count: 6,
      evidence_count: 12
    },
    code_analyzer: {
      status: "completed", 
      last_run: "2026-01-13T14:28:30Z",
      findings_count: 9,
      evidence_count: 18
    },
    log_analyzer: {
      status: "completed",
      last_run: "2026-01-13T14:30:15Z", 
      findings_count: 5,
      evidence_count: 10
    },
    compliance_checker: {
      status: "completed",
      last_run: "2026-01-13T14:31:45Z",
      findings_count: 3,
      evidence_count: 7
    }
  },
  anti_hallucination: {
    llm_overrides: 4,
    forbidden_words_detected: 2,
    evidence_citation_rate: 0.96,
    average_confidence: 0.87,
    confidence_distribution: [
      { range: "0.9-1.0", count: 8 },
      { range: "0.8-0.9", count: 3 },
      { range: "0.7-0.8", count: 1 },
      { range: "<0.7", count: 0 }
    ]
  },
  findings: [
    { id: "F001", title: "SQL Injection in user input", severity: "critical", agent: "code_analyzer", control: "CC6.6", cwe: "CWE-89" },
    { id: "F002", title: "Missing rate limiting on API", severity: "high", agent: "vulnerability_scanner", control: "CC6.6", cwe: "CWE-307" },
    { id: "F003", title: "Hardcoded credentials detected", severity: "high", agent: "code_analyzer", control: "CC6.1", cwe: "CWE-798" },
    { id: "F004", title: "Insufficient logging for auth events", severity: "high", agent: "log_analyzer", control: "CC7.1", cwe: "CWE-778" },
    { id: "F005", title: "Weak TLS configuration", severity: "high", agent: "vulnerability_scanner", control: "CC6.7", cwe: "CWE-327" },
    { id: "F006", title: "Missing CSRF protection", severity: "medium", agent: "code_analyzer", control: "CC6.6", cwe: "CWE-352" },
    { id: "F007", title: "Verbose error messages", severity: "medium", agent: "code_analyzer", control: "CC6.6", cwe: "CWE-209" },
    { id: "F008", title: "Session timeout too long", severity: "medium", agent: "compliance_checker", control: "CC6.1", cwe: null },
  ],
  evidence_gaps: [
    { control: "CC6.6", requirement: "Vulnerability scan schedule documentation", priority: "high" },
    { control: "CC7.1", requirement: "SIEM alert configuration evidence", priority: "medium" },
    { control: "CC6.6", requirement: "Penetration test report (last 12 months)", priority: "high" }
  ]
};

export default function SecurityAuditorDashboard() {
  const [data] = useState(mockAuditData);
  
  const overallScore = useMemo(() => {
    // Calculate based on summary stats
    const { controls_assessed, controls_passed } = data.summary;
    return Math.round((controls_passed / controls_assessed) * 100);
  }, [data.summary]);

  const severityData = [
    { name: 'Critical', value: data.summary.critical, color: '#dc2626' },
    { name: 'High', value: data.summary.high, color: '#f97316' },
    { name: 'Medium', value: data.summary.medium, color: '#eab308' },
    { name: 'Low', value: data.summary.low, color: '#3b82f6' }
  ];

  const findingsByAgent = [
    { agent: 'Vuln Scanner', critical: 0, high: 1, medium: 2, low: 3 },
    { agent: 'Code Analyzer', critical: 1, high: 2, medium: 3, low: 3 },
    { agent: 'Log Analyzer', critical: 0, high: 1, medium: 2, low: 2 },
    { agent: 'Compliance', critical: 0, high: 0, medium: 1, low: 2 }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-100 via-slate-50 to-white">
      <div className="max-w-7xl mx-auto p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-slate-800 flex items-center gap-3">
              <Shield className="w-8 h-8 text-indigo-500" />
              AI-Powered Security Auditor
            </h1>
            <p className="text-slate-500 mt-1">
              Audit ID: {data.audit_id} • {new Date(data.started_at).toLocaleDateString()}
            </p>
          </div>
          <div className="flex items-center gap-3">
            <StatusBadge status={data.current_phase} />
            <button className="px-4 py-2 bg-indigo-500 text-white rounded-lg hover:bg-indigo-600 transition-colors flex items-center gap-2">
              <Download className="w-4 h-4" />
              Export Report
            </button>
          </div>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-4 gap-4">
          <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-500">Overall Score</p>
                <p className="text-3xl font-bold text-indigo-600">{overallScore}%</p>
              </div>
              <div className="w-14 h-14 bg-indigo-100 rounded-full flex items-center justify-center">
                <Shield className="w-7 h-7 text-indigo-500" />
              </div>
            </div>
          </div>
          
          <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-500">Total Findings</p>
                <p className="text-3xl font-bold text-slate-800">{data.summary.total_findings}</p>
              </div>
              <div className="w-14 h-14 bg-amber-100 rounded-full flex items-center justify-center">
                <AlertTriangle className="w-7 h-7 text-amber-500" />
              </div>
            </div>
          </div>
          
          <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-500">Evidence Collected</p>
                <p className="text-3xl font-bold text-emerald-600">{data.summary.evidence_collected}</p>
              </div>
              <div className="w-14 h-14 bg-emerald-100 rounded-full flex items-center justify-center">
                <FileText className="w-7 h-7 text-emerald-500" />
              </div>
            </div>
          </div>
          
          <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-500">Evidence Gaps</p>
                <p className="text-3xl font-bold text-red-600">{data.summary.evidence_gaps}</p>
              </div>
              <div className="w-14 h-14 bg-red-100 rounded-full flex items-center justify-center">
                <AlertOctagon className="w-7 h-7 text-red-500" />
              </div>
            </div>
          </div>
        </div>

        {/* Agent Status */}
        <div className="grid grid-cols-4 gap-4">
          {Object.entries(data.agents).map(([name, agent]) => (
            <div key={name} className="bg-white rounded-xl shadow-sm border border-slate-200 p-4">
              <div className="flex items-center justify-between mb-3">
                <h3 className="font-semibold text-slate-700 capitalize">{name.replace(/_/g, ' ')}</h3>
                <StatusBadge status={agent.status} />
              </div>
              <div className="space-y-1 text-sm">
                <div className="flex justify-between">
                  <span className="text-slate-500">Findings</span>
                  <span className="font-medium">{agent.findings_count}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Evidence</span>
                  <span className="font-medium">{agent.evidence_count}</span>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Charts Row */}
        <div className="grid grid-cols-2 gap-6">
          <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-5">
            <h3 className="font-semibold text-slate-800 mb-4">Findings by Severity</h3>
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  dataKey="value"
                  label={({ name, value }) => `${name}: ${value}`}
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
          
          <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-5">
            <h3 className="font-semibold text-slate-800 mb-4">Findings by Agent</h3>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={findingsByAgent}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="agent" tick={{ fontSize: 12 }} />
                <YAxis />
                <Tooltip />
                <Legend />
                <Bar dataKey="critical" fill="#dc2626" stackId="a" />
                <Bar dataKey="high" fill="#f97316" stackId="a" />
                <Bar dataKey="medium" fill="#eab308" stackId="a" />
                <Bar dataKey="low" fill="#3b82f6" stackId="a" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* UPDATED: Control Assessments with Framework Switching */}
        <ControlAssessments auditId={data.audit_id} />

        {/* Findings Table */}
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-200">
            <h3 className="font-semibold text-slate-800 flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-amber-500" />
              Top Security Findings
            </h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-slate-500 uppercase">ID</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-slate-500 uppercase">Finding</th>
                  <th className="px-6 py-3 text-center text-xs font-semibold text-slate-500 uppercase">Severity</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-slate-500 uppercase">Agent</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-slate-500 uppercase">Control</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-slate-500 uppercase">CWE</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {data.findings.map(finding => (
                  <tr key={finding.id} className="hover:bg-slate-50">
                    <td className="px-6 py-4 font-mono text-indigo-600">{finding.id}</td>
                    <td className="px-6 py-4 text-slate-800">{finding.title}</td>
                    <td className="px-6 py-4 text-center"><SeverityBadge severity={finding.severity} /></td>
                    <td className="px-6 py-4 text-slate-600 capitalize">{finding.agent.replace(/_/g, ' ')}</td>
                    <td className="px-6 py-4 font-mono text-slate-600">{finding.control}</td>
                    <td className="px-6 py-4 font-mono text-blue-600">{finding.cwe || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Anti-Hallucination Metrics */}
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-200">
            <h3 className="font-semibold text-slate-800 flex items-center gap-2">
              <Shield className="w-5 h-5 text-cyan-500" />
              Anti-Hallucination Safeguards
              <span className="ml-2 text-xs font-normal text-slate-500 bg-slate-100 px-2 py-1 rounded">
                "If you can't prove it, you can't claim it"
              </span>
            </h3>
          </div>
          <div className="p-6">
            <div className="grid grid-cols-4 gap-4">
              <div className="text-center p-4 bg-gradient-to-br from-cyan-50 to-blue-50 rounded-xl">
                <p className="text-3xl font-bold text-cyan-600">{data.anti_hallucination.llm_overrides}</p>
                <p className="text-sm text-slate-600 mt-1">LLM Overrides</p>
                <p className="text-xs text-slate-400 mt-1">PASS→EVIDENCE_GAP</p>
              </div>
              <div className="text-center p-4 bg-gradient-to-br from-orange-50 to-red-50 rounded-xl">
                <p className="text-3xl font-bold text-orange-600">{data.anti_hallucination.forbidden_words_detected}</p>
                <p className="text-sm text-slate-600 mt-1">Forbidden Words</p>
                <p className="text-xs text-slate-400 mt-1">Weasel words blocked</p>
              </div>
              <div className="text-center p-4 bg-gradient-to-br from-emerald-50 to-teal-50 rounded-xl">
                <p className="text-3xl font-bold text-emerald-600">{Math.round(data.anti_hallucination.evidence_citation_rate * 100)}%</p>
                <p className="text-sm text-slate-600 mt-1">Citation Rate</p>
                <p className="text-xs text-slate-400 mt-1">Claims with evidence</p>
              </div>
              <div className="text-center p-4 bg-gradient-to-br from-purple-50 to-indigo-50 rounded-xl">
                <p className="text-3xl font-bold text-purple-600">{Math.round(data.anti_hallucination.average_confidence * 100)}%</p>
                <p className="text-sm text-slate-600 mt-1">Avg Confidence</p>
                <p className="text-xs text-slate-400 mt-1">Assessment certainty</p>
              </div>
            </div>
          </div>
        </div>

        {/* Evidence Gaps */}
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-200">
            <h3 className="font-semibold text-slate-800 flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-orange-500" />
              Evidence Gaps ({data.evidence_gaps.length})
            </h3>
          </div>
          <div className="p-4 space-y-2">
            {data.evidence_gaps.map((gap, idx) => (
              <div key={idx} className="flex items-start gap-3 p-4 bg-red-50 rounded-lg border border-red-100">
                <span className="font-mono text-xs font-semibold text-red-700 bg-red-100 px-2 py-1 rounded">{gap.control}</span>
                <span className="text-sm text-slate-700 flex-1">{gap.requirement}</span>
                <span className={`text-xs font-semibold px-2 py-1 rounded ${gap.priority === 'high' ? 'bg-red-200 text-red-800' : 'bg-amber-200 text-amber-800'}`}>
                  {gap.priority}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="text-center text-sm text-slate-500 py-4">
          <p>AI-Powered Security Auditor • NVIDIA Interview Demo</p>
          <p className="text-xs mt-1">LangGraph Orchestration • RAG Compliance • Anti-Hallucination Framework</p>
        </div>
      </div>
    </div>
  );
}

// Export individual components for modular use
export { ControlAssessments, StatusBadge, SeverityBadge, useControlAssessments, useAuditWebSocket };
