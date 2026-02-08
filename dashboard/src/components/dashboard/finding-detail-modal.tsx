/**
 * Finding Detail Modal Component
 * 
 * Displays detailed information about a security finding including
 * evidence, remediation steps, and compliance mapping.
 * 
 * @module components/dashboard/finding-detail-modal
 */

'use client';

import React from 'react';
import {
  AlertTriangle,
  Shield,
  FileText,
  Code,
  ExternalLink,
  Copy,
  CheckCircle,
  Clock,
  LinkIcon,
} from 'lucide-react';
import { Modal, ModalFooter } from '@/components/ui/modal';
import { SeverityBadge } from '@/components/ui/badge';
import { cn, formatDateTime } from '@/lib/utils';
import type { Finding } from '@/types';

interface FindingDetailModalProps {
  finding: Finding | null;
  isOpen: boolean;
  onClose: () => void;
}

export function FindingDetailModal({
  finding,
  isOpen,
  onClose,
}: FindingDetailModalProps) {
  const [copied, setCopied] = React.useState(false);

  if (!finding) return null;

  const handleCopyId = () => {
    navigator.clipboard.writeText(finding.finding_id);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={finding.title}
      description={`Finding ${finding.finding_id}`}
      size="lg"
    >
      <div className="space-y-6">
        {/* Header Info */}
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <SeverityBadge severity={finding.severity} />
            <button
              onClick={handleCopyId}
              className="flex items-center gap-1 text-sm text-gray-500 hover:text-gray-700"
            >
              <span className="font-mono">{finding.finding_id}</span>
              {copied ? (
                <CheckCircle className="h-4 w-4 text-green-500" />
              ) : (
                <Copy className="h-4 w-4" />
              )}
            </button>
          </div>
          <div className="flex items-center gap-1 text-sm text-gray-500">
            <Clock className="h-4 w-4" />
            {formatDateTime(finding.discovered_at)}
          </div>
        </div>

        {/* Description */}
        <div>
          <h4 className="text-sm font-medium text-gray-700 mb-2 flex items-center gap-2">
            <AlertTriangle className="h-4 w-4" />
            Description
          </h4>
          <p className="text-sm text-gray-600 bg-gray-50 rounded-lg p-4">
            {finding.description}
          </p>
        </div>

        {/* CWE & OWASP */}
        {(finding.cwe_id || finding.owasp_category) && (
          <div className="grid grid-cols-2 gap-4">
            {finding.cwe_id && (
              <div className="bg-blue-50 rounded-lg p-4">
                <h4 className="text-sm font-medium text-blue-800 mb-1">CWE ID</h4>
                <a
                  href={`https://cwe.mitre.org/data/definitions/${finding.cwe_id.replace('CWE-', '')}.html`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-blue-600 hover:underline flex items-center gap-1"
                >
                  {finding.cwe_id}
                  <ExternalLink className="h-3 w-3" />
                </a>
              </div>
            )}
            {finding.owasp_category && (
              <div className="bg-orange-50 rounded-lg p-4">
                <h4 className="text-sm font-medium text-orange-800 mb-1">
                  OWASP Category
                </h4>
                <span className="text-sm text-orange-600">
                  {finding.owasp_category}
                </span>
              </div>
            )}
          </div>
        )}

        {/* Confidence Score */}
        {finding.confidence !== undefined && (
          <div>
            <h4 className="text-sm font-medium text-gray-700 mb-2 flex items-center gap-2">
              <Shield className="h-4 w-4 text-green-600" />
              Confidence Score
            </h4>
            <div className="flex items-center gap-4">
              <div className="flex-1 h-3 bg-gray-200 rounded-full overflow-hidden">
                <div
                  className={cn(
                    'h-full rounded-full transition-all duration-500',
                    finding.confidence >= 0.8
                      ? 'bg-green-500'
                      : finding.confidence >= 0.6
                      ? 'bg-yellow-500'
                      : 'bg-red-500'
                  )}
                  style={{ width: `${finding.confidence * 100}%` }}
                />
              </div>
              <span className="text-sm font-medium text-gray-700">
                {Math.round(finding.confidence * 100)}%
              </span>
            </div>
            <p className="text-xs text-gray-500 mt-1">
              Based on evidence quality and anti-hallucination validation
            </p>
          </div>
        )}

        {/* Evidence */}
        {finding.evidence_ids.length > 0 && (
          <div>
            <h4 className="text-sm font-medium text-gray-700 mb-2 flex items-center gap-2">
              <FileText className="h-4 w-4" />
              Supporting Evidence ({finding.evidence_ids.length})
            </h4>
            <ul className="space-y-2">
              {finding.evidence_ids.map((evidenceId) => (
                <li
                  key={evidenceId}
                  className="flex items-center gap-2 text-sm text-gray-600 bg-gray-50 rounded px-3 py-2"
                >
                  <Code className="h-4 w-4 text-gray-400" />
                  <span className="font-mono">{evidenceId}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Related Controls */}
        {finding.control_ids.length > 0 && (
          <div>
            <h4 className="text-sm font-medium text-gray-700 mb-2 flex items-center gap-2">
              <LinkIcon className="h-4 w-4" />
              Related Compliance Controls
            </h4>
            <div className="flex flex-wrap gap-2">
              {finding.control_ids.map((controlId) => (
                <span
                  key={controlId}
                  className="px-2 py-1 text-xs font-medium bg-purple-100 text-purple-700 rounded"
                >
                  {controlId}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Remediation */}
        {finding.remediation && (
          <div>
            <h4 className="text-sm font-medium text-gray-700 mb-2 flex items-center gap-2">
              <CheckCircle className="h-4 w-4 text-green-600" />
              Remediation
            </h4>
            <div className="text-sm text-gray-600 bg-green-50 border border-green-200 rounded-lg p-4">
              {finding.remediation}
            </div>
          </div>
        )}
      </div>

      <ModalFooter>
        <button
          onClick={onClose}
          className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50"
        >
          Close
        </button>
        <button className="px-4 py-2 text-sm font-medium text-white bg-gray-900 rounded-lg hover:bg-gray-800">
          Export Finding
        </button>
      </ModalFooter>
    </Modal>
  );
}
