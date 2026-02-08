'use client';

/**
 * Anti-Hallucination Panel Component
 * 
 * Displays the key metrics that demonstrate the anti-hallucination
 * capabilities of the security auditor - the main differentiator
 * for NVIDIA interview presentations.
 * 
 * Core Principle: "If you can't prove it, you can't claim it"
 * 
 * @module components/dashboard/anti-hallucination-panel
 */

import React from 'react';
import {
  Shield,
  AlertOctagon,
  CheckCircle2,
  Ban,
  TrendingUp,
  HelpCircle,
} from 'lucide-react';
import { cn, formatPercentage } from '@/lib/utils';
import type { AntiHallucinationMetrics, ConfidenceBucket } from '@/types';

interface AntiHallucinationPanelProps {
  metrics: AntiHallucinationMetrics;
  isLoading?: boolean;
  className?: string;
}

export function AntiHallucinationPanel({
  metrics,
  isLoading,
  className,
}: AntiHallucinationPanelProps) {
  if (isLoading) {
    return <AntiHallucinationPanelSkeleton className={className} />;
  }
  return (
    <div className={cn('space-y-4', className)}>
      {/* Core Principle Banner */}
      <div className="bg-gradient-to-r from-green-50 to-emerald-50 border border-green-200 rounded-lg p-3">
        <div className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-green-600" />
          <span className="text-sm font-medium text-green-800">
            Core Principle: "If you can't prove it, you can't claim it"
          </span>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-2 gap-3">
        <MetricCard
          icon={AlertOctagon}
          label="LLM Overrides"
          value={metrics.llm_overrides}
          description="Times LLM output was overridden due to validation failure"
          variant="warning"
          tooltip="When LLM generates claims without evidence, the system defaults to conservative assessment"
        />
        <MetricCard
          icon={Ban}
          label="Weasel Words Blocked"
          value={metrics.forbidden_words_detected}
          description="Hedging patterns detected and removed"
          variant="danger"
          tooltip="Words like 'may', 'might', 'could' are blocked to ensure definitive assessments"
        />
        <MetricCard
          icon={CheckCircle2}
          label="Evidence Citation Rate"
          value={formatPercentage(metrics.evidence_citation_rate, 1)}
          description="Claims with proper evidence backing"
          variant="success"
          tooltip="Every compliance claim must cite specific evidence artifacts"
        />
        <MetricCard
          icon={TrendingUp}
          label="Average Confidence"
          value={formatPercentage(metrics.average_confidence * 100, 0)}
          description="Mean confidence across assessments"
          variant={metrics.average_confidence >= 0.8 ? 'success' : 'warning'}
          tooltip="Confidence score based on evidence quality and completeness"
        />
      </div>

      {/* Confidence Distribution */}
      <div className="bg-gray-50 rounded-lg p-3">
        <h4 className="text-xs font-medium text-gray-700 mb-2">
          Confidence Distribution
        </h4>
        <ConfidenceDistributionChart distribution={metrics.confidence_distribution} />
      </div>

      {/* Five Core Rules */}
      <div className="border border-gray-200 rounded-lg p-3">
        <h4 className="text-xs font-medium text-gray-700 mb-2 flex items-center gap-1">
          5 Anti-Hallucination Rules
          <HelpCircle className="h-3 w-3 text-gray-400" />
        </h4>
        <ul className="space-y-1">
          {FIVE_CORE_RULES.map((rule, index) => (
            <li key={index} className="flex items-center gap-2 text-xs">
              <CheckCircle2 className="h-3 w-3 text-green-500 flex-shrink-0" />
              <span className="text-gray-600">{rule}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* Valid Assessment States */}
      <div className="border border-gray-200 rounded-lg p-3">
        <h4 className="text-xs font-medium text-gray-700 mb-2">
          Valid Assessment States (6 Only)
        </h4>
        <div className="flex flex-wrap gap-1">
          {VALID_STATES.map((state) => (
            <span
              key={state.name}
              className={cn('px-2 py-0.5 text-xs font-medium rounded', state.className)}
            >
              {state.name}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

interface MetricCardProps {
  icon: typeof Shield;
  label: string;
  value: string | number;
  description: string;
  variant: 'success' | 'warning' | 'danger' | 'info';
  tooltip?: string;
}

function MetricCard({
  icon: Icon,
  label,
  value,
  description,
  variant,
  tooltip,
}: MetricCardProps) {
  const variantStyles = {
    success: 'bg-green-50 border-green-200 text-green-700',
    warning: 'bg-yellow-50 border-yellow-200 text-yellow-700',
    danger: 'bg-red-50 border-red-200 text-red-700',
    info: 'bg-blue-50 border-blue-200 text-blue-700',
  };

  const iconStyles = {
    success: 'text-green-600',
    warning: 'text-yellow-600',
    danger: 'text-red-600',
    info: 'text-blue-600',
  };

  return (
    <div
      className={cn('rounded-lg border p-3', variantStyles[variant])}
      title={tooltip}
    >
      <div className="flex items-center gap-2 mb-1">
        <Icon className={cn('h-4 w-4', iconStyles[variant])} />
        <span className="text-xs font-medium">{label}</span>
      </div>
      <p className="text-2xl font-bold">{value}</p>
      <p className="text-xs opacity-75 mt-1">{description}</p>
    </div>
  );
}

interface ConfidenceDistributionChartProps {
  distribution: ConfidenceBucket[];
}

function ConfidenceDistributionChart({ distribution }: ConfidenceDistributionChartProps) {
  const maxCount = Math.max(...distribution.map((d) => d.count), 1);

  return (
    <div className="space-y-1">
      {distribution.map((bucket) => (
        <div key={bucket.range} className="flex items-center gap-2">
          <span className="text-xs text-gray-500 w-16">{bucket.range}</span>
          <div className="flex-1 h-4 bg-gray-200 rounded-full overflow-hidden">
            <div
              className={cn(
                'h-full rounded-full transition-all duration-500',
                getConfidenceBarColor(bucket.range)
              )}
              style={{ width: `${(bucket.count / maxCount) * 100}%` }}
            />
          </div>
          <span className="text-xs font-medium text-gray-700 w-8 text-right">
            {bucket.count}
          </span>
        </div>
      ))}
    </div>
  );
}

function getConfidenceBarColor(range: string): string {
  if (range.includes('0.9') || range.includes('1.0')) return 'bg-green-500';
  if (range.includes('0.7') || range.includes('0.8')) return 'bg-blue-500';
  if (range.includes('0.5') || range.includes('0.6')) return 'bg-yellow-500';
  return 'bg-red-500';
}

const FIVE_CORE_RULES = [
  'Cite-or-Abstain: Every claim must cite evidence',
  'Confidence Scoring: All assessments include confidence',
  'No Weasel Words: 30+ hedging patterns blocked',
  'Scope Boundaries: Stay within evidence bounds',
  'Provenance Chains: Complete evidence lineage',
];

const VALID_STATES = [
  { name: 'PASS', className: 'bg-green-100 text-green-800' },
  { name: 'FAIL', className: 'bg-red-100 text-red-800' },
  { name: 'INSUFFICIENT_EVIDENCE', className: 'bg-yellow-100 text-yellow-800' },
  { name: 'EVIDENCE_GAP', className: 'bg-orange-100 text-orange-800' },
  { name: 'CONFLICTING_EVIDENCE', className: 'bg-purple-100 text-purple-800' },
  { name: 'NEEDS_MANUAL_REVIEW', className: 'bg-blue-100 text-blue-800' },
];

// Skeleton loader for the panel
function AntiHallucinationPanelSkeleton({ className }: { className?: string }) {
  return (
    <div className={cn('space-y-4 animate-pulse', className)}>
      {/* Core Principle Banner Skeleton */}
      <div className="bg-gray-100 rounded-lg p-3 h-12" />
      
      {/* Metrics Grid Skeleton */}
      <div className="grid grid-cols-2 gap-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="rounded-lg border border-gray-200 p-3">
            <div className="h-4 w-24 bg-gray-200 rounded mb-2" />
            <div className="h-8 w-16 bg-gray-200 rounded mb-1" />
            <div className="h-3 w-32 bg-gray-200 rounded" />
          </div>
        ))}
      </div>
      
      {/* Confidence Distribution Skeleton */}
      <div className="bg-gray-50 rounded-lg p-3">
        <div className="h-4 w-32 bg-gray-200 rounded mb-2" />
        <div className="space-y-1">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="flex items-center gap-2">
              <div className="h-3 w-12 bg-gray-200 rounded" />
              <div className="flex-1 h-4 bg-gray-200 rounded" />
              <div className="h-3 w-6 bg-gray-200 rounded" />
            </div>
          ))}
        </div>
      </div>
      
      {/* Rules Skeleton */}
      <div className="border border-gray-200 rounded-lg p-3">
        <div className="h-4 w-40 bg-gray-200 rounded mb-2" />
        <div className="space-y-1">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="h-3 bg-gray-200 rounded w-full" />
          ))}
        </div>
      </div>
    </div>
  );
}

// Export smaller version for embedding
export function AntiHallucinationSummary({
  evidenceCitationRate,
  confidence,
}: {
  evidenceCitationRate: number;
  confidence: number;
}) {
  return (
    <div className="flex items-center gap-4 text-xs">
      <div className="flex items-center gap-1">
        <Shield className="h-3 w-3 text-green-600" />
        <span className="text-gray-600">Evidence:</span>
        <span className="font-medium">{formatPercentage(evidenceCitationRate, 0)}</span>
      </div>
      <div className="flex items-center gap-1">
        <TrendingUp className="h-3 w-3 text-blue-600" />
        <span className="text-gray-600">Confidence:</span>
        <span className="font-medium">{formatPercentage(confidence * 100, 0)}</span>
      </div>
    </div>
  );
}
