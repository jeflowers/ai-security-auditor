'use client';

/**
 * Evidence Gaps List Component
 * 
 * Displays a prioritized list of evidence gaps that need to be
 * addressed for complete compliance assessment.
 * 
 * @module components/dashboard/evidence-gaps-list
 */

import React from 'react';
import { AlertCircle, ChevronRight, FileQuestion, ExternalLink } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { EvidenceGap } from '@/types';

interface EvidenceGapsListProps {
  gaps: EvidenceGap[];
  isLoading?: boolean;
  maxItems?: number;
  onGapClick?: (gap: EvidenceGap) => void;
  className?: string;
}

export function EvidenceGapsList({
  gaps,
  isLoading,
  maxItems,
  onGapClick,
  className,
}: EvidenceGapsListProps) {
  const displayGaps = maxItems ? gaps.slice(0, maxItems) : gaps;
  const hasMore = maxItems && gaps.length > maxItems;

  if (isLoading) {
    return <EvidenceGapsListSkeleton count={maxItems || 5} />;
  }

  if (gaps.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-8 text-gray-500">
        <FileQuestion className="h-8 w-8 mb-2 opacity-50" />
        <p className="text-sm">No evidence gaps identified</p>
        <p className="text-xs mt-1">All controls have sufficient evidence</p>
      </div>
    );
  }

  return (
    <div className={cn('space-y-2', className)}>
      {displayGaps.map((gap, index) => (
        <EvidenceGapItem
          key={`${gap.control}-${index}`}
          gap={gap}
          onClick={onGapClick}
        />
      ))}
      
      {hasMore && (
        <button className="w-full py-2 text-sm text-blue-600 hover:text-blue-700 flex items-center justify-center gap-1">
          View all {gaps.length} gaps
          <ChevronRight className="h-4 w-4" />
        </button>
      )}
    </div>
  );
}

interface EvidenceGapItemProps {
  gap: EvidenceGap;
  onClick?: (gap: EvidenceGap) => void;
}

function EvidenceGapItem({ gap, onClick }: EvidenceGapItemProps) {
  const priorityStyles = {
    high: {
      badge: 'bg-red-100 text-red-700 border-red-200',
      icon: 'text-red-500',
      border: 'border-l-red-500',
    },
    medium: {
      badge: 'bg-yellow-100 text-yellow-700 border-yellow-200',
      icon: 'text-yellow-500',
      border: 'border-l-yellow-500',
    },
    low: {
      badge: 'bg-blue-100 text-blue-700 border-blue-200',
      icon: 'text-blue-500',
      border: 'border-l-blue-500',
    },
  };

  const style = priorityStyles[gap.priority];

  return (
    <div
      className={cn(
        'flex items-start gap-3 p-3 bg-gray-50 rounded-lg border-l-4 hover:bg-gray-100 transition-colors',
        style.border,
        onClick && 'cursor-pointer'
      )}
      onClick={() => onClick?.(gap)}
    >
      <AlertCircle className={cn('h-5 w-5 mt-0.5 flex-shrink-0', style.icon)} />
      
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1">
          <span className="font-mono text-sm font-medium text-gray-900">
            {gap.control}
          </span>
          <span className={cn('px-1.5 py-0.5 text-xs font-medium rounded border', style.badge)}>
            {gap.priority.toUpperCase()}
          </span>
        </div>
        <p className="text-sm text-gray-600">{gap.requirement}</p>
      </div>
      
      {onClick && (
        <ExternalLink className="h-4 w-4 text-gray-400 flex-shrink-0 mt-0.5" />
      )}
    </div>
  );
}

function EvidenceGapsListSkeleton({ count }: { count: number }) {
  return (
    <div className="animate-pulse space-y-2">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="h-16 bg-gray-100 rounded-lg" />
      ))}
    </div>
  );
}

// Compact version for smaller spaces
export function EvidenceGapsCompact({
  gaps,
  maxItems = 3,
}: {
  gaps: EvidenceGap[];
  maxItems?: number;
}) {
  const highPriorityCount = gaps.filter((g) => g.priority === 'high').length;
  const mediumPriorityCount = gaps.filter((g) => g.priority === 'medium').length;
  const lowPriorityCount = gaps.filter((g) => g.priority === 'low').length;

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-sm">
        <span className="text-gray-500">Evidence Gaps</span>
        <span className="font-bold">{gaps.length}</span>
      </div>
      
      <div className="flex gap-2">
        {highPriorityCount > 0 && (
          <span className="flex items-center gap-1 text-xs bg-red-50 text-red-700 px-2 py-1 rounded">
            <span className="font-medium">{highPriorityCount}</span> High
          </span>
        )}
        {mediumPriorityCount > 0 && (
          <span className="flex items-center gap-1 text-xs bg-yellow-50 text-yellow-700 px-2 py-1 rounded">
            <span className="font-medium">{mediumPriorityCount}</span> Medium
          </span>
        )}
        {lowPriorityCount > 0 && (
          <span className="flex items-center gap-1 text-xs bg-blue-50 text-blue-700 px-2 py-1 rounded">
            <span className="font-medium">{lowPriorityCount}</span> Low
          </span>
        )}
      </div>

      <ul className="space-y-1">
        {gaps.slice(0, maxItems).map((gap, index) => (
          <li
            key={`${gap.control}-${index}`}
            className="text-xs text-gray-600 flex items-center gap-1"
          >
            <span className={cn(
              'w-1.5 h-1.5 rounded-full',
              gap.priority === 'high' ? 'bg-red-500' :
              gap.priority === 'medium' ? 'bg-yellow-500' : 'bg-blue-500'
            )} />
            <span className="font-mono font-medium">{gap.control}</span>
            <span className="truncate">{gap.requirement}</span>
          </li>
        ))}
      </ul>
      
      {gaps.length > maxItems && (
        <p className="text-xs text-gray-400">
          +{gaps.length - maxItems} more gaps
        </p>
      )}
    </div>
  );
}
