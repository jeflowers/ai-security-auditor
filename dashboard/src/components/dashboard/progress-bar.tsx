'use client';

import React from 'react';
import { cn } from '@/lib/utils';

interface ProgressBarProps {
  value: number;
  max?: number;
  label?: string;
  showPercentage?: boolean;
  size?: 'sm' | 'md' | 'lg';
  variant?: 'default' | 'success' | 'warning' | 'danger';
  className?: string;
}

const sizeStyles = {
  sm: 'h-1',
  md: 'h-2',
  lg: 'h-3',
};

const variantStyles = {
  default: 'bg-blue-600',
  success: 'bg-green-600',
  warning: 'bg-yellow-500',
  danger: 'bg-red-600',
};

export function ProgressBar({
  value,
  max = 100,
  label,
  showPercentage = true,
  size = 'md',
  variant = 'default',
  className,
}: ProgressBarProps) {
  const percentage = Math.min(Math.max((value / max) * 100, 0), 100);
  
  return (
    <div className={cn('w-full', className)}>
      {(label || showPercentage) && (
        <div className="flex justify-between items-center mb-1">
          {label && <span className="text-sm font-medium text-gray-700">{label}</span>}
          {showPercentage && (
            <span className="text-sm text-gray-500">{Math.round(percentage)}%</span>
          )}
        </div>
      )}
      <div className={cn('w-full bg-gray-200 rounded-full overflow-hidden', sizeStyles[size])}>
        <div
          className={cn('h-full rounded-full transition-all duration-500', variantStyles[variant])}
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  );
}

interface MultiProgressBarProps {
  segments: Array<{
    value: number;
    color: string;
    label?: string;
  }>;
  className?: string;
}

export function MultiProgressBar({ segments, className }: MultiProgressBarProps) {
  const total = segments.reduce((acc, seg) => acc + seg.value, 0);
  
  return (
    <div className={cn('w-full', className)}>
      <div className="flex h-3 bg-gray-200 rounded-full overflow-hidden">
        {segments.map((segment, index) => (
          <div
            key={index}
            className="h-full transition-all duration-500"
            style={{
              width: `${(segment.value / total) * 100}%`,
              backgroundColor: segment.color,
            }}
            title={segment.label ? `${segment.label}: ${segment.value}` : String(segment.value)}
          />
        ))}
      </div>
      <div className="flex justify-between mt-2">
        {segments.map((segment, index) => (
          <div key={index} className="flex items-center text-xs">
            <div
              className="w-2 h-2 rounded-full mr-1"
              style={{ backgroundColor: segment.color }}
            />
            <span className="text-gray-600">{segment.label || segment.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
