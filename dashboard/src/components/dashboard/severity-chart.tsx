'use client';

/**
 * Severity Chart Component
 * 
 * Displays a visual representation of finding severity distribution
 * using a donut/pie chart style visualization.
 * 
 * @module components/dashboard/severity-chart
 */

import React from 'react';
import { cn } from '@/lib/utils';

interface SeverityDataPoint {
  name: string;
  value: number;
  color: string;
}

interface SeverityChartProps {
  data: SeverityDataPoint[];
  className?: string;
  showLegend?: boolean;
  size?: 'sm' | 'md' | 'lg';
}

export function SeverityChart({
  data,
  className,
  showLegend = true,
  size = 'md',
}: SeverityChartProps) {
  const total = data.reduce((sum, d) => sum + d.value, 0);
  
  if (total === 0) {
    return (
      <div className={cn('flex flex-col items-center justify-center py-8 text-gray-500', className)}>
        <div className="w-24 h-24 rounded-full border-4 border-gray-200 flex items-center justify-center">
          <span className="text-2xl font-bold text-gray-400">0</span>
        </div>
        <p className="text-sm mt-3">No findings to display</p>
      </div>
    );
  }

  const sizeStyles = {
    sm: { chart: 'w-24 h-24', text: 'text-xl' },
    md: { chart: 'w-32 h-32', text: 'text-2xl' },
    lg: { chart: 'w-40 h-40', text: 'text-3xl' },
  };

  // Calculate percentages for the donut chart
  let cumulativePercent = 0;
  const segments = data.map((d) => {
    const percent = (d.value / total) * 100;
    const startPercent = cumulativePercent;
    cumulativePercent += percent;
    return {
      ...d,
      percent,
      startPercent,
      endPercent: cumulativePercent,
    };
  });

  // Generate conic gradient
  const gradientStops = segments
    .map((s) => `${s.color} ${s.startPercent}% ${s.endPercent}%`)
    .join(', ');

  return (
    <div className={cn('flex flex-col items-center', className)}>
      {/* Donut Chart */}
      <div className="relative">
        <div
          className={cn('rounded-full', sizeStyles[size].chart)}
          style={{
            background: `conic-gradient(${gradientStops})`,
          }}
        />
        {/* Inner circle for donut effect */}
        <div
          className={cn(
            'absolute inset-0 m-auto rounded-full bg-white flex items-center justify-center',
            size === 'sm' ? 'w-14 h-14' : size === 'md' ? 'w-20 h-20' : 'w-24 h-24'
          )}
        >
          <div className="text-center">
            <span className={cn('font-bold text-gray-900', sizeStyles[size].text)}>
              {total}
            </span>
            <p className="text-xs text-gray-500">Total</p>
          </div>
        </div>
      </div>

      {/* Legend */}
      {showLegend && (
        <div className="mt-4 grid grid-cols-2 gap-2 w-full">
          {segments.map((segment) => (
            <div key={segment.name} className="flex items-center gap-2">
              <div
                className="w-3 h-3 rounded-sm flex-shrink-0"
                style={{ backgroundColor: segment.color }}
              />
              <span className="text-xs text-gray-600 truncate">{segment.name}</span>
              <span className="text-xs font-medium text-gray-900 ml-auto">
                {segment.value}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// Bar chart alternative for severity distribution
export function SeverityBarChart({
  data,
  className,
}: {
  data: SeverityDataPoint[];
  className?: string;
}) {
  const maxValue = Math.max(...data.map((d) => d.value), 1);

  return (
    <div className={cn('space-y-2', className)}>
      {data.map((item) => (
        <div key={item.name} className="flex items-center gap-2">
          <span className="text-xs text-gray-600 w-16 truncate">{item.name}</span>
          <div className="flex-1 h-5 bg-gray-100 rounded overflow-hidden">
            <div
              className="h-full rounded transition-all duration-500"
              style={{
                width: `${(item.value / maxValue) * 100}%`,
                backgroundColor: item.color,
              }}
            />
          </div>
          <span className="text-xs font-medium text-gray-900 w-8 text-right">
            {item.value}
          </span>
        </div>
      ))}
    </div>
  );
}

// Mini severity indicator for compact displays
export function SeverityIndicator({
  critical = 0,
  high = 0,
  medium = 0,
  low = 0,
}: {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
}) {
  const total = critical + high + medium + low;
  
  if (total === 0) {
    return (
      <span className="text-xs text-gray-400">No findings</span>
    );
  }

  return (
    <div className="flex items-center gap-1">
      {critical > 0 && (
        <span className="flex items-center gap-0.5 text-xs bg-red-100 text-red-700 px-1.5 py-0.5 rounded">
          <span className="w-1.5 h-1.5 bg-red-600 rounded-full" />
          {critical}
        </span>
      )}
      {high > 0 && (
        <span className="flex items-center gap-0.5 text-xs bg-orange-100 text-orange-700 px-1.5 py-0.5 rounded">
          <span className="w-1.5 h-1.5 bg-orange-500 rounded-full" />
          {high}
        </span>
      )}
      {medium > 0 && (
        <span className="flex items-center gap-0.5 text-xs bg-yellow-100 text-yellow-700 px-1.5 py-0.5 rounded">
          <span className="w-1.5 h-1.5 bg-yellow-500 rounded-full" />
          {medium}
        </span>
      )}
      {low > 0 && (
        <span className="flex items-center gap-0.5 text-xs bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded">
          <span className="w-1.5 h-1.5 bg-blue-500 rounded-full" />
          {low}
        </span>
      )}
    </div>
  );
}
