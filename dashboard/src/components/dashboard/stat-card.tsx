'use client';

import React from 'react';
import { cn } from '@/lib/utils';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon?: LucideIcon;
  trend?: {
    value: number;
    isPositive: boolean;
  };
  variant?: 'default' | 'critical' | 'high' | 'medium' | 'low' | 'success';
  className?: string;
}

const variantStyles = {
  default: 'border-gray-200',
  critical: 'border-l-4 border-l-red-600 border-gray-200',
  high: 'border-l-4 border-l-orange-500 border-gray-200',
  medium: 'border-l-4 border-l-yellow-500 border-gray-200',
  low: 'border-l-4 border-l-blue-500 border-gray-200',
  success: 'border-l-4 border-l-green-500 border-gray-200',
};

const iconStyles = {
  default: 'bg-gray-100 text-gray-600',
  critical: 'bg-red-100 text-red-600',
  high: 'bg-orange-100 text-orange-600',
  medium: 'bg-yellow-100 text-yellow-600',
  low: 'bg-blue-100 text-blue-600',
  success: 'bg-green-100 text-green-600',
};

export function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  variant = 'default',
  className,
}: StatCardProps) {
  return (
    <div
      className={cn(
        'bg-white rounded-lg border shadow-sm p-6',
        variantStyles[variant],
        className
      )}
    >
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-sm font-medium text-gray-500">{title}</p>
          <p className="mt-2 text-3xl font-bold text-gray-900">{value}</p>
          {subtitle && (
            <p className="mt-1 text-sm text-gray-500">{subtitle}</p>
          )}
          {trend && (
            <div className={cn(
              'mt-2 flex items-center text-sm',
              trend.isPositive ? 'text-green-600' : 'text-red-600'
            )}>
              <span>{trend.isPositive ? '↑' : '↓'}</span>
              <span className="ml-1">{Math.abs(trend.value)}%</span>
              <span className="ml-1 text-gray-500">vs last audit</span>
            </div>
          )}
        </div>
        {Icon && (
          <div className={cn('p-3 rounded-lg', iconStyles[variant])}>
            <Icon className="h-6 w-6" />
          </div>
        )}
      </div>
    </div>
  );
}
