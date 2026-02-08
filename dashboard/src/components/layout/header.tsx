'use client';

import React, { useState, useRef, useEffect } from 'react';
import Link from 'next/link';
import { Bell, Search, User, RefreshCw, Settings, LogOut, X, AlertTriangle, Info, CheckCircle } from 'lucide-react';
import { useAuditStore } from '@/lib/store';
import { useHealth } from '@/hooks';
import { cn } from '@/lib/utils';

export function Header() {
  const { notifications, clearNotifications, removeNotification } = useAuditStore();
  const { data: health, isLoading: healthLoading, refetch: refetchHealth } = useHealth();
  
  const [showNotifications, setShowNotifications] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  
  const notificationsRef = useRef<HTMLDivElement>(null);
  const userMenuRef = useRef<HTMLDivElement>(null);
  
  const unreadCount = notifications.filter(n => n.type === 'error' || n.type === 'warning').length;

  // Close dropdowns when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (notificationsRef.current && !notificationsRef.current.contains(event.target as Node)) {
        setShowNotifications(false);
      }
      if (userMenuRef.current && !userMenuRef.current.contains(event.target as Node)) {
        setShowUserMenu(false);
      }
    }
    
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <header className="h-16 bg-white border-b border-gray-200 px-6 flex items-center justify-between">
      {/* Search */}
      <div className="flex-1 max-w-lg">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
          <input
            type="search"
            placeholder="Search audits, findings, controls..."
            className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-gray-900 focus:border-transparent"
          />
        </div>
      </div>

      {/* Right Side */}
      <div className="flex items-center space-x-4">
        {/* System Status */}
        <div className="flex items-center space-x-2">
          <div
            className={cn(
              'h-2 w-2 rounded-full',
              healthLoading ? 'bg-gray-400' :
              health?.status === 'healthy' ? 'bg-green-500' :
              health?.status === 'degraded' ? 'bg-yellow-500' :
              'bg-red-500'
            )}
          />
          <span className="text-sm text-gray-500">
            {healthLoading ? 'Checking...' : health?.status || 'Unknown'}
          </span>
          <button
            onClick={() => refetchHealth()}
            className="p-1 hover:bg-gray-100 rounded transition-colors"
            title="Refresh status"
          >
            <RefreshCw className={cn('h-4 w-4 text-gray-400', healthLoading && 'animate-spin')} />
          </button>
        </div>

        {/* Notifications Dropdown */}
        <div className="relative" ref={notificationsRef}>
          <button 
            onClick={() => {
              setShowNotifications(!showNotifications);
              setShowUserMenu(false);
            }}
            className="relative p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <Bell className="h-5 w-5 text-gray-500" />
            {unreadCount > 0 && (
              <span className="absolute top-1 right-1 h-4 w-4 bg-red-500 text-white text-xs rounded-full flex items-center justify-center">
                {unreadCount > 9 ? '9+' : unreadCount}
              </span>
            )}
          </button>
          
          {/* Notifications Panel */}
          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 bg-white rounded-lg shadow-lg border border-gray-200 z-50">
              <div className="flex items-center justify-between px-4 py-3 border-b border-gray-200">
                <h3 className="font-medium text-gray-900">Notifications</h3>
                {notifications.length > 0 && (
                  <button 
                    onClick={() => clearNotifications()}
                    className="text-xs text-gray-500 hover:text-gray-700"
                  >
                    Clear all
                  </button>
                )}
              </div>
              <div className="max-h-80 overflow-y-auto">
                {notifications.length === 0 ? (
                  <div className="px-4 py-8 text-center">
                    <Bell className="h-8 w-8 text-gray-300 mx-auto mb-2" />
                    <p className="text-sm text-gray-500">No notifications</p>
                  </div>
                ) : (
                  notifications.slice(0, 10).map((notification) => (
                    <div 
                      key={notification.id}
                      className="px-4 py-3 border-b border-gray-100 hover:bg-gray-50 flex items-start gap-3"
                    >
                      <NotificationIcon type={notification.type} />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-gray-900">{notification.title}</p>
                        {notification.message && (
                          <p className="text-sm text-gray-500 truncate">{notification.message}</p>
                        )}
                        <p className="text-xs text-gray-400 mt-1">
                          {formatTimeAgo(new Date(notification.timestamp))}
                        </p>
                      </div>
                      <button 
                        onClick={() => removeNotification(notification.id)}
                        className="p-1 hover:bg-gray-200 rounded"
                      >
                        <X className="h-3 w-3 text-gray-400" />
                      </button>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        {/* User Menu Dropdown */}
        <div className="relative" ref={userMenuRef}>
          <button 
            onClick={() => {
              setShowUserMenu(!showUserMenu);
              setShowNotifications(false);
            }}
            className="flex items-center space-x-2 p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <div className="h-8 w-8 bg-gray-200 rounded-full flex items-center justify-center">
              <User className="h-5 w-5 text-gray-500" />
            </div>
          </button>
          
          {/* User Menu Panel */}
          {showUserMenu && (
            <div className="absolute right-0 mt-2 w-56 bg-white rounded-lg shadow-lg border border-gray-200 z-50">
              <div className="px-4 py-3 border-b border-gray-200">
                <p className="font-medium text-gray-900">Security Auditor</p>
                <p className="text-xs text-gray-500">Admin User</p>
              </div>
              <div className="py-1">
                <Link
                  href="/settings"
                  onClick={() => setShowUserMenu(false)}
                  className="flex items-center gap-3 px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                >
                  <Settings className="h-4 w-4" />
                  Settings
                </Link>
                <a
                  href="http://localhost:8000/api/docs"
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={() => setShowUserMenu(false)}
                  className="flex items-center gap-3 px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                >
                  <Info className="h-4 w-4" />
                  API Documentation
                </a>
              </div>
              <div className="border-t border-gray-200 py-1">
                <button
                  onClick={() => {
                    setShowUserMenu(false);
                    // In a real app, this would handle logout
                    alert('Logout functionality would go here');
                  }}
                  className="flex items-center gap-3 px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 w-full text-left"
                >
                  <LogOut className="h-4 w-4" />
                  Sign out
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}

function NotificationIcon({ type }: { type: string }) {
  switch (type) {
    case 'error':
      return <AlertTriangle className="h-5 w-5 text-red-500 flex-shrink-0" />;
    case 'warning':
      return <AlertTriangle className="h-5 w-5 text-yellow-500 flex-shrink-0" />;
    case 'success':
      return <CheckCircle className="h-5 w-5 text-green-500 flex-shrink-0" />;
    default:
      return <Info className="h-5 w-5 text-blue-500 flex-shrink-0" />;
  }
}

function formatTimeAgo(date: Date): string {
  const seconds = Math.floor((new Date().getTime() - date.getTime()) / 1000);
  
  if (seconds < 60) return 'Just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}
