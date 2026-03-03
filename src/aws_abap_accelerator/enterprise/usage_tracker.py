"""
Enterprise Usage Tracker
Tracks tool usage, performance metrics, and user analytics
"""

import logging
import time
import json
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict
from datetime import datetime
from collections import defaultdict
import threading

logger = logging.getLogger(__name__)


@dataclass
class ToolUsageEvent:
    """Represents a single tool usage event"""
    timestamp: datetime
    user_id: str
    system_id: str
    session_id: str
    tool_name: str
    duration_ms: int
    success: bool
    error_message: Optional[str] = None
    request_size: Optional[int] = None
    response_size: Optional[int] = None
    team_id: Optional[str] = None
    request_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/export"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data


class EnterpriseUsageTracker:
    """
    Tracks usage patterns, performance metrics, and analytics
    Thread-safe event collection and aggregation
    """
    
    def __init__(self, max_events: int = 10000):
        self.events: List[ToolUsageEvent] = []
        self.max_events = max_events
        self._lock = threading.RLock()
        
        # In-memory aggregations for quick stats
        self.user_stats = defaultdict(lambda: {
            'total_requests': 0,
            'total_duration_ms': 0,
            'success_count': 0,
            'error_count': 0,
            'tools_used': set(),
            'systems_accessed': set(),
            'first_seen': None,
            'last_seen': None
        })
        
        self.system_stats = defaultdict(lambda: {
            'total_requests': 0,
            'unique_users': set(),
            'tools_used': set(),
            'avg_duration_ms': 0,
            'error_rate': 0.0
        })
        
        self.tool_stats = defaultdict(lambda: {
            'total_calls': 0,
            'total_duration_ms': 0,
            'success_count': 0,
            'error_count': 0,
            'unique_users': set(),
            'avg_duration_ms': 0
        })
        
        logger.info(f"Enterprise Usage Tracker initialized (max_events: {max_events})")
    
    def track_tool_usage(self, user_id: str, system_id: str, session_id: str, 
                        tool_name: str, duration_ms: int, success: bool,
                        error_message: Optional[str] = None,
                        request_size: Optional[int] = None,
                        response_size: Optional[int] = None,
                        team_id: Optional[str] = None,
                        request_id: Optional[str] = None):
        """
        Track a tool usage event
        """
        event = ToolUsageEvent(
            timestamp=datetime.now(),
            user_id=user_id,
            system_id=system_id,
            session_id=session_id,
            tool_name=tool_name,
            duration_ms=duration_ms,
            success=success,
            error_message=error_message,
            request_size=request_size,
            response_size=response_size,
            team_id=team_id,
            request_id=request_id
        )
        
        with self._lock:
            # Add event to list
            self.events.append(event)
            
            # Maintain max events limit
            if len(self.events) > self.max_events:
                # Remove oldest 10% when limit exceeded
                remove_count = self.max_events // 10
                self.events = self.events[remove_count:]
                logger.debug(f"Trimmed {remove_count} old events")
            
            # Update aggregated stats
            self._update_user_stats(event)
            self._update_system_stats(event)
            self._update_tool_stats(event)
        
        # Log the event (structured logging for monitoring)
        logger.info(f"TOOL_USAGE", extra={
            'event_type': 'tool_usage',
            'user_id': user_id,
            'system_id': system_id,
            'tool_name': tool_name,
            'duration_ms': duration_ms,
            'success': success,
            'team_id': team_id,
            'request_id': request_id
        })
    
    def _update_user_stats(self, event: ToolUsageEvent):
        """Update user statistics"""
        stats = self.user_stats[event.user_id]
        stats['total_requests'] += 1
        stats['total_duration_ms'] += event.duration_ms
        
        if event.success:
            stats['success_count'] += 1
        else:
            stats['error_count'] += 1
        
        stats['tools_used'].add(event.tool_name)
        stats['systems_accessed'].add(event.system_id)
        
        if stats['first_seen'] is None:
            stats['first_seen'] = event.timestamp
        stats['last_seen'] = event.timestamp
    
    def _update_system_stats(self, event: ToolUsageEvent):
        """Update system statistics"""
        stats = self.system_stats[event.system_id]
        stats['total_requests'] += 1
        stats['unique_users'].add(event.user_id)
        stats['tools_used'].add(event.tool_name)
        
        # Update average duration
        if stats['total_requests'] > 0:
            total_duration = stats.get('total_duration_ms', 0) + event.duration_ms
            stats['total_duration_ms'] = total_duration
            stats['avg_duration_ms'] = total_duration // stats['total_requests']
        
        # Update error rate
        error_count = stats.get('error_count', 0)
        if not event.success:
            error_count += 1
            stats['error_count'] = error_count
        
        stats['error_rate'] = (error_count / stats['total_requests']) * 100
    
    def _update_tool_stats(self, event: ToolUsageEvent):
        """Update tool statistics"""
        stats = self.tool_stats[event.tool_name]
        stats['total_calls'] += 1
        stats['total_duration_ms'] += event.duration_ms
        stats['unique_users'].add(event.user_id)
        
        if event.success:
            stats['success_count'] += 1
        else:
            stats['error_count'] += 1
        
        # Update average duration
        stats['avg_duration_ms'] = stats['total_duration_ms'] // stats['total_calls']
    
    def get_user_stats(self, user_id: str) -> Dict[str, Any]:
        """Get statistics for a specific user"""
        with self._lock:
            if user_id not in self.user_stats:
                return {}
            
            stats = self.user_stats[user_id].copy()
            # Convert sets to lists for JSON serialization
            stats['tools_used'] = list(stats['tools_used'])
            stats['systems_accessed'] = list(stats['systems_accessed'])
            
            if stats['first_seen']:
                stats['first_seen'] = stats['first_seen'].isoformat()
            if stats['last_seen']:
                stats['last_seen'] = stats['last_seen'].isoformat()
            
            return stats
    
    def get_system_stats(self, system_id: str) -> Dict[str, Any]:
        """Get statistics for a specific system"""
        with self._lock:
            if system_id not in self.system_stats:
                return {}
            
            stats = self.system_stats[system_id].copy()
            stats['unique_users'] = list(stats['unique_users'])
            stats['tools_used'] = list(stats['tools_used'])
            
            return stats
    
    def get_tool_stats(self, tool_name: str) -> Dict[str, Any]:
        """Get statistics for a specific tool"""
        with self._lock:
            if tool_name not in self.tool_stats:
                return {}
            
            stats = self.tool_stats[tool_name].copy()
            stats['unique_users'] = list(stats['unique_users'])
            
            return stats
    
    def get_overall_stats(self) -> Dict[str, Any]:
        """Get overall usage statistics"""
        with self._lock:
            total_events = len(self.events)
            total_users = len(self.user_stats)
            total_systems = len(self.system_stats)
            total_tools = len(self.tool_stats)
            
            # Calculate overall success rate
            success_events = sum(1 for event in self.events if event.success)
            success_rate = (success_events / total_events * 100) if total_events > 0 else 0
            
            # Calculate average duration
            total_duration = sum(event.duration_ms for event in self.events)
            avg_duration = total_duration // total_events if total_events > 0 else 0
            
            return {
                'total_events': total_events,
                'total_users': total_users,
                'total_systems': total_systems,
                'total_tools': total_tools,
                'overall_success_rate': round(success_rate, 2),
                'average_duration_ms': avg_duration,
                'events_in_memory': total_events
            }
    
    def get_top_users(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top users by request count"""
        with self._lock:
            user_list = []
            for user_id, stats in self.user_stats.items():
                user_list.append({
                    'user_id': user_id,
                    'total_requests': stats['total_requests'],
                    'success_rate': (stats['success_count'] / stats['total_requests'] * 100) 
                                  if stats['total_requests'] > 0 else 0,
                    'tools_count': len(stats['tools_used']),
                    'systems_count': len(stats['systems_accessed'])
                })
            
            return sorted(user_list, key=lambda x: x['total_requests'], reverse=True)[:limit]
    
    def get_top_tools(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get most used tools"""
        with self._lock:
            tool_list = []
            for tool_name, stats in self.tool_stats.items():
                tool_list.append({
                    'tool_name': tool_name,
                    'total_calls': stats['total_calls'],
                    'success_rate': (stats['success_count'] / stats['total_calls'] * 100)
                                  if stats['total_calls'] > 0 else 0,
                    'avg_duration_ms': stats['avg_duration_ms'],
                    'unique_users': len(stats['unique_users'])
                })
            
            return sorted(tool_list, key=lambda x: x['total_calls'], reverse=True)[:limit]
    
    def export_events(self, start_time: Optional[datetime] = None, 
                     end_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Export events for external analysis"""
        with self._lock:
            filtered_events = self.events
            
            if start_time:
                filtered_events = [e for e in filtered_events if e.timestamp >= start_time]
            
            if end_time:
                filtered_events = [e for e in filtered_events if e.timestamp <= end_time]
            
            return [event.to_dict() for event in filtered_events]
    
    def clear_old_events(self, older_than_hours: int = 24):
        """Clear events older than specified hours"""
        cutoff_time = datetime.now() - timedelta(hours=older_than_hours)
        
        with self._lock:
            original_count = len(self.events)
            self.events = [event for event in self.events if event.timestamp > cutoff_time]
            removed_count = original_count - len(self.events)
            
            if removed_count > 0:
                logger.info(f"Cleared {removed_count} events older than {older_than_hours} hours")


# Global usage tracker instance
enterprise_usage_tracker = EnterpriseUsageTracker()