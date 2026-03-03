"""
Logging utilities for the ABAP-Accelerator MCP Server.
Python equivalent of logger.ts
"""

import logging
import json
import sys
from typing import Any, Dict, Optional
from pathlib import Path

from .security import sanitize_for_logging


def safe_format_error(error: Any) -> Dict[str, Any]:
    """Function to safely format error objects for logging"""
    if not error:
        return {}
    
    # If it's an Exception object, extract safe properties
    if isinstance(error, Exception):
        return {
            'message': sanitize_for_logging(str(error)),
            'type': sanitize_for_logging(type(error).__name__),
            'args': sanitize_for_logging(error.args) if error.args else None
        }
    
    # If it's a dict with response property (like requests errors)
    if isinstance(error, dict) and 'response' in error:
        return {
            'message': sanitize_for_logging(error.get('message', 'API Error')),
            'status': error.get('response', {}).get('status'),
            'status_text': sanitize_for_logging(error.get('response', {}).get('status_text', '')),
            'data': sanitize_for_logging(error.get('response', {}).get('data'))
        }
    
    # For other objects, convert to string safely
    return {'error': sanitize_for_logging(error)}


class CircularSafeJSONEncoder(json.JSONEncoder):
    """JSON encoder that handles circular references"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._seen = set()
    
    def default(self, obj):
        if id(obj) in self._seen:
            return f"<Circular reference to {type(obj).__name__}>"
        
        self._seen.add(id(obj))
        try:
            if hasattr(obj, '__dict__'):
                return obj.__dict__
            elif hasattr(obj, '__slots__'):
                return {slot: getattr(obj, slot, None) for slot in obj.__slots__}
            else:
                return str(obj)
        finally:
            self._seen.remove(id(obj))


def circular_safe_stringify(obj: Any) -> str:
    """Safely stringify objects with potential circular references"""
    try:
        return json.dumps(obj, cls=CircularSafeJSONEncoder, indent=2, default=str)
    except Exception:
        return str(obj)


class RAPLoggerAdapter(logging.LoggerAdapter):
    """Custom logger adapter for RAP-specific logging"""
    
    def process(self, msg, kwargs):
        # Add RAP context to all log messages
        return f"[RAP] {msg}", kwargs


def setup_logging(level: str = "INFO", log_file: Optional[str] = None) -> None:
    """Setup logging configuration"""
    
    # Create formatter
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Setup console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    
    handlers = [console_handler]
    
    # Setup file handler if log_file is specified
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file, mode='a')
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)
    
    # Configure root logger
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        handlers=handlers,
        force=True
    )


def create_logger(name: str, level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """Create a custom logger with configurable options"""
    logger = logging.getLogger(name)
    
    if not logger.handlers:  # Only add handlers if none exist
        # Create formatter
        formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # File handler if specified
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(log_file, mode='a')
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        logger.setLevel(getattr(logging, level.upper()))
    
    return logger


class RAPLogger:
    """RAP-specific logging functions"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def info(self, message: str, *args, **kwargs):
        """Standard info logging method"""
        self.logger.info(message, *args, **kwargs)
    
    def debug(self, message: str, *args, **kwargs):
        """Standard debug logging method"""
        self.logger.debug(message, *args, **kwargs)
    
    def warning(self, message: str, *args, **kwargs):
        """Standard warning logging method"""
        self.logger.warning(message, *args, **kwargs)
    
    def error(self, message: str, *args, **kwargs):
        """Standard error logging method"""
        self.logger.error(message, *args, **kwargs)
    
    def object_creation(self, object_name: str, object_type: str, package_name: str, 
                       phase: str, details: Optional[Dict[str, Any]] = None):
        """Log RAP object creation events"""
        self.logger.info(
            f"RAP Object Creation - {sanitize_for_logging(phase)}",
            extra={
                'object_name': sanitize_for_logging(object_name),
                'object_type': sanitize_for_logging(object_type),
                'package_name': sanitize_for_logging(package_name),
                'phase': sanitize_for_logging(phase),
                **(details or {})
            }
        )
    
    def syntax_check(self, object_name: str, object_type: str, result: str, 
                    errors: Optional[int] = None, warnings: Optional[int] = None):
        """Log syntax check results"""
        self.logger.info(
            f"RAP Syntax Check - {sanitize_for_logging(result)}",
            extra={
                'object_name': sanitize_for_logging(object_name),
                'object_type': sanitize_for_logging(object_type),
                'result': sanitize_for_logging(result),
                'errors': errors,
                'warnings': warnings
            }
        )
    
    def activation(self, object_name: str, object_type: str, result: str, 
                  details: Optional[Dict[str, Any]] = None):
        """Log activation results"""
        self.logger.info(
            f"RAP Activation - {sanitize_for_logging(result)}",
            extra={
                'object_name': sanitize_for_logging(object_name),
                'object_type': sanitize_for_logging(object_type),
                'result': sanitize_for_logging(result),
                **(details or {})
            }
        )
    
    def cds_view(self, view_name: str, entity_name: str, phase: str, 
                details: Optional[Dict[str, Any]] = None):
        """Log CDS view operations"""
        self.logger.info(
            f"RAP CDS View - {sanitize_for_logging(phase)}",
            extra={
                'view_name': sanitize_for_logging(view_name),
                'entity_name': sanitize_for_logging(entity_name),
                'phase': sanitize_for_logging(phase),
                **(details or {})
            }
        )
    
    def behavior_definition(self, bdef_name: str, entity_name: str, phase: str,
                          details: Optional[Dict[str, Any]] = None):
        """Log behavior definition operations"""
        self.logger.info(
            f"RAP Behavior Definition - {sanitize_for_logging(phase)}",
            extra={
                'bdef_name': sanitize_for_logging(bdef_name),
                'entity_name': sanitize_for_logging(entity_name),
                'phase': sanitize_for_logging(phase),
                **(details or {})
            }
        )
    
    def service_binding(self, binding_name: str, service_definition: str, 
                       binding_type: str, phase: str, details: Optional[Dict[str, Any]] = None):
        """Log service binding operations"""
        self.logger.info(
            f"RAP Service Binding - {sanitize_for_logging(phase)}",
            extra={
                'binding_name': sanitize_for_logging(binding_name),
                'service_definition': sanitize_for_logging(service_definition),
                'binding_type': sanitize_for_logging(binding_type),
                'phase': sanitize_for_logging(phase),
                **(details or {})
            }
        )
    
    def rap_error(self, category: str, object_name: str, object_type: str, message: str,
                 details: Optional[Dict[str, Any]] = None):
        """Log errors with RAP context"""
        self.logger.error(
            f"RAP Error - {sanitize_for_logging(category)}",
            extra={
                'object_name': sanitize_for_logging(object_name),
                'object_type': sanitize_for_logging(object_type),
                'message': sanitize_for_logging(message),
                'category': sanitize_for_logging(category),
                **(details or {})
            }
        )


# Create default logger instance
logger = create_logger(__name__)

# Create RAP logger instance
rap_logger = RAPLogger(logger)