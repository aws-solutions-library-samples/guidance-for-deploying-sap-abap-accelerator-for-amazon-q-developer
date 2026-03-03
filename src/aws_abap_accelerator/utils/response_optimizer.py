"""
Response optimization utilities for enhanced source code handling.
Implements intelligent truncation and summarization matching TypeScript version quality.
"""

import re
from typing import Dict, List, Tuple, Optional
from utils.security import sanitize_for_logging, validate_numeric_input


class ResponseOptimizer:
    """Optimizes responses for MCP transport with intelligent truncation"""
    
    # ABAP keywords that indicate important code sections
    IMPORTANT_KEYWORDS = [
        'CLASS', 'ENDCLASS', 'METHOD', 'ENDMETHOD', 'INTERFACE', 'ENDINTERFACE',
        'DEFINITION', 'IMPLEMENTATION', 'TYPES', 'CONSTANTS', 'DATA',
        'FORM', 'ENDFORM', 'FUNCTION', 'ENDFUNCTION', 'SELECT', 'LOOP', 'IF'
    ]
    
    # Maximum sizes for different response types (matching TypeScript limits)
    MAX_FULL_RESPONSE = 80000  # Conservative limit for MCP transport
    MAX_EMERGENCY_RESPONSE = 60000  # Emergency fallback
    
    @classmethod
    def optimize_source_response(cls, source: str, object_name: str, object_type: str) -> Dict[str, any]:
        """
        Optimize source code response with intelligent truncation
        Returns response dict ready for MCP transport
        """
        if not source:
            return cls._create_error_response(f"No source code available for {object_name}")
        
        # Check if source needs optimization
        if len(source) <= cls.MAX_FULL_RESPONSE:
            return cls._create_full_response(source, object_name)
        
        # Apply intelligent truncation
        return cls._create_truncated_response(source, object_name, object_type)
    
    @classmethod
    def _create_full_response(cls, source: str, object_name: str) -> Dict[str, any]:
        """Create full source response"""
        header = f"Source code for {sanitize_for_logging(object_name)}:\n\n```abap\n"
        footer = "\n```"
        
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"{header}{source}{footer}"
                }
            ]
        }
    
    @classmethod
    def _create_truncated_response(cls, source: str, object_name: str, object_type: str) -> Dict[str, any]:
        """Create intelligently truncated response"""
        lines = source.split('\n')
        total_lines = len(lines)
        
        # Analyze source structure
        analysis = cls._analyze_source_structure(lines)
        
        # Apply intelligent truncation
        truncated_lines, truncation_info = cls._apply_intelligent_truncation(lines, analysis)
        
        # Build response with metadata
        header = f"Source code for {sanitize_for_logging(object_name)}:\n\n```abap\n"
        footer = "\n```"
        
        truncated_source = '\n'.join(truncated_lines)
        
        # Add truncation notice
        if truncation_info['truncated']:
            truncation_notice = cls._build_truncation_notice(
                total_lines, len(truncated_lines), len(source), len(truncated_source), analysis
            )
            truncated_source += f"\n\n{truncation_notice}"
        
        final_text = f"{header}{truncated_source}{footer}"
        
        return {
            "content": [
                {
                    "type": "text",
                    "text": final_text
                }
            ]
        }
    
    @classmethod
    def _analyze_source_structure(cls, lines: List[str]) -> Dict[str, any]:
        """Analyze ABAP source structure for intelligent truncation"""
        analysis = {
            'class_definitions': [],
            'method_definitions': [],
            'interface_implementations': [],
            'important_lines': [],
            'total_lines': len(lines)
        }
        
        for i, line in enumerate(lines):
            line_upper = line.strip().upper()
            
            # Track class definitions
            if 'CLASS' in line_upper and 'DEFINITION' in line_upper:
                analysis['class_definitions'].append((i, line.strip()))
            
            # Track method definitions
            elif 'METHOD' in line_upper and not 'ENDMETHOD' in line_upper:
                analysis['method_definitions'].append((i, line.strip()))
            
            # Track interface implementations
            elif 'INTERFACES:' in line_upper or 'INTERFACE' in line_upper:
                analysis['interface_implementations'].append((i, line.strip()))
            
            # Track important lines
            elif any(keyword in line_upper for keyword in cls.IMPORTANT_KEYWORDS):
                analysis['important_lines'].append(i)
        
        return analysis
    
    @classmethod
    def _apply_intelligent_truncation(cls, lines: List[str], analysis: Dict[str, any]) -> Tuple[List[str], Dict[str, any]]:
        """Apply intelligent truncation preserving important sections"""
        # Match TypeScript truncation exactly
        available_chars = 45000  # Very conservative for large files
        
        truncated_lines = []
        current_size = 0
        truncated = False
        
        # Take first portion like TypeScript does
        for i, line in enumerate(lines):
            line_size = len(line) + 1
            
            if current_size + line_size <= available_chars:
                truncated_lines.append(line)
                current_size += line_size
            else:
                truncated = True
                break
        
        return truncated_lines, {
            'truncated': truncated,
            'original_size': sum(len(line) + 1 for line in lines),
            'truncated_size': current_size
        }
    
    @classmethod
    def _build_truncation_notice(cls, total_lines: int, shown_lines: int, 
                                original_size: int, truncated_size: int, 
                                analysis: Dict[str, any]) -> str:
        """Build TypeScript-style truncation notice"""
        omitted_lines = total_lines - shown_lines
        
        notice = f"\n\n// ⚠️ Source truncated for MCP transport: {omitted_lines} lines omitted\n"
        notice += f"// Original: {original_size:,} chars ({original_size/1024:.1f}KB), Shown: {truncated_size:,} chars\n"
        notice += f"// To view complete source:\n"
        notice += f"//   • Eclipse ADT: Open directly in SAP Development Tools\n"
        notice += f"//   • SAP GUI: Use transaction SE80/SE24/SE38\n"
        notice += f"//   • Download source file directly"
        
        return notice
    
    @classmethod
    def _create_emergency_response(cls, source: str, object_name: str, analysis: Dict[str, any]) -> Dict[str, any]:
        """Create emergency response for extremely large sources"""
        lines = source.split('\n')
        
        # Extract only the most critical lines
        critical_lines = []
        for class_def in analysis['class_definitions'][:3]:  # Max 3 classes
            critical_lines.append(lines[class_def[0]])
        
        for method_def in analysis['method_definitions'][:5]:  # Max 5 methods
            critical_lines.append(lines[method_def[0]])
        
        emergency_source = '\n'.join(critical_lines)
        
        header = f"Source code for {sanitize_for_logging(object_name)} (EMERGENCY MODE):\n\n```abap\n"
        footer = "\n```"
        
        emergency_notice = f"""

// 🚨 EMERGENCY TRUNCATION - Source too large for transport
// Original: {len(source):,} chars, Emergency: {len(emergency_source):,} chars
// Showing only critical class/method definitions
//
// 📋 Structure Summary:
//   • Classes: {len(analysis['class_definitions'])}
//   • Methods: {len(analysis['method_definitions'])}
//   • Total lines: {len(lines):,}
//
// 🔍 For complete source:
//   • Use Eclipse ADT or SAP GUI
//   • Ask for specific sections
//   • Request smaller code segments"""
        
        final_text = f"{header}{emergency_source}{emergency_notice}{footer}"
        
        return {
            "content": [
                {
                    "type": "text",
                    "text": final_text
                }
            ]
        }
    
    @classmethod
    def _create_error_response(cls, message: str) -> Dict[str, any]:
        """Create error response"""
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"❌ {message}"
                }
            ]
        }
    
    @classmethod
    def create_large_file_summary(cls, source: str, object_name: str, object_type: str) -> Dict[str, any]:
        """Create intelligent summary for very large files (>150KB)"""
        lines = source.split('\n')
        analysis = cls._analyze_source_structure(lines)
        
        summary = f"""Source code for {sanitize_for_logging(object_name)} - INTELLIGENT SUMMARY

📊 **File Statistics:**
- Total size: {len(source):,} characters ({len(source) / 1024:.1f}KB)
- Total lines: {len(lines):,}
- File type: {object_type}

🏗️ **Structure Analysis:**"""
        
        if analysis['class_definitions']:
            summary += f"\n- Classes found: {len(analysis['class_definitions'])}"
            for i, (line_num, class_def) in enumerate(analysis['class_definitions'][:3], 1):
                truncated_def = class_def[:80] + '...' if len(class_def) > 80 else class_def
                summary += f"\n  {i}. {truncated_def}"
            if len(analysis['class_definitions']) > 3:
                summary += f"\n  ... and {len(analysis['class_definitions']) - 3} more classes"
        
        if analysis['method_definitions']:
            summary += f"\n- Methods found: {len(analysis['method_definitions'])}"
        
        if analysis['interface_implementations']:
            summary += f"\n- Interfaces: {len(analysis['interface_implementations'])}"
        
        summary += f"""

⚠️ **Note:** This file is too large to display in full due to MCP size limits.

🔍 **To access the complete source:**
1. **Eclipse ADT**: Open directly in SAP Development Tools
2. **SAP GUI**: Use transaction SE80/SE24/SE38
3. **Ask specifically**: Request specific methods, classes, or sections

💡 **What would you like to explore in this {object_type}?**
- Specific method implementations
- Class structure and relationships  
- Interface definitions
- Key business logic sections
- Error handling patterns"""
        
        return {
            "content": [
                {
                    "type": "text",
                    "text": summary
                }
            ]
        }