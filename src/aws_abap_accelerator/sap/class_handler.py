"""
Class handler for ABAP class operations.
Python equivalent of class-handler.ts
"""

import re
from typing import List, Optional, Dict, Any
import logging
from pydantic import BaseModel

from sap_types.sap_types import ObjectOperationResult, SyntaxError as SAPSyntaxError, CreateObjectRequest
from utils.security import sanitize_for_logging, sanitize_for_xml, validate_object_name
from utils.logger import rap_logger

logger = logging.getLogger(__name__)

# Pre-compiled regex patterns for security and performance
CONTROL_CHARS_REGEX = re.compile(r'[\r\n\t]')
SANITIZE_REPLACEMENT = '_'


class MethodParameter(BaseModel):
    """Method parameter definition"""
    name: str
    type: str
    direction: str  # IMPORTING, EXPORTING, CHANGING, RETURNING
    optional: bool = False


class MethodDefinition(BaseModel):
    """Method definition"""
    name: str
    visibility: str  # PUBLIC, PROTECTED, PRIVATE
    is_static: bool = False
    is_abstract: bool = False
    is_for_testing: bool = False
    parameters: Optional[List[MethodParameter]] = None
    return_type: Optional[str] = None
    implementation: Optional[str] = None


class ClassDefinition(BaseModel):
    """Class definition"""
    name: str
    description: str
    package_name: str
    is_test_class: bool = False
    interfaces: Optional[List[str]] = None
    super_class: Optional[str] = None
    visibility: str = "PUBLIC"  # PUBLIC, PRIVATE, PROTECTED


class ClassHandler:
    """Handler for ABAP class operations"""
    
    # Section patterns for parsing class structure
    SECTION_PATTERNS = {
        'PUBLIC': re.compile(r'(PUBLIC\s+SECTION\..*?)(?=\s+(?:PROTECTED|PRIVATE)\s+SECTION\.|ENDCLASS\.)', re.DOTALL),
        'PROTECTED': re.compile(r'(PROTECTED\s+SECTION\..*?)(?=\s+(?:PUBLIC|PRIVATE)\s+SECTION\.|ENDCLASS\.)', re.DOTALL),
        'PRIVATE': re.compile(r'(PRIVATE\s+SECTION\..*?)(?=\s+(?:PUBLIC|PROTECTED)\s+SECTION\.|ENDCLASS\.)', re.DOTALL)
    }
    
    def __init__(self, sap_client):
        self.sap_client = sap_client
    
    async def create_class(self, definition: ClassDefinition, 
                          initial_methods: Optional[List[MethodDefinition]] = None) -> ObjectOperationResult:
        """Create a new ABAP class with enhanced structure handling"""
        try:
            # Validate inputs before processing
            validated_name = validate_object_name(definition.name)
            validated_super_class = validate_object_name(definition.super_class) if definition.super_class else None
            validated_interfaces = [validate_object_name(intf) for intf in (definition.interfaces or [])]
            
            # Create sanitized definition
            # nosemgrep: is-function-without-parentheses - is_test_class is a boolean attribute in ClassDefinition Pydantic model
            sanitized_definition = ClassDefinition(
                name=validated_name,
                description=definition.description,
                package_name=definition.package_name,
                is_test_class=definition.is_test_class,
                interfaces=validated_interfaces,
                super_class=validated_super_class,
                visibility=definition.visibility
            )
            
            sanitized_name = validated_name.replace(CONTROL_CHARS_REGEX, SANITIZE_REPLACEMENT) or 'unknown'
            logger.info(f"Creating class {sanitize_for_logging(sanitized_name)} with enhanced structure")
            
            # Check if class already exists
            existing_source = await self.sap_client.get_source(validated_name, 'CLAS')
            if existing_source:
                logger.info(f"Class {sanitize_for_logging(sanitized_name)} already exists, updating with new structure")
                
                # If methods provided, update the existing class
                if initial_methods:
                    return await self.update_class_methods(validated_name, initial_methods)
                
                return ObjectOperationResult(
                    created=True,
                    syntax_check_passed=True,
                    activated=True,
                    errors=[],
                    warnings=[SAPSyntaxError(line=1, message='Class already exists, no changes made', severity='WARNING')]
                )
            
            # Generate class template
            source_code = self.generate_class_template(sanitized_definition, initial_methods)
            
            request = CreateObjectRequest(
                name=validated_name,
                type='CLAS',
                description=definition.description,
                package_name=definition.package_name,
                source_code=source_code
            )
            
            return await self.sap_client.create_object_with_syntax_check(request)
            
        except Exception as e:
            logger.error(f"Error creating class: {sanitize_for_logging(str(e))}")
            return ObjectOperationResult(
                created=False,
                syntax_check_passed=False,
                activated=False,
                errors=[SAPSyntaxError(line=1, message=str(e), severity='ERROR')],
                warnings=[]
            )
    
    def generate_class_template(self, definition: ClassDefinition, 
                               methods: Optional[List[MethodDefinition]] = None) -> str:
        """Generate ABAP class template"""
        try:
            lines = []
            
            # Class definition line
            class_line = f"CLASS {definition.name} DEFINITION"
            
            if definition.visibility and definition.visibility != "PUBLIC":
                class_line += f" {definition.visibility}"
            
            # nosemgrep: is-function-without-parentheses - is_test_class is a boolean attribute in ClassDefinition Pydantic model
            if definition.is_test_class:
                class_line += " FOR TESTING"
            
            if definition.super_class:
                class_line += f" INHERITING FROM {definition.super_class}"
            
            class_line += "."
            lines.append(class_line)
            lines.append("")
            
            # Add interfaces if any
            if definition.interfaces:
                for interface in definition.interfaces:
                    lines.append(f"  INTERFACES {interface}.")
                lines.append("")
            
            # Generate sections with methods
            sections = self._generate_sections(methods or [])
            
            for section_name, section_content in sections.items():
                if section_content.strip():
                    lines.append(f"  {section_name} SECTION.")
                    lines.extend(section_content.split('\n'))
                    lines.append("")
            
            lines.append("ENDCLASS.")
            lines.append("")
            lines.append("")
            
            # Implementation section
            lines.append(f"CLASS {definition.name} IMPLEMENTATION.")
            lines.append("")
            
            # Add method implementations
            if methods:
                for method in methods:
                    if method.implementation:
                        lines.append(f"  METHOD {method.name}.")
                        # Add implementation with proper indentation
                        impl_lines = method.implementation.split('\n')
                        for impl_line in impl_lines:
                            if impl_line.strip():
                                lines.append(f"    {impl_line}")
                            else:
                                lines.append("")
                        lines.append("  ENDMETHOD.")
                        lines.append("")
            
            lines.append("ENDCLASS.")
            
            return '\n'.join(lines)
            
        except Exception as e:
            logger.error(f"Error generating class template: {sanitize_for_logging(str(e))}")
            return f"CLASS {definition.name} DEFINITION.\nENDCLASS.\nCLASS {definition.name} IMPLEMENTATION.\nENDCLASS."
    
    def _generate_sections(self, methods: List[MethodDefinition]) -> Dict[str, str]:
        """Generate class sections with methods"""
        sections = {
            'PUBLIC': '',
            'PROTECTED': '',
            'PRIVATE': ''
        }
        
        # Group methods by visibility
        methods_by_visibility = {
            'PUBLIC': [],
            'PROTECTED': [],
            'PRIVATE': []
        }
        
        for method in methods:
            visibility = method.visibility.upper()
            if visibility in methods_by_visibility:
                methods_by_visibility[visibility].append(method)
        
        # Generate each section
        for visibility, method_list in methods_by_visibility.items():
            if method_list:
                section_lines = []
                
                for method in method_list:
                    method_line = f"    METHODS {method.name}"
                    
                    # Add parameters
                    if method.parameters:
                        param_parts = []
                        for param in method.parameters:
                            param_str = f"{param.direction} {param.name} TYPE {param.type}"
                            if param.optional:
                                param_str += " OPTIONAL"
                            param_parts.append(param_str)
                        
                        if param_parts:
                            method_line += f" {' '.join(param_parts)}"
                    
                    # Add return type
                    if method.return_type:
                        method_line += f" RETURNING VALUE(result) TYPE {method.return_type}"
                    
                    # Add modifiers
                    # nosemgrep: is-function-without-parentheses - is_static, is_abstract, is_for_testing are boolean attributes in MethodDefinition Pydantic model
                    if method.is_static:
                        method_line += " CLASS-METHODS"
                    
                    if method.is_abstract:
                        method_line += " ABSTRACT"
                    
                    if method.is_for_testing:
                        method_line += " FOR TESTING"
                    
                    method_line += "."
                    section_lines.append(method_line)
                
                sections[visibility] = '\n'.join(section_lines)
        
        return sections
    
    async def update_class_methods(self, class_name: str, 
                                  methods: List[MethodDefinition]) -> ObjectOperationResult:
        """Update class methods"""
        try:
            logger.info(f"Updating methods for class {sanitize_for_logging(class_name)}")
            
            # Get existing class source
            existing_source = await self.sap_client.get_source(class_name, 'CLAS')
            if not existing_source:
                return ObjectOperationResult(
                    updated=False,
                    syntax_check_passed=False,
                    activated=False,
                    errors=[SAPSyntaxError(line=1, message="Class not found", severity='ERROR')],
                    warnings=[]
                )
            
            # Parse and update the class
            updated_source = self._update_class_source_with_methods(existing_source, methods)
            
            # Update the source
            return await self.sap_client.update_source_with_syntax_check(
                class_name, 'CLAS', updated_source
            )
            
        except Exception as e:
            logger.error(f"Error updating class methods: {sanitize_for_logging(str(e))}")
            return ObjectOperationResult(
                updated=False,
                syntax_check_passed=False,
                activated=False,
                errors=[SAPSyntaxError(line=1, message=str(e), severity='ERROR')],
                warnings=[]
            )
    
    def _update_class_source_with_methods(self, source: str, 
                                         methods: List[MethodDefinition]) -> str:
        """Update class source with new methods"""
        try:
            # This is a simplified implementation
            # In a full implementation, you would parse the existing class structure
            # and intelligently merge the new methods
            
            # For now, append methods to the end of the implementation section
            lines = source.split('\n')
            
            # Find the implementation section
            impl_start = -1
            impl_end = -1
            
            for i, line in enumerate(lines):
                if 'IMPLEMENTATION' in line.upper():
                    impl_start = i
                elif impl_start != -1 and 'ENDCLASS' in line.upper():
                    impl_end = i
                    break
            
            if impl_start != -1 and impl_end != -1:
                # Insert methods before ENDCLASS
                method_lines = []
                for method in methods:
                    if method.implementation:
                        method_lines.append(f"  METHOD {method.name}.")
                        impl_lines = method.implementation.split('\n')
                        for impl_line in impl_lines:
                            if impl_line.strip():
                                method_lines.append(f"    {impl_line}")
                            else:
                                method_lines.append("")
                        method_lines.append("  ENDMETHOD.")
                        method_lines.append("")
                
                # Insert the new methods
                lines[impl_end:impl_end] = method_lines
            
            return '\n'.join(lines)
            
        except Exception as e:
            logger.error(f"Error updating class source: {sanitize_for_logging(str(e))}")
            return source
    
    async def add_interface_to_class(self, class_name: str, interface_name: str) -> ObjectOperationResult:
        """Add interface to existing class"""
        try:
            logger.info(f"Adding interface {sanitize_for_logging(interface_name)} to class {sanitize_for_logging(class_name)}")
            
            # Get existing class source
            existing_source = await self.sap_client.get_source(class_name, 'CLAS')
            if not existing_source:
                return ObjectOperationResult(
                    updated=False,
                    syntax_check_passed=False,
                    activated=False,
                    errors=[SAPSyntaxError(line=1, message="Class not found", severity='ERROR')],
                    warnings=[]
                )
            
            # Add interface to the class
            updated_source = self._add_interface_to_source(existing_source, interface_name)
            
            # Update the source
            return await self.sap_client.update_source_with_syntax_check(
                class_name, 'CLAS', updated_source
            )
            
        except Exception as e:
            logger.error(f"Error adding interface to class: {sanitize_for_logging(str(e))}")
            return ObjectOperationResult(
                updated=False,
                syntax_check_passed=False,
                activated=False,
                errors=[SAPSyntaxError(line=1, message=str(e), severity='ERROR')],
                warnings=[]
            )
    
    def _add_interface_to_source(self, source: str, interface_name: str) -> str:
        """Add interface to class source"""
        try:
            lines = source.split('\n')
            
            # Find the class definition section
            for i, line in enumerate(lines):
                if 'CLASS' in line.upper() and 'DEFINITION' in line.upper():
                    # Look for the first empty line or PUBLIC SECTION to insert interface
                    for j in range(i + 1, len(lines)):
                        if not lines[j].strip() or 'PUBLIC SECTION' in lines[j].upper():
                            # Insert interface statement
                            lines.insert(j, f"  INTERFACES {interface_name}.")
                            break
                    break
            
            return '\n'.join(lines)
            
        except Exception as e:
            logger.error(f"Error adding interface to source: {sanitize_for_logging(str(e))}")
            return source
    
    async def create_test_class(self, class_name: str, 
                               test_methods: List[MethodDefinition]) -> ObjectOperationResult:
        """Create unit test class inside of a class using ADT testclasses endpoint
        
        This creates a local test class in /includes/testclasses of the main class,
        matching the TypeScript implementation.
        """
        try:
            sanitized_class_name = CONTROL_CHARS_REGEX.sub(SANITIZE_REPLACEMENT, class_name) if class_name else 'unknown'
            logger.info(f"Creating unit test class for {sanitize_for_logging(sanitized_class_name)}")
            
            # Validate testMethods array
            if not test_methods or len(test_methods) == 0:
                return ObjectOperationResult(
                    updated=False,
                    syntax_check_passed=False,
                    activated=False,
                    errors=[SAPSyntaxError(line=1, message='No test methods provided', severity='ERROR')],
                    warnings=[]
                )
            
            # Generate test class source code
            test_class_source = self._generate_test_class_source(class_name, test_methods)
            
            # Use the specific ADT URL for test classes
            test_class_url = f"/sap/bc/adt/oo/classes/{class_name}/includes/testclasses"
            
            return await self.sap_client.update_test_class_source(class_name, test_class_source, test_class_url)
            
        except Exception as e:
            logger.error(f"Error creating test class: {sanitize_for_logging(str(e))}")
            return ObjectOperationResult(
                updated=False,
                syntax_check_passed=False,
                activated=False,
                errors=[SAPSyntaxError(line=1, message=str(e), severity='ERROR')],
                warnings=[]
            )
    
    def _generate_test_class_source(self, class_name: str, test_methods: List[MethodDefinition]) -> str:
        """Generate standalone test class source code (matching TypeScript implementation)"""
        lines = []
        
        # Header comment
        lines.append(f'*"* Local Test Class for {class_name}')
        
        # Class definition
        lines.append(f'CLASS ltc_{class_name.lower()} DEFINITION FOR TESTING DURATION SHORT RISK LEVEL HARMLESS.')
        lines.append('  PRIVATE SECTION.')
        lines.append('    METHODS:')
        
        # Add test method signatures
        for i, method in enumerate(test_methods):
            comma = ',' if i < len(test_methods) - 1 else '.'
            lines.append(f'      {method.name} FOR TESTING{comma}')
        
        lines.append('ENDCLASS.')
        lines.append('')
        
        # Class implementation
        lines.append(f'CLASS ltc_{class_name.lower()} IMPLEMENTATION.')
        
        # Add test method implementations
        for method in test_methods:
            lines.append(f'  METHOD {method.name}.')
            implementation = method.implementation if method.implementation else '" Test implementation'
            logger.info(f"Generating test method {method.name}: implementation={'<provided>' if method.implementation else '<default>'}, length={len(method.implementation) if method.implementation else 0}")
            lines.append(f'    {implementation}')
            lines.append('  ENDMETHOD.')
            lines.append('')
        
        lines.append('ENDCLASS.')
        
        return '\n'.join(lines)
