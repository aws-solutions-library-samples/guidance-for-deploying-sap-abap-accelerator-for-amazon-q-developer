"""
Tool handlers for MCP server operations.
Contains the business logic for handling MCP tool calls.
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional

from sap.sap_client import SAPADTClient
from sap.class_handler import ClassDefinition, MethodDefinition
from sap_types.sap_types import (
    CreateObjectRequest, ATCCheckArgs, ObjectType, BindingType
)
from utils.logger import rap_logger
from utils.security import sanitize_for_logging, validate_numeric_input
from utils.response_optimizer import ResponseOptimizer

logger = logging.getLogger(__name__)


class ToolHandlers:
    """Handlers for MCP tool operations"""
    
    def __init__(self, sap_client: SAPADTClient):
        self.sap_client = sap_client
    
    async def _ensure_connected(self) -> bool:
        """Ensure SAP client is connected"""
        if not self.sap_client.session or not self.sap_client.csrf_token:
            logger.info("SAP client not connected, attempting to connect...")
            connected = await self.sap_client.connect()
            if not connected:
                logger.error("Failed to connect to SAP system")
                return False
            logger.info("Successfully connected to SAP system")
        return True
    
    def handle_connection_status(self, connected: bool) -> str:
        """Handle connection status check"""
        try:
            status = "Connected" if connected else "Disconnected"
            
            connection_details = (
                f"- Host: {self.sap_client.connection.host}\n"
                f"- Client: {self.sap_client.connection.client}\n"
                f"- Language: {self.sap_client.connection.language}\n"
                f"- Secure: {'Yes' if self.sap_client.connection.secure else 'No'}\n"
                f"- Auth Type: {self.sap_client.connection.auth_type.value}\n"
                f"- Username: {self.sap_client.connection.username}"
            )
            
            if self.sap_client.connection.instance_number:
                connection_details = (
                    f"- Host: {self.sap_client.connection.host}\n"
                    f"- Instance: {self.sap_client.connection.instance_number}\n"
                    f"- Client: {self.sap_client.connection.client}\n"
                    f"- Language: {self.sap_client.connection.language}\n"
                    f"- Secure: {'Yes' if self.sap_client.connection.secure else 'No'}\n"
                    f"- Auth Type: {self.sap_client.connection.auth_type.value}\n"
                    f"- Username: {self.sap_client.connection.username}"
                )
            
            return f"SAP Connection Status: {status}\n\nConnection Details:\n{connection_details}"
            
        except Exception as e:
            logger.error(f"Error getting connection status: {sanitize_for_logging(str(e))}")
            return f"Error getting connection status: {sanitize_for_logging(str(e))}"
    
    async def handle_get_objects(self, package_name: Optional[str] = None) -> str:
        """Handle get objects request"""
        try:
            logger.info(f"Getting objects{f' from package {sanitize_for_logging(package_name)}' if package_name else ''}")
            
            # Ensure we're connected to SAP
            if not await self._ensure_connected():
                return f"❌ Failed to connect to SAP system. Please check your configuration and network connectivity."
            
            objects = await self.sap_client.get_objects(package_name)
            
            if objects:
                object_list = "\n".join([
                    f"• {obj.name} ({obj.type}) - {obj.description or 'No description'}"
                    for obj in objects
                ])
                return f"Found {validate_numeric_input(len(objects), 'objects')} objects:\n\n{object_list}"
            else:
                return f"No objects found{f' in package {sanitize_for_logging(package_name)}' if package_name else ''}."
                
        except Exception as e:
            logger.error(f"Error getting objects: {sanitize_for_logging(str(e))}")
            return f"Error getting objects: {sanitize_for_logging(str(e))}"
    
    async def handle_create_object(self, args: Dict[str, Any]) -> str:
        """Handle create object request"""
        try:
            object_name = args.get('name', '')
            object_type = args.get('type', '')
            package_name = args.get('package_name') or "$TMP"  # Default to $TMP if not provided
            
            logger.info(f"Creating object {sanitize_for_logging(object_name)} ({sanitize_for_logging(object_type)}) in package {sanitize_for_logging(package_name)}")
            
            # Ensure we're connected to SAP
            if not await self._ensure_connected():
                return f"❌ Failed to connect to SAP system. Please check your configuration and network connectivity."
            
            rap_logger.object_creation(
                sanitize_for_logging(object_name),
                sanitize_for_logging(object_type),
                sanitize_for_logging(package_name),
                'MCP_REQUEST_RECEIVED',
                {
                    'has_source_code': bool(args.get('source_code')),
                    'has_methods': bool(args.get('methods')),
                    'is_test_class': bool(args.get('is_test_class')),
                    'interfaces': len(args.get('interfaces') or []),
                    'service_definition': args.get('service_definition'),
                    'binding_type': args.get('binding_type'),
                    'is_tmp_package': package_name.upper() == "$TMP"
                }
            )
            
            # Handle enhanced class creation
            if object_type == 'CLAS' and (args.get('methods') or args.get('interfaces') or args.get('is_test_class')):
                return await self._handle_enhanced_class_creation(args)
            
            # Handle standard object creation
            result_message = await self._handle_standard_object_creation(args)
            
            # If object was created successfully and transport_request is provided, check assignment
            if args.get('transport_request') and "✅" in result_message:
                try:
                    # First, check if object is already assigned to the requested transport
                    logger.info(f"Checking transport assignment for {sanitize_for_logging(args['name'])}")
                    
                    # Lock the object to get current transport assignment info
                    lock_info = await self.sap_client.lock_object(args['name'], args['type'])
                    
                    if lock_info and lock_info.get('CORRNR'):
                        current_transport = lock_info.get('CORRNR')
                        logger.info(f"Object {sanitize_for_logging(args['name'])} is currently assigned to transport: {sanitize_for_logging(current_transport)}")
                        
                        if current_transport == args['transport_request']:
                            # Object is already assigned to the requested transport
                            result_message += f"\n\n✅ Object already assigned to transport request {args['transport_request']}"
                            logger.info(f"Object {sanitize_for_logging(args['name'])} already assigned to requested transport {sanitize_for_logging(args['transport_request'])}")
                        else:
                            # Object is assigned to a different transport, attempt reassignment
                            logger.info(f"Object assigned to different transport ({sanitize_for_logging(current_transport)}), attempting reassignment to {sanitize_for_logging(args['transport_request'])}")
                            transport_result = await self.sap_client.assign_object_to_transport(
                                args['name'], args['type'], args['transport_request']
                            )
                            if transport_result.success:
                                result_message += f"\n\n✅ Object reassigned from transport {current_transport} to {args['transport_request']}"
                            else:
                                result_message += f"\n\n⚠️ Object created but reassignment failed: {transport_result.message}"
                        
                        # Unlock the object after checking
                        try:
                            await self.sap_client.unlock_object(args['name'], args['type'], lock_info.get('LOCK_HANDLE'))
                        except Exception as unlock_error:
                            logger.warning(f"Failed to unlock object after transport check: {sanitize_for_logging(str(unlock_error))}")
                    
                    else:
                        # No current transport assignment found, attempt manual assignment
                        logger.info(f"No current transport assignment found for {sanitize_for_logging(args['name'])}, attempting manual assignment")
                        transport_result = await self.sap_client.assign_object_to_transport(
                            args['name'], args['type'], args['transport_request']
                        )
                        if transport_result.success:
                            result_message += f"\n\n✅ Object assigned to transport request {args['transport_request']}"
                        else:
                            result_message += f"\n\n⚠️ Object created but transport assignment failed: {transport_result.message}"
                
                except Exception as e:
                    logger.error(f"Error checking/assigning transport for {sanitize_for_logging(args['name'])}: {sanitize_for_logging(str(e))}")
                    result_message += f"\n\n⚠️ Object created but transport assignment check failed: {sanitize_for_logging(str(e))}"
            
            return result_message
            
        except Exception as e:
            logger.error(f"Error creating object: {sanitize_for_logging(str(e))}")
            return f"Error creating object: {sanitize_for_logging(str(e))}"
    
    async def _handle_enhanced_class_creation(self, args: Dict[str, Any]) -> str:
        """Handle enhanced class creation with methods and interfaces"""
        try:
            # Create class definition
            definition = ClassDefinition(
                name=args['name'],
                description=args['description'],
                package_name=args['package_name'],
                is_test_class=args.get('is_test_class', False),
                interfaces=args.get('interfaces', []),
                super_class=args.get('super_class'),
                visibility=args.get('visibility', 'PUBLIC')
            )
            
            # Create method definitions
            methods = []
            if args.get('methods'):
                for method_data in args['methods']:
                    method = MethodDefinition(
                        name=method_data['name'],
                        visibility=method_data['visibility'],
                        is_for_testing=method_data.get('is_for_testing', False),
                        implementation=method_data.get('implementation')
                    )
                    methods.append(method)
            
            # Create the class
            result = await self.sap_client.class_handler.create_class(definition, methods)
            
            return self._format_object_operation_result(args['name'], result, is_creation=True)
            
        except Exception as e:
            logger.error(f"Error in enhanced class creation: {sanitize_for_logging(str(e))}")
            return f"Error in enhanced class creation: {sanitize_for_logging(str(e))}"
    
    async def _handle_standard_object_creation(self, args: Dict[str, Any]) -> str:
        """Handle standard object creation"""
        try:
            # Ensure package_name is set (default to $TMP if not provided)
            package_name = args.get('package_name') or "$TMP"
            args['package_name'] = package_name  # Update args to ensure consistency
            
            # Map string type to ObjectType enum
            object_type_str = args['type']
            try:
                object_type = ObjectType(object_type_str)
            except ValueError:
                return f"Invalid object type: {sanitize_for_logging(object_type_str)}"
            
            # Map binding type if provided
            binding_type = None
            if args.get('binding_type'):
                try:
                    binding_type = BindingType(args['binding_type'])
                except ValueError:
                    return f"Invalid binding type: {sanitize_for_logging(args['binding_type'])}"
            
            request = CreateObjectRequest(
                name=args['name'],
                type=object_type,
                description=args['description'],
                package_name=package_name,  # Use the ensured package_name
                source_code=args.get('source_code'),
                service_definition=args.get('service_definition'),
                binding_type=binding_type,
                behavior_definition=args.get('behavior_definition'),
                transport_request=args.get('transport_request')
            )
            
            result = await self.sap_client.create_object_with_syntax_check(request)
            
            return self._format_object_operation_result(args['name'], result, is_creation=True)
            
        except Exception as e:
            logger.error(f"Error in standard object creation: {sanitize_for_logging(str(e))}")
            return f"Error in standard object creation: {sanitize_for_logging(str(e))}"
    
    async def handle_get_source(self, object_name: str, object_type: str) -> Dict[str, Any]:
        """Handle get source request"""
        try:
            # Add console-style logging to match TypeScript version
            print(f"[MCP-SERVER] handleGetSource called for {sanitize_for_logging(object_name)} ({sanitize_for_logging(object_type)})")
            logger.info(f"Getting source code for {sanitize_for_logging(object_name)}")
            
            # Ensure we're connected to SAP
            if not await self._ensure_connected():
                return f"❌ Failed to connect to SAP system. Please check your configuration and network connectivity."
            
            source = await self.sap_client.get_source(object_name, object_type)
            print(f"[MCP-SERVER] getSource result:", 'SUCCESS' if source else 'FAILED')
            
            if not source:
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Could not retrieve source code for {sanitize_for_logging(object_name)}"
                        }
                    ]
                }
            
            # Use enhanced response optimizer for optimal source handling (matching TypeScript quality)
            print(f"[MCP-SERVER] Processing source response with ResponseOptimizer")
            print(f"[MCP-SERVER] Source size: {len(source):,} chars ({len(source) / 1024:.1f}KB)")
            
            # Let the ResponseOptimizer handle all the intelligent truncation and formatting
            # This will show actual source code with smart truncation, not summaries
            optimized_response = ResponseOptimizer.optimize_source_response(source, object_name, object_type)
            
            # Log the optimization results
            import json
            json_response = json.dumps(optimized_response)
            print(f"[MCP-SERVER] Optimized response size: {len(json_response):,} chars")
            logger.info(f"Source optimization complete - Original: {len(source)}, Final JSON: {len(json_response)}")
            
            return optimized_response
            
        except Exception as e:
            print(f"[MCP-SERVER] Error in handleGetSource: {sanitize_for_logging(str(e))}")
            logger.error(f"Error getting source: {sanitize_for_logging(str(e))}")
            
            # Enhanced error response with troubleshooting guidance
            error_message = f"""❌ Error retrieving source code for {sanitize_for_logging(object_name)}

🔍 **Error Details:**
{sanitize_for_logging(str(e))}

🛠️ **Troubleshooting Steps:**
1. **Check Connection**: Verify SAP system connectivity
2. **Object Exists**: Confirm {sanitize_for_logging(object_name)} exists in the system
3. **Permissions**: Ensure you have read access to the object
4. **Object Type**: Verify {sanitize_for_logging(object_type)} is the correct type
5. **System Load**: SAP system may be under heavy load

💡 **Alternative Actions:**
- Try accessing the object through SAP GUI (SE80/SE24/SE38)
- Check if the object is locked by another user
- Verify the object is in an active state
- Contact your SAP administrator if the issue persists"""
            
            return {
                "content": [
                    {
                        "type": "text",
                        "text": error_message
                    }
                ]
            }
    
    async def handle_update_source(self, args: Dict[str, Any]) -> str:
        """Handle update source request"""
        try:
            object_name = args['object_name']
            object_type = args['object_type']
            
            logger.info(f"Updating source for {sanitize_for_logging(object_name)} ({sanitize_for_logging(object_type)})")
            
            rap_logger.object_creation(
                sanitize_for_logging(object_name),
                sanitize_for_logging(object_type),
                'unknown',
                'SOURCE_UPDATE_REQUEST',
                {
                    'has_methods': bool(args.get('methods')),
                    'has_source_code': bool(args.get('source_code')),
                    'add_interface': args.get('add_interface')
                }
            )
            
            # Handle different update types
            if object_type == 'CLAS':
                if args.get('methods'):
                    # Method-based update
                    methods = [
                        MethodDefinition(
                            name=method_data['name'],
                            visibility=method_data['visibility'],
                            implementation=method_data['implementation']
                        )
                        for method_data in args['methods']
                    ]
                    result = await self.sap_client.class_handler.update_class_methods(object_name, methods)
                elif args.get('add_interface'):
                    # Interface addition
                    result = await self.sap_client.class_handler.add_interface_to_class(
                        object_name, args['add_interface']
                    )
                elif args.get('source_code'):
                    # Standard source update
                    result = await self.sap_client.update_source_with_syntax_check(
                        object_name, object_type, args['source_code']
                    )
                else:
                    return "Error: Must provide source_code, methods, or add_interface for class updates"
            else:
                # Standard source update for non-class objects
                if not args.get('source_code'):
                    return "Error: source_code is required for non-class objects"
                result = await self.sap_client.update_source_with_syntax_check(
                    object_name, object_type, args['source_code']
                )
            
            return self._format_object_operation_result(object_name, result, is_creation=False)
            
        except Exception as e:
            logger.error(f"Error updating source: {sanitize_for_logging(str(e))}")
            return f"Error updating source: {sanitize_for_logging(str(e))}"
    
    async def handle_check_syntax(self, object_name: str, object_type: str, 
                                 source_code: Optional[str] = None) -> str:
        """Handle syntax check request"""
        try:
            logger.info(f"Checking syntax for {sanitize_for_logging(object_name)} ({sanitize_for_logging(object_type)})")
            
            # Ensure we're connected to SAP
            if not await self._ensure_connected():
                return f"❌ Failed to connect to SAP system. Please check your configuration and network connectivity."
            
            result = await self.sap_client.check_syntax(object_name, object_type, source_code)
            
            message = f"Syntax Check Results for '{object_name}' ({object_type}):\n\n"
            
            if result.success:
                message += "✅ Syntax check passed - No errors found!\n"
                if result.warnings:
                    message += f"\n⚠️ Warnings ({len(result.warnings)}):\n"
                    for warning in result.warnings:
                        line_info = f" (Line {warning.line})" if warning.line and warning.line > 0 else ""
                        message += f"  • {warning.message}{line_info}\n"
            else:
                message += f"❌ Syntax check failed with {len(result.errors)} error(s)\n"
                
                if result.errors:
                    message += f"\n❌ Errors ({len(result.errors)}):\n"
                    for error in result.errors:
                        line_info = f" (Line {error.line})" if error.line and error.line > 0 else ""
                        message += f"  • {error.message}{line_info}\n"
                
                if result.warnings:
                    message += f"\n⚠️ Warnings ({len(result.warnings)}):\n"
                    for warning in result.warnings:
                        line_info = f" (Line {warning.line})" if warning.line and warning.line > 0 else ""
                        message += f"  • {warning.message}{line_info}\n"
                
                message += "\n💡 Suggestions:\n"
                message += "  • Fix the errors listed above\n"
                message += "  • Ensure all referenced types and objects exist\n"
                message += "  • Check for typos in variable/type names\n"
            
            return message
            
        except Exception as e:
            logger.error(f"Error checking syntax: {sanitize_for_logging(str(e))}")
            return f"Error checking syntax: {sanitize_for_logging(str(e))}"
    
    async def handle_activate_object(self, args: Dict[str, Any]) -> str:
        """Handle activate object request"""
        try:
            # Ensure we're connected to SAP
            if not await self._ensure_connected():
                return f"❌ Failed to connect to SAP system. Please check your configuration and network connectivity."
            
            # Support both single object and batch activation
            objects_to_activate = []
            
            if args.get('objects'):
                objects_to_activate = args['objects']
            elif args.get('object_name') and args.get('object_type'):
                objects_to_activate = [{
                    'object_name': args['object_name'],
                    'object_type': args['object_type']
                }]
            
            if not objects_to_activate:
                return "Error: No objects specified for activation"
            
            results = []
            for obj in objects_to_activate:
                object_name = obj['object_name']
                object_type = obj['object_type']
                
                logger.info(f"Activating {sanitize_for_logging(object_name)} ({sanitize_for_logging(object_type)})")
                
                result = await self.sap_client.activate_object(object_name, object_type)
                results.append((object_name, object_type, result))
            
            # Format results
            if len(results) == 1:
                object_name, object_type, result = results[0]
                message = f"Activation Results for '{object_name}' ({object_type}):\n\n"
                
                if result.success and result.activated:
                    message += "✅ Object activated successfully\n"
                elif result.activated and not result.success:
                    message += "⚠️ Object activation completed with issues\n"
                else:
                    message += "❌ Activation failed - object was NOT activated\n"
                    if not result.activated:
                        message += "   (Activation was cancelled due to errors)\n"
                
                if result.errors:
                    message += f"\n❌ Errors ({len(result.errors)}):\n"
                    for error in result.errors:
                        line_info = f" (Line {error.line})" if error.line and error.line > 0 else ""
                        message += f"  • {error.message}{line_info}\n"
                
                if result.warnings:
                    message += f"\n⚠️ Warnings ({len(result.warnings)}):\n"
                    for warning in result.warnings:
                        line_info = f" (Line {warning.line})" if warning.line and warning.line > 0 else ""
                        message += f"  • {warning.message}{line_info}\n"
                
                # Add helpful suggestions if activation failed
                if not result.success:
                    message += "\n💡 Suggestions:\n"
                    message += "  • Fix the errors listed above and try again\n"
                    message += "  • Use syntax check to validate code before activation\n"
                    message += "  • Ensure all referenced types and objects exist\n"
                
                return message
            else:
                # Batch activation results
                success_count = sum(1 for _, _, r in results if r.success)
                failed_count = len(results) - success_count
                
                message = f"Batch Activation Results ({len(results)} objects):\n\n"
                message += f"📊 Summary: {success_count} succeeded, {failed_count} failed\n\n"
                
                for object_name, object_type, result in results:
                    if result.success:
                        message += f"✅ {object_name} ({object_type}): Activated\n"
                    else:
                        message += f"❌ {object_name} ({object_type}): Failed\n"
                        if result.errors:
                            for error in result.errors[:2]:  # Show first 2 errors per object
                                message += f"   • {error.message}\n"
                            if len(result.errors) > 2:
                                message += f"   ... and {len(result.errors) - 2} more errors\n"
                
                return message
            
        except Exception as e:
            logger.error(f"Error activating object: {sanitize_for_logging(str(e))}")
            return f"Error activating object: {sanitize_for_logging(str(e))}"

    async def handle_activate_objects_batch(self, args: Dict[str, Any]) -> str:
        """Handle batch activation request for objects with circular dependencies"""
        try:
            # Ensure we're connected to SAP
            if not await self._ensure_connected():
                return f"❌ Failed to connect to SAP system. Please check your configuration and network connectivity."
            
            objects = args.get('objects', [])
            if not objects:
                return "Error: No objects specified for batch activation"
            
            # Validate object format
            for obj in objects:
                if not isinstance(obj, dict) or 'name' not in obj or 'type' not in obj:
                    return "Error: Each object must have 'name' and 'type' fields"
            
            object_names = [obj['name'] for obj in objects]
            logger.info(f"Batch activating {len(objects)} objects: {sanitize_for_logging(', '.join(object_names))}")
            
            # Use batch activation to handle circular dependencies
            result = await self.sap_client.activate_objects_batch(objects)
            
            # Format results
            message = f"Batch Activation Results ({len(objects)} objects):\n"
            message += f"Objects: {', '.join(object_names)}\n\n"
            
            if result.success and result.activated:
                message += "✅ All objects activated successfully in batch\n"
                message += "   (Circular dependencies resolved automatically)\n"
            elif result.activated and not result.success:
                message += "⚠️ Batch activation completed with issues\n"
            else:
                message += "❌ Batch activation failed - objects were NOT activated\n"
                if not result.activated:
                    message += "   (Activation was cancelled due to errors)\n"
            
            if result.errors:
                message += f"\n❌ Errors ({len(result.errors)}):\n"
                for error in result.errors:
                    line_info = f" (Line {error.line})" if error.line and error.line > 0 else ""
                    message += f"  • {error.message}{line_info}\n"
            
            if result.warnings:
                message += f"\n⚠️ Warnings ({len(result.warnings)}):\n"
                for warning in result.warnings:
                    line_info = f" (Line {warning.line})" if warning.line and warning.line > 0 else ""
                    message += f"  • {warning.message}{line_info}\n"
            
            # Add helpful information about batch activation
            if result.success:
                message += "\n💡 Batch activation benefits:\n"
                message += "  • Resolves circular dependencies automatically\n"
                message += "  • Activates all objects together in correct order\n"
                message += "  • More efficient than individual activations\n"
            else:
                message += "\n💡 Suggestions:\n"
                message += "  • Fix the errors listed above and try again\n"
                message += "  • Use syntax check on individual objects first\n"
                message += "  • Ensure all referenced objects exist\n"
                message += "  • Consider activating dependencies first\n"
            
            return message
            
        except Exception as e:
            logger.error(f"Error in batch activation: {sanitize_for_logging(str(e))}")
            return f"Error in batch activation: {sanitize_for_logging(str(e))}"
    
    async def handle_run_atc_check(self, args: ATCCheckArgs, summary_mode: bool = False) -> str:
        """Handle ATC check request"""
        try:
            target_desc = args.object_name or args.package_name or args.transport_number or 'unknown'
            logger.info(f"Running ATC check for {sanitize_for_logging(target_desc)}")
            
            # Ensure we're connected to SAP
            if not await self._ensure_connected():
                return f"❌ Failed to connect to SAP system. Please check your configuration and network connectivity."
            
            results = await self.sap_client.run_atc_check(args)
            
            if not results:
                return f"ATC check completed for {target_desc} - No issues found! ✅"
            
            # Format results with truncation to avoid MCP 100K character limit
            return self._format_atc_results(target_desc, results)
            
        except Exception as e:
            logger.error(f"Error running ATC check: {sanitize_for_logging(str(e))}")
            return f"Error running ATC check: {sanitize_for_logging(str(e))}"
    
    async def handle_run_unit_tests(self, object_name: str, object_type: str, 
                                   with_coverage: bool = False) -> str:
        """Handle unit test request"""
        try:
            logger.info(f"Running unit tests for {sanitize_for_logging(object_name)}")
            
            results = await self.sap_client.run_unit_tests(object_name, object_type, with_coverage)
            
            if not results:
                return (f"No unit tests found for {object_name}.\n\n"
                       "This could mean:\n"
                       "- No test class exists\n"
                       "- Test class has no test methods\n"
                       "- Object is not testable")
            
            # Format results
            message = f"Unit Test Results for '{object_name}':\n\n"
            
            passed = sum(1 for r in results if r.status == 'SUCCESS')
            failed = sum(1 for r in results if r.status == 'FAILURE')
            errors = sum(1 for r in results if r.status == 'ERROR')
            
            message += f"Summary: {passed} passed, {failed} failed, {errors} errors\n\n"
            
            for result in results:
                status_icon = "✅" if result.status == 'SUCCESS' else "❌"
                message += f"{status_icon} {result.test_class}.{result.test_method}: {result.status}"
                if result.message:
                    message += f" - {result.message}"
                if result.duration:
                    message += f" ({result.duration:.2f}s)"
                message += "\n"
            
            return message
            
        except Exception as e:
            logger.error(f"Error running unit tests: {sanitize_for_logging(str(e))}")
            return f"Error running unit tests: {sanitize_for_logging(str(e))}"
    
    async def handle_create_or_update_test_class(self, class_name: str, 
                                                methods: List[Dict[str, Any]]) -> str:
        """Handle create or update test class request"""
        try:
            logger.info(f"Creating/updating test class for {sanitize_for_logging(class_name)}")
            logger.info(f"Received {len(methods)} methods with data: {sanitize_for_logging(str(methods))}")
            
            # Convert method data to MethodDefinition objects
            method_definitions = []
            for method_data in methods:
                # Try both 'implementation' and 'test_logic' keys for backward compatibility
                impl = method_data.get('implementation') or method_data.get('test_logic', '')
                logger.info(f"Method {method_data['name']}: implementation={'<provided>' if impl else '<empty>'}, length={len(impl) if impl else 0}")
                
                method_definitions.append(MethodDefinition(
                    name=method_data['name'],
                    visibility='PUBLIC',
                    is_for_testing=True,
                    implementation=impl
                ))
            
            result = await self.sap_client.class_handler.create_test_class(class_name, method_definitions)
            
            return self._format_object_operation_result(f"{class_name}_TEST", result, is_creation=True)
            
        except Exception as e:
            logger.error(f"Error creating/updating test class: {sanitize_for_logging(str(e))}")
            return f"Error creating/updating test class: {sanitize_for_logging(str(e))}"
    
    async def handle_get_test_classes(self, class_name: str, object_type: str) -> str:
        """Handle get test classes request"""
        try:
            logger.info(f"Getting test classes for {sanitize_for_logging(class_name)}")
            
            # Ensure we're connected to SAP
            if not await self._ensure_connected():
                return f"❌ Failed to connect to SAP system. Please check your configuration and network connectivity."
            
            # Use the SAP client's get_test_classes method
            test_class_source = await self.sap_client.get_test_classes(class_name, object_type)
            
            if test_class_source:
                return f"Test class source code for {class_name}:\n\n```abap\n{test_class_source}\n```"
            else:
                return f"No test classes found for {class_name}. You can create one using the create_or_update_test_class tool."
            
        except Exception as e:
            logger.error(f"Error getting test classes: {sanitize_for_logging(str(e))}")
            return f"Error getting test classes: {sanitize_for_logging(str(e))}"
    
    async def handle_search_object(self, args: Dict[str, Any]) -> str:
        """Handle search object request"""
        try:
            from sap_types.sap_types import SearchOptions
            
            # Extract parameters
            query = args['query']
            object_type = args.get('object_type')
            package_name = args.get('package_name')
            max_results = args.get('max_results', 50)
            include_inactive = args.get('include_inactive', False)
            
            logger.info(f"Searching objects with query: {sanitize_for_logging(query)}")
            
            # Ensure SAP client is connected
            if not self.sap_client.session:
                logger.info("SAP client not connected, attempting to connect...")
                connected = await self.sap_client.connect()
                if not connected:
                    logger.error("Failed to connect to SAP system")
                    return "❌ Failed to connect to SAP system"
            
            # Create search options
            search_options = SearchOptions(
                query=query,
                object_type=object_type,
                package_name=package_name,
                max_results=max_results
            )
            
            # Execute search
            results = await self.sap_client.search_objects(search_options)
            
            if not results:
                return f"🔍 No objects found for query: '{query}'"
            
            # Format results
            response_lines = [f"🔍 Found {len(results)} objects for query: '{query}'", ""]
            
            for i, result in enumerate(results[:max_results], 1):
                response_lines.append(f"{i}. **{result.name}** ({result.type})")
                if result.description:
                    response_lines.append(f"   📝 {result.description}")
                if result.package_name:
                    response_lines.append(f"   📦 Package: {result.package_name}")
                if result.uri:
                    response_lines.append(f"   🔗 URI: {result.uri}")
                response_lines.append("")  # Empty line for spacing
            
            if len(results) > max_results:
                response_lines.append(f"... and {len(results) - max_results} more results")
            
            return "\n".join(response_lines)
            
        except Exception as e:
            logger.error(f"Error searching objects: {sanitize_for_logging(str(e))}")
            return f"❌ Error searching objects: {sanitize_for_logging(str(e))}"
    
    async def handle_get_migration_analysis(self, object_name: str, object_type: str) -> str:
        """Handle get migration analysis request"""
        try:
            logger.info(f"Getting migration analysis for {sanitize_for_logging(object_name)} ({sanitize_for_logging(object_type)})")
            
            # Ensure we're connected to SAP
            if not await self._ensure_connected():
                return f"❌ Failed to connect to SAP system. Please check your configuration and network connectivity."
            
            # Get migration analysis from SAP client
            analysis = await self.sap_client.get_migration_analysis(object_name, object_type)
            
            if not analysis:
                return f"No migration analysis available for {sanitize_for_logging(object_name)} ({sanitize_for_logging(object_type)})"
            
            # Format analysis results
            message = f"Migration Analysis for '{object_name}' ({object_type}):\n\n"
            
            if analysis.get('compatibility_issues'):
                message += f"🔍 Compatibility Issues ({len(analysis['compatibility_issues'])}):\n"
                for issue in analysis['compatibility_issues']:
                    severity_icon = "❌" if issue.get('severity') == 'ERROR' else "⚠️" if issue.get('severity') == 'WARNING' else "ℹ️"
                    message += f"  {severity_icon} {issue.get('message', 'No message')}\n"
                    if issue.get('line'):
                        message += f"     Line: {issue['line']}\n"
                message += "\n"
            
            if analysis.get('migration_recommendations'):
                message += f"💡 Migration Recommendations:\n"
                for rec in analysis['migration_recommendations']:
                    message += f"  • {rec}\n"
                message += "\n"
            
            if analysis.get('effort_estimate'):
                message += f"📊 Effort Estimate: {analysis['effort_estimate']}\n\n"
            
            if analysis.get('dependencies'):
                message += f"🔗 Dependencies ({len(analysis['dependencies'])}):\n"
                for dep in analysis['dependencies']:
                    message += f"  • {dep}\n"
                message += "\n"
            
            return message
            
        except Exception as e:
            logger.error(f"Error getting migration analysis: {sanitize_for_logging(str(e))}")
            return f"Error getting migration analysis: {sanitize_for_logging(str(e))}"
    
    def _format_object_operation_result(self, object_name: str, result, is_creation: bool = True) -> str:
        """Format object operation result for display"""
        try:
            operation = "Creation" if is_creation else "Update"
            message = f"Object {operation} Results for '{object_name}':\n\n"
            
            # Safety check for None result
            if result is None:
                message += f"❌ Object {operation.lower()} failed - No result returned\n"
                return message
            
            # Check if result has the expected attributes
            if not hasattr(result, 'errors'):
                logger.error("Result object missing 'errors' attribute")
                message += f"❌ Object {operation.lower()} failed - Invalid result object\n"
                return message
                
            if not hasattr(result, 'warnings'):
                logger.error("Result object missing 'warnings' attribute")
                message += f"❌ Object {operation.lower()} failed - Invalid result object\n"
                return message
            
            # Check if errors and warnings are None
            if result.errors is None:
                logger.error("result.errors is None")
                message += f"❌ Object {operation.lower()} failed - Errors list is None\n"
                return message
                
            if result.warnings is None:
                logger.error("result.warnings is None")
                message += f"❌ Object {operation.lower()} failed - Warnings list is None\n"
                return message
            if result.created or result.updated:
                message += f"✅ Object {'created' if is_creation else 'updated'} successfully\n"
                
                if result.syntax_check_passed:
                    message += "✅ Syntax check passed\n"
                    
                    if result.activated:
                        message += "✅ Object activated successfully\n"
                    else:
                        message += "❌ Activation failed\n"
                else:
                    message += "❌ Syntax check failed\n"
                
                if result.errors:
                    message += f"\nErrors ({validate_numeric_input(len(result.errors), 'errors')}):\n"
                    message += "\n".join([
                        f"Line {error.line}: {error.message}"
                        for error in result.errors
                    ])
                
                if result.warnings:
                    message += f"\nWarnings ({validate_numeric_input(len(result.warnings), 'warnings')}):\n"
                    message += "\n".join([
                        f"Line {warning.line}: {warning.message}"
                        for warning in result.warnings
                    ])
            else:
                message += f"❌ Object {'creation' if is_creation else 'update'} failed\n"
                if result.errors:
                    message += f"\nErrors:\n"
                    message += "\n".join([error.message for error in result.errors])
            
            return message
            
        except Exception as e:
            logger.error(f"Error in _format_object_operation_result: {e}")
            import traceback
            traceback.print_exc()
            return f"❌ Object {operation if 'operation' in locals() else 'operation'} failed - Error formatting result: {str(e)}"
    

    

    

    
    def _format_atc_results(self, target_desc: str, results: List) -> str:
        """Format ATC results with intelligent truncation for MCP"""
        MAX_OUTPUT_SIZE = 70000  # Very conservative limit for FastMCP + JSON overhead
        
        # If we have an extremely large number of findings, use summary mode
        if len(results) > 200:  # More aggressive threshold for FastMCP
            return self._format_atc_results_summary_mode(target_desc, results)
        
        # Count findings by severity
        error_count = sum(1 for r in results if r.severity.value == 'ERROR')
        warning_count = sum(1 for r in results if r.severity.value == 'WARNING')
        info_count = sum(1 for r in results if r.severity.value == 'INFO')
        
        # Build header with enhanced summary
        header = f"🔍 ATC Check Results for {target_desc}\n\n"
        header += f"📊 Summary:\n"
        header += f"   • Total findings: {len(results)}\n"
        header += f"   • Errors: {error_count} ❌\n"
        header += f"   • Warnings: {warning_count} ⚠️\n"
        header += f"   • Info: {info_count} ℹ️\n\n"
        
        # Add check type breakdown for better insight
        check_types = {}
        for result in results:
            check_title = result.check_title or 'Unknown Check'
            check_types[check_title] = check_types.get(check_title, 0) + 1
        
        if check_types:
            header += f"🔍 Top Check Types:\n"
            # Show top 5 most common check types
            sorted_checks = sorted(check_types.items(), key=lambda x: x[1], reverse=True)[:5]
            for check_name, count in sorted_checks:
                header += f"   • {check_name}: {count} findings\n"
            header += "\n"
        
        # Prioritize findings: Errors first, then warnings, then info
        sorted_results = sorted(results, key=lambda x: (
            0 if x.severity.value == 'ERROR' else 
            1 if x.severity.value == 'WARNING' else 2,
            x.line or 0
        ))
        
        findings_section = "📋 Detailed Findings:\n\n"
        current_size = len(header) + len(findings_section)
        
        findings_shown = 0
        findings_truncated = 0
        
        # More aggressive limits for large result sets to avoid FastMCP issues
        max_findings_to_show = min(30, len(results))  # Cap at 30 findings max
        if len(results) > 50:
            max_findings_to_show = min(15, len(results))  # Even more aggressive for large sets
        
        for i, result in enumerate(sorted_results, 1):
            if findings_shown >= max_findings_to_show:
                findings_truncated = len(sorted_results) - findings_shown
                break
                
            # Format finding more concisely
            severity_icon = {
                'ERROR': '❌',
                'WARNING': '⚠️', 
                'INFO': 'ℹ️'
            }.get(result.severity.value, '•')
            
            # Truncate long messages
            message = result.message or 'No message'
            if len(message) > 120:
                message = message[:117] + "..."
            
            finding_text = f"{i}. {severity_icon} {message}"
            
            if result.line:
                finding_text += f" (Line {result.line})"
            
            if result.check_id:
                finding_text += f" [{result.check_id[:12]}...]" if len(result.check_id) > 15 else f" [{result.check_id}]"
            
            # Only add documentation for errors and first few warnings
            if result.documentation and (result.severity.value == 'ERROR' or findings_shown < 10):
                # Extract first meaningful sentence from HTML documentation
                import re
                doc_text = re.sub(r'<[^>]+>', '', result.documentation)  # Remove HTML tags
                doc_text = re.sub(r'\s+', ' ', doc_text).strip()  # Normalize whitespace
                if len(doc_text) > 80:
                    doc_text = doc_text[:77] + "..."
                if doc_text:
                    finding_text += f"\n   📖 {doc_text}"
            
            finding_text += "\n\n"
            
            # Check if adding this finding would exceed the limit
            if current_size + len(finding_text) > MAX_OUTPUT_SIZE - 3000:  # Reserve even more space for footer and JSON overhead
                findings_truncated = len(sorted_results) - findings_shown
                break
            
            findings_section += finding_text
            current_size += len(finding_text)
            findings_shown += 1
        
        # Build footer with enhanced truncation info
        footer = ""
        if findings_truncated > 0:
            footer += f"⚠️ Output truncated: Showing {findings_shown} of {len(results)} findings\n"
            footer += f"   ({findings_truncated} additional findings not shown due to MCP size limit)\n\n"
            
            # Show summary of truncated findings by severity
            remaining_results = sorted_results[findings_shown:]
            remaining_errors = sum(1 for r in remaining_results if r.severity.value == 'ERROR')
            remaining_warnings = sum(1 for r in remaining_results if r.severity.value == 'WARNING')
            remaining_info = sum(1 for r in remaining_results if r.severity.value == 'INFO')
            
            if remaining_errors > 0 or remaining_warnings > 0 or remaining_info > 0:
                footer += f"📊 Hidden findings breakdown:\n"
                if remaining_errors > 0:
                    footer += f"   • {remaining_errors} additional errors ❌\n"
                if remaining_warnings > 0:
                    footer += f"   • {remaining_warnings} additional warnings ⚠️\n"
                if remaining_info > 0:
                    footer += f"   • {remaining_info} additional info messages ℹ️\n"
                footer += "\n"
                
            # Show most common check types in hidden findings
            hidden_check_types = {}
            for result in remaining_results:
                check_title = result.check_title or 'Unknown Check'
                hidden_check_types[check_title] = hidden_check_types.get(check_title, 0) + 1
            
            if hidden_check_types:
                footer += f"🔍 Most common hidden check types:\n"
                sorted_hidden = sorted(hidden_check_types.items(), key=lambda x: x[1], reverse=True)[:3]
                for check_name, count in sorted_hidden:
                    short_name = check_name[:50] + "..." if len(check_name) > 50 else check_name
                    footer += f"   • {short_name}: {count} findings\n"
                footer += "\n"
        
        footer += "💡 Recommendations:\n"
        if error_count > 0:
            footer += "   • Fix errors first (❌) - these are critical issues\n"
        if warning_count > 0:
            footer += "   • Address warnings (⚠️) - these may cause problems\n"
        if findings_truncated > 0:
            footer += "   • Run ATC check with smaller scope for complete results\n"
            footer += "   • Focus on specific objects or use filters\n"
        footer += "   • Use SAP ADT or SE80 for full detailed analysis\n"
        
        # Ensure we don't exceed the limit even with footer
        result_text = header + findings_section + footer
        if len(result_text) > MAX_OUTPUT_SIZE:
            # Emergency truncation - cut findings section
            available_space = MAX_OUTPUT_SIZE - len(header) - len(footer) - 500
            if available_space > 0:
                findings_section = findings_section[:available_space] + "\n\n[EMERGENCY TRUNCATION - Output too large]\n\n"
            else:
                findings_section = "[OUTPUT TOO LARGE - Please use smaller scope]\n\n"
            result_text = header + findings_section + footer
        
        return result_text
    
    def _format_atc_results_summary_mode(self, target_desc: str, results: List) -> str:
        """Format ATC results in summary mode for very large result sets"""
        # Count findings by severity
        error_count = sum(1 for r in results if r.severity.value == 'ERROR')
        warning_count = sum(1 for r in results if r.severity.value == 'WARNING')
        info_count = sum(1 for r in results if r.severity.value == 'INFO')
        
        # Build comprehensive summary
        summary = f"🔍 ATC Check Results for {target_desc} (Summary Mode)\n\n"
        summary += f"📊 Overall Summary:\n"
        summary += f"   • Total findings: {len(results)} (Large result set - showing summary)\n"
        summary += f"   • Errors: {error_count} ❌\n"
        summary += f"   • Warnings: {warning_count} ⚠️\n"
        summary += f"   • Info: {info_count} ℹ️\n\n"
        
        # Check type breakdown
        check_types = {}
        for result in results:
            check_title = result.check_title or 'Unknown Check'
            check_types[check_title] = check_types.get(check_title, 0) + 1
        
        if check_types:
            summary += f"🔍 Check Types Breakdown:\n"
            sorted_checks = sorted(check_types.items(), key=lambda x: x[1], reverse=True)
            for i, (check_name, count) in enumerate(sorted_checks[:10], 1):
                short_name = check_name[:60] + "..." if len(check_name) > 60 else check_name
                summary += f"   {i:2d}. {short_name}: {count} findings\n"
            if len(sorted_checks) > 10:
                summary += f"   ... and {len(sorted_checks) - 10} more check types\n"
            summary += "\n"
        
        # Show top errors (most critical)
        errors = [r for r in results if r.severity.value == 'ERROR']
        if errors:
            summary += f"❌ Top Critical Errors (showing first 10 of {len(errors)}):\n"
            for i, error in enumerate(errors[:10], 1):
                message = error.message or 'No message'
                if len(message) > 80:
                    message = message[:77] + "..."
                line_info = f" (Line {error.line})" if error.line else ""
                summary += f"   {i:2d}. {message}{line_info}\n"
            if len(errors) > 10:
                summary += f"   ... and {len(errors) - 10} more errors\n"
            summary += "\n"
        
        # Show sample warnings
        warnings = [r for r in results if r.severity.value == 'WARNING']
        if warnings:
            summary += f"⚠️ Sample Warnings (showing first 5 of {len(warnings)}):\n"
            for i, warning in enumerate(warnings[:5], 1):
                message = warning.message or 'No message'
                if len(message) > 80:
                    message = message[:77] + "..."
                line_info = f" (Line {warning.line})" if warning.line else ""
                summary += f"   {i}. {message}{line_info}\n"
            if len(warnings) > 5:
                summary += f"   ... and {len(warnings) - 5} more warnings\n"
            summary += "\n"
        
        # Recommendations
        summary += "💡 Recommendations for Large Result Sets:\n"
        summary += "   • Focus on fixing errors first (❌) - these are critical\n"
        summary += "   • Run ATC check on smaller scopes (individual objects/classes)\n"
        summary += "   • Use filters in SAP ADT to focus on specific check types\n"
        summary += "   • Consider running checks incrementally during development\n"
        summary += "   • Use SAP ADT or SE80 for complete detailed analysis\n\n"
        
        summary += f"📋 To get detailed findings, try:\n"
        summary += f"   • Run ATC on specific objects instead of entire package\n"
        summary += f"   • Use include_subpackages=false for package checks\n"
        summary += f"   • Filter by specific check variants or priorities\n"
        
        # Final size check for FastMCP compatibility
        if len(summary) > 70000:
            logger.warning(f"ATC summary mode result still large: {len(summary)} chars, truncating")
            summary = summary[:65000] + "\n\n⚠️ Summary truncated due to size limits. Use more specific ATC scope."
        
        logger.info(f"ATC summary mode result size: {len(summary)} chars")
        return summary
    async def handle_get_transport_requests(self, username: Optional[str] = None) -> str:
        """Handle get transport requests request"""
        try:
            logger.info(f"Getting transport requests{f' for user {sanitize_for_logging(username)}' if username else ''}")
            
            # Ensure we're connected to SAP
            if not await self._ensure_connected():
                return f"❌ Failed to connect to SAP system. Please check your configuration and network connectivity."
            
            # Determine which user to query for
            query_user = username
            if not query_user:
                # Get current user info from SAP connection
                user_info = await self.sap_client.get_current_user_info()
                query_user = user_info.get('sap_user_id') if user_info else self.sap_client.connection.username
                logger.info(f"Using SAP user: {sanitize_for_logging(query_user)}")
            
            # Ensure user is uppercase (SAP standard)
            query_user = query_user.upper() if query_user else None
            logger.info(f"Final query user (uppercase): {sanitize_for_logging(query_user)}")
            
            if not query_user:
                return f"❌ Could not determine SAP user for transport request query"
            
            # Step 1: Get user's transport requests list
            transport_list_url = f"/sap/bc/adt/cts/transports"
            params = {
                'user': query_user,
                'trfunction': '*',  # All transport types
                '_action': 'FIND'
            }
            
            headers = await self.sap_client._get_appropriate_headers()
            headers['Accept'] = 'application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.CorrectionRequests'
            
            logger.info(f"Getting transport list for user {sanitize_for_logging(query_user)}")
            logger.info(f"Transport list URL: {sanitize_for_logging(transport_list_url)}")
            logger.info(f"Transport list params: {sanitize_for_logging(params)}")
            logger.info(f"Transport list headers Accept: {sanitize_for_logging(headers.get('Accept'))}")
            
            transport_numbers = []
            async with self.sap_client.session.get(
                self.sap_client.add_client_param(transport_list_url), 
                params=params, 
                headers=headers
            ) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    logger.info(f"Transport list response length: {len(xml_content)}")
                    
                    # Debug: Log the actual response content if it's short
                    if len(xml_content) < 500:
                        logger.info(f"Transport list response content: {sanitize_for_logging(xml_content)}")
                    else:
                        logger.info(f"Transport list response content (first 500 chars): {sanitize_for_logging(xml_content[:500])}")
                    
                    # Handle empty response
                    if len(xml_content.strip()) == 0:
                        logger.info(f"Empty response from transport list endpoint for user {sanitize_for_logging(query_user)}")
                        return f"No transport requests found for user {sanitize_for_logging(query_user)} (empty response from SAP)"
                    
                    # Parse transport numbers from the response
                    from utils.xml_utils import safe_parse_xml
                    root = safe_parse_xml(xml_content)
                    if root is not None:
                        # Look for transport request headers and extract more details
                        for elem in root.iter():
                            if elem.tag.endswith('CTS_REQ_HEADER'):
                                trkorr_elem = elem.find('TRKORR')
                                if trkorr_elem is not None and trkorr_elem.text:
                                    transport_number = trkorr_elem.text.strip()
                                    
                                    # Avoid duplicates
                                    if transport_number not in transport_numbers:
                                        transport_numbers.append(transport_number)
                                        
                                        # Extract additional details from the header
                                        as4text_elem = elem.find('AS4TEXT')
                                        as4date_elem = elem.find('AS4DATE')
                                        as4time_elem = elem.find('AS4TIME')
                                        trstatus_elem = elem.find('TRSTATUS')
                                        trfunction_elem = elem.find('TRFUNCTION')
                                        
                                        description = as4text_elem.text if as4text_elem is not None else ''
                                        date = as4date_elem.text if as4date_elem is not None else ''
                                        time = as4time_elem.text if as4time_elem is not None else ''
                                        status = trstatus_elem.text if trstatus_elem is not None else ''
                                        tr_type = trfunction_elem.text if trfunction_elem is not None else ''
                                        
                                        logger.info(f"Found transport: {sanitize_for_logging(transport_number)} - {sanitize_for_logging(description)} (Status: {status})")
                    else:
                        logger.warning(f"Failed to parse XML response for transport list")
                        # Try to extract any useful information from the raw response
                        if 'TRKORR' in xml_content:
                            logger.info("Response contains TRKORR but XML parsing failed - trying alternative parsing")
                            # Simple regex fallback for transport numbers
                            import re
                            transport_matches = re.findall(r'<TRKORR>([^<]+)</TRKORR>', xml_content)
                            for match in transport_matches:
                                if match.strip() and match.strip() not in transport_numbers:
                                    transport_numbers.append(match.strip())
                                    logger.info(f"Found transport via regex: {sanitize_for_logging(match.strip())}")
                    
                    if not transport_numbers:
                        logger.info(f"No transports found with user-specific query, trying broader transport organizer endpoint")
                        
                        # Fallback: Try the broader transport organizer endpoint
                        fallback_url = f"/sap/bc/adt/cts/transportrequests"
                        fallback_params = {
                            'targets': 'true'
                        }
                        
                        logger.info(f"Trying fallback URL: {sanitize_for_logging(fallback_url)}")
                        logger.info(f"Fallback params: {sanitize_for_logging(fallback_params)}")
                        
                        fallback_headers = await self.sap_client._get_appropriate_headers()
                        fallback_headers['Accept'] = 'application/vnd.sap.adt.transportorganizertree.v1+xml'
                        
                        async with self.sap_client.session.get(
                            self.sap_client.add_client_param(fallback_url),
                            params=fallback_params,
                            headers=fallback_headers
                        ) as fallback_response:
                            if fallback_response.status == 200:
                                fallback_xml = await fallback_response.text()
                                logger.info(f"Fallback response length: {len(fallback_xml)}")
                                
                                if len(fallback_xml.strip()) > 0:
                                    fallback_root = safe_parse_xml(fallback_xml)
                                    if fallback_root is not None:
                                        # Look for transport requests owned by our user
                                        for elem in fallback_root.iter():
                                            # Look for request elements with owner matching our user
                                            elem_owner = self._get_attr_with_namespace(elem, 'owner')
                                            elem_number = self._get_attr_with_namespace(elem, 'number')
                                            if ('request' in elem.tag.lower() and 
                                                elem_owner == query_user and 
                                                elem_number):
                                                transport_number = elem_number
                                                if transport_number:
                                                    transport_numbers.append(transport_number)
                                                    logger.info(f"Found transport via fallback: {sanitize_for_logging(transport_number)}")
                            else:
                                logger.warning(f"Fallback endpoint also failed: {fallback_response.status}")
                        
                        if not transport_numbers:
                            return f"No transport requests found for user {sanitize_for_logging(query_user)} (tried both user-specific and general endpoints)"
                        
                else:
                    logger.error(f"Failed to get transport list: {response.status}")
                    response_text = await response.text()
                    logger.error(f"Response: {sanitize_for_logging(response_text[:500])}")
                    return f"❌ Failed to get transport requests list: HTTP {response.status}"
            
            # Step 2: Get detailed information using the exact same approach as your working ADT call
            logger.info(f"Getting detailed info for {len(transport_numbers)} transports")
            
            # Use the exact same endpoint and parameters as your working ADT call
            # GET /sap/bc/adt/cts/transportrequests?targets=true&configUri=%2Fsap%2Fbc%2Fadt%2Fcts%2Ftransportrequests%2Fsearchconfiguration%2Fconfigurations%2FE3EA780B64C31FD0B5A7444450EBC84A
            detail_url = f"/sap/bc/adt/cts/transportrequests"
            detail_params = {
                'targets': 'true',
                'configUri': '/sap/bc/adt/cts/transportrequests/searchconfiguration/configurations/E3EA780B64C31FD0B5A7444450EBC84A'
            }
            
            detail_headers = await self.sap_client._get_appropriate_headers()
            detail_headers['Accept'] = 'application/vnd.sap.adt.transportorganizer.v1+xml, application/vnd.sap.adt.transportorganizertree.v1+xml'
            
            logger.info(f"Getting transport organizer tree with config")
            logger.info(f"Detail URL: {sanitize_for_logging(detail_url)}")
            logger.info(f"Detail params: {sanitize_for_logging(detail_params)}")
            
            detailed_transports = []
            
            try:
                async with self.sap_client.session.get(
                    self.sap_client.add_client_param(detail_url), 
                    params=detail_params,
                    headers=detail_headers
                ) as detail_response:
                    if detail_response.status == 200:
                        detail_xml = await detail_response.text()
                        logger.info(f"Transport organizer tree response length: {len(detail_xml)}")
                        
                        # Debug: Log a sample of the response
                        if len(detail_xml) < 2000:
                            logger.info(f"Transport organizer XML: {sanitize_for_logging(detail_xml)}")
                        else:
                            logger.info(f"Transport organizer XML (first 1500 chars): {sanitize_for_logging(detail_xml[:1500])}")
                        
                        # Parse the transport organizer tree and extract details for our transports
                        for transport_number in transport_numbers:
                            transport_detail = self._parse_transport_detail_from_tree(detail_xml, transport_number)
                            if transport_detail:
                                detailed_transports.append(transport_detail)
                                logger.info(f"Successfully parsed details for transport {sanitize_for_logging(transport_number)}")
                            else:
                                logger.warning(f"Could not find transport {sanitize_for_logging(transport_number)} in organizer tree")
                                # Add basic info from the first step with data we already have
                                detailed_transports.append({
                                    'number': transport_number,
                                    'description': 'Basic info only (not in organizer tree)',
                                    'status': 'D',  # From first step
                                    'owner': query_user,
                                    'type': 'K',  # From first step
                                    'last_changed': '',
                                    'tasks': [],
                                    'objects': []
                                })
                    else:
                        logger.error(f"Failed to get transport organizer tree: {detail_response.status}")
                        detail_response_text = await detail_response.text()
                        logger.error(f"Transport organizer error: {sanitize_for_logging(detail_response_text[:500])}")
                        
                        # Fall back to basic info for all transports
                        for transport_number in transport_numbers:
                            detailed_transports.append({
                                'number': transport_number,
                                'description': 'Details not available (organizer tree error)',
                                'status': 'D',  # From first step
                                'owner': query_user,
                                'type': 'K',  # From first step
                                'last_changed': '',
                                'tasks': [],
                                'objects': []
                            })
                            
            except Exception as detail_error:
                logger.error(f"Error getting transport organizer tree: {sanitize_for_logging(str(detail_error))}")
                # Fall back to basic info for all transports
                for transport_number in transport_numbers:
                    detailed_transports.append({
                        'number': transport_number,
                        'description': 'Details not available (exception)',
                        'status': 'D',  # From first step
                        'owner': query_user,
                        'type': 'K',  # From first step
                        'last_changed': '',
                        'tasks': [],
                        'objects': []
                    })
            
            # Step 3: Format the response
            if not detailed_transports:
                return f"No detailed transport information available for user {sanitize_for_logging(query_user)}"
            
            # Format the results
            result = f"🚚 Transport Requests for User: {query_user}\n\n"
            result += f"📊 Summary: Found {len(detailed_transports)} transport request(s)\n\n"
            
            for i, transport in enumerate(detailed_transports, 1):
                result += f"{'='*60}\n"
                result += f"Transport #{i}: {transport['number']}\n"
                result += f"{'='*60}\n"
                result += f"📝 Description: {transport['description']}\n"
                result += f"👤 Owner: {transport['owner']}\n"
                result += f"📊 Status: {transport['status']}\n"
                result += f"📅 Type: {transport.get('type', 'Unknown')}\n"
                
                if transport.get('last_changed'):
                    result += f"🕒 Last Changed: {transport['last_changed']}\n"
                
                # Show tasks
                if transport['tasks']:
                    result += f"\n📋 Tasks ({len(transport['tasks'])}):\n"
                    for task in transport['tasks']:
                        result += f"  • {task['number']} - {task['description']} (Owner: {task['owner']}, Status: {task['status']})\n"
                        
                        # Show objects in task
                        if task.get('objects'):
                            result += f"    📦 Objects ({len(task['objects'])}):\n"
                            for obj in task['objects'][:10]:  # Limit to first 10 objects per task
                                result += f"      - {obj['name']} ({obj['type']}) - {obj.get('description', 'No description')}\n"
                            if len(task['objects']) > 10:
                                result += f"      ... and {len(task['objects']) - 10} more objects\n"
                else:
                    result += f"\n📋 Tasks: None found (may require different SAP authorization or transport may be empty)\n"
                
                # Show direct objects (if any)
                if transport['objects']:
                    result += f"\n📦 Direct Objects ({len(transport['objects'])}):\n"
                    for obj in transport['objects'][:10]:  # Limit to first 10 objects
                        result += f"  • {obj['name']} ({obj['type']}) - {obj.get('description', 'No description')}\n"
                    if len(transport['objects']) > 10:
                        result += f"  ... and {len(transport['objects']) - 10} more objects\n"
                
                result += "\n"
            
            # Add helpful information
            result += f"💡 Tips:\n"
            result += f"• Use transport numbers for object creation/modification\n"
            result += f"• Check task status before making changes\n"
            result += f"• Objects are typically assigned to tasks, not directly to requests\n"
            result += f"• If tasks/objects are not shown, you may need additional SAP authorizations\n"
            
            return result
            
        except Exception as e:
            logger.error(f"Error getting transport requests: {sanitize_for_logging(str(e))}")
            return f"❌ Error getting transport requests: {sanitize_for_logging(str(e))}"
    
    def _get_attr_with_namespace(self, elem, attr_name):
        """Try multiple ways to get an attribute from XML element with namespace handling"""
        # Try without namespace first
        value = elem.get(attr_name)
        if value:
            return value
        
        # Try with tm: prefix
        value = elem.get(f'tm:{attr_name}')
        if value:
            return value
        
        # Try with full namespace
        tm_ns = "{http://www.sap.com/cts/adt/tm}"
        value = elem.get(f'{tm_ns}{attr_name}')
        if value:
            return value
        
        return ''

    def _parse_transport_detail_from_tree(self, xml_content: str, target_transport_number: str) -> Optional[Dict[str, Any]]:
        """Parse detailed transport information from transport organizer tree XML response"""
        try:
            from utils.xml_utils import safe_parse_xml
            root = safe_parse_xml(xml_content)
            if root is None:
                logger.error(f"Failed to parse XML for transport {target_transport_number}")
                return None
            
            transport_info = {
                'number': target_transport_number,
                'description': '',
                'status': '',
                'owner': '',
                'type': '',
                'last_changed': '',
                'tasks': [],
                'objects': []
            }
            
            logger.info(f"Searching for transport {target_transport_number} in organizer tree")
            
            # Parse transport organizer tree - handle XML namespaces properly
            found_transport = False
            all_request_numbers = []
            
            for elem in root.iter():
                # Debug: Log all elements we're checking
                elem_number = self._get_attr_with_namespace(elem, 'number')
                if elem_number:
                    logger.debug(f"Found element with number: {elem.tag} -> {elem_number}")
                
                # Look for request elements - handle namespace properly
                if elem_number:
                    all_request_numbers.append(elem_number)
                    
                    # Check if this is our target transport and it's a request element
                    if (elem_number == target_transport_number and 
                        (elem.tag.endswith('}request') or elem.tag == 'tm:request' or 'request' in elem.tag)):
                        
                        found_transport = True
                        logger.info(f"Found transport request element for {target_transport_number}")
                        
                        # Extract request-level information
                        transport_info['description'] = self._get_attr_with_namespace(elem, 'desc')
                        transport_info['status'] = self._get_attr_with_namespace(elem, 'status')
                        transport_info['owner'] = self._get_attr_with_namespace(elem, 'owner')
                        transport_info['type'] = self._get_attr_with_namespace(elem, 'type')
                        transport_info['last_changed'] = self._get_attr_with_namespace(elem, 'lastchanged_timestamp')
                        
                        logger.info(f"Transport details: {transport_info['description']} (Status: {transport_info['status']}, Owner: {transport_info['owner']})")
                        
                        # Look for tasks within this request element and in the broader tree
                        task_count = 0
                        
                        # Method 1: Look for tasks as direct children of this request
                        logger.info(f"Method 1: Looking for tasks as children of request {target_transport_number}")
                        for child in elem:
                            child_number = self._get_attr_with_namespace(child, 'number')
                            if (child_number and 
                                (child.tag.endswith('}task') or child.tag == 'tm:task' or 'task' in child.tag)):
                                
                                task_number = child_number
                                logger.info(f"Found direct child task: {task_number}")
                                task_count += 1
                                
                                task_info = {
                                    'number': task_number,
                                    'description': self._get_attr_with_namespace(child, 'desc'),
                                    'owner': self._get_attr_with_namespace(child, 'owner'),
                                    'status': self._get_attr_with_namespace(child, 'status'),
                                    'type': self._get_attr_with_namespace(child, 'type'),
                                    'objects': []
                                }
                                
                                logger.info(f"Task details: {task_number} - {task_info['description']} (Owner: {task_info['owner']})")
                                
                                # Look for objects within this task
                                object_count = 0
                                for obj_child in child:
                                    obj_name = self._get_attr_with_namespace(obj_child, 'name')
                                    if (obj_name and 
                                        (obj_child.tag.endswith('}abap_object') or obj_child.tag == 'tm:abap_object' or 
                                         'abap_object' in obj_child.tag or 'object' in obj_child.tag)):
                                        
                                        object_count += 1
                                        obj_info = {
                                            'name': obj_name,
                                            'type': self._get_attr_with_namespace(obj_child, 'type'),
                                            'description': self._get_attr_with_namespace(obj_child, 'obj_desc'),
                                            'pgmid': self._get_attr_with_namespace(obj_child, 'pgmid'),
                                            'position': self._get_attr_with_namespace(obj_child, 'position'),
                                            'lock_status': self._get_attr_with_namespace(obj_child, 'lock_status'),
                                            'wbtype': self._get_attr_with_namespace(obj_child, 'wbtype'),
                                            'obj_info': self._get_attr_with_namespace(obj_child, 'obj_info')
                                        }
                                        
                                        task_info['objects'].append(obj_info)
                                        logger.info(f"Found object in task: {obj_info['name']} ({obj_info['type']}) - {obj_info['description']}")
                                
                                logger.info(f"Task {task_number} has {object_count} objects")
                                transport_info['tasks'].append(task_info)
                        
                        # Method 2: Look for tasks anywhere in the tree that reference this transport as parent
                        logger.info(f"Method 2: Looking for tasks with parent={target_transport_number} anywhere in tree")
                        for any_elem in root.iter():
                            any_elem_parent = self._get_attr_with_namespace(any_elem, 'parent')
                            any_elem_number = self._get_attr_with_namespace(any_elem, 'number')
                            if (any_elem_parent == target_transport_number and
                                any_elem_number and
                                (any_elem.tag.endswith('}task') or any_elem.tag == 'tm:task' or 'task' in any_elem.tag)):
                                
                                task_number = any_elem_number
                                
                                # Check if we already found this task
                                existing_task = next((t for t in transport_info['tasks'] if t['number'] == task_number), None)
                                if existing_task:
                                    logger.info(f"Task {task_number} already found via method 1")
                                    continue
                                
                                logger.info(f"Found task via parent reference: {task_number}")
                                task_count += 1
                                
                                task_info = {
                                    'number': task_number,
                                    'description': self._get_attr_with_namespace(any_elem, 'desc'),
                                    'owner': self._get_attr_with_namespace(any_elem, 'owner'),
                                    'status': self._get_attr_with_namespace(any_elem, 'status'),
                                    'type': self._get_attr_with_namespace(any_elem, 'type'),
                                    'objects': []
                                }
                                
                                logger.info(f"Task details: {task_number} - {task_info['description']} (Owner: {task_info['owner']})")
                                
                                # Look for objects within this task
                                object_count = 0
                                for obj_child in any_elem:
                                    obj_name = self._get_attr_with_namespace(obj_child, 'name')
                                    if (obj_name and 
                                        (obj_child.tag.endswith('}abap_object') or obj_child.tag == 'tm:abap_object' or 
                                         'abap_object' in obj_child.tag or 'object' in obj_child.tag)):
                                        
                                        object_count += 1
                                        obj_info = {
                                            'name': obj_name,
                                            'type': self._get_attr_with_namespace(obj_child, 'type'),
                                            'description': self._get_attr_with_namespace(obj_child, 'obj_desc'),
                                            'pgmid': self._get_attr_with_namespace(obj_child, 'pgmid'),
                                            'position': self._get_attr_with_namespace(obj_child, 'position'),
                                            'lock_status': self._get_attr_with_namespace(obj_child, 'lock_status'),
                                            'wbtype': self._get_attr_with_namespace(obj_child, 'wbtype'),
                                            'obj_info': self._get_attr_with_namespace(obj_child, 'obj_info')
                                        }
                                        
                                        task_info['objects'].append(obj_info)
                                        logger.info(f"Found object in task: {obj_info['name']} ({obj_info['type']}) - {obj_info['description']}")
                                
                                logger.info(f"Task {task_number} has {object_count} objects")
                                transport_info['tasks'].append(task_info)
                        
                        logger.info(f"Transport {target_transport_number} has {len(transport_info['tasks'])} tasks total")
                        break  # Found our transport, no need to continue
            
            if not found_transport:
                logger.warning(f"Transport {target_transport_number} not found in XML tree")
                logger.info(f"Available request numbers in tree: {list(set(all_request_numbers))}")
                
                # Debug: Show some sample elements to understand the structure
                sample_elements = []
                task_elements = []
                object_elements = []
                
                for elem in root.iter():
                    elem_number = self._get_attr_with_namespace(elem, 'number')
                    if elem_number and len(sample_elements) < 5:
                        sample_elements.append(f"{elem.tag} -> {elem_number}")
                    
                    if 'task' in elem.tag and len(task_elements) < 3:
                        task_number = self._get_attr_with_namespace(elem, 'number')
                        task_parent = self._get_attr_with_namespace(elem, 'parent')
                        task_elements.append(f"{elem.tag} -> number:{task_number} parent:{task_parent}")
                    
                    if ('object' in elem.tag or 'abap_object' in elem.tag) and len(object_elements) < 3:
                        obj_name = self._get_attr_with_namespace(elem, 'name')
                        obj_type = self._get_attr_with_namespace(elem, 'type')
                        object_elements.append(f"{elem.tag} -> name:{obj_name} type:{obj_type}")
                
                logger.info(f"Sample elements with tm:number: {sample_elements}")
                logger.info(f"Sample task elements: {task_elements}")
                logger.info(f"Sample object elements: {object_elements}")
                return None
            
            # Return the transport info if we found it
            logger.info(f"Successfully parsed transport {target_transport_number}: {len(transport_info['tasks'])} tasks, description: '{transport_info['description']}'")
            return transport_info
            
        except Exception as e:
            logger.error(f"Error parsing transport detail XML for {target_transport_number}: {sanitize_for_logging(str(e))}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return None