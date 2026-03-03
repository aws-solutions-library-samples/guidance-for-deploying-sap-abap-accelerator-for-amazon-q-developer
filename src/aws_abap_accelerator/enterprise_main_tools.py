"""
SAP Tools for Enterprise MCP Server
All tools use principal propagation authentication when enabled
"""

import os
import time
import logging
from typing import Dict, Any, Tuple
from functools import wraps

logger = logging.getLogger(__name__)


def register_sap_tools(mcp, server):
    """
    Register all SAP tools with principal propagation support.
    
    Args:
        mcp: FastMCP instance
        server: EnterpriseABAPAcceleratorServer instance
    """
    from enterprise.usage_tracker import enterprise_usage_tracker
    
    def _extract_user_identity(headers: Dict[str, str]) -> Tuple[str, str]:
        """
        Extract user identity from request headers using IAM Identity Validator.
        
        Returns:
            Tuple of (user_id, login_identifier)
            - user_id: Username for display/logging
            - login_identifier: Pass-through value for certificate CN (what user typed to login)
        """
        from auth.iam_identity_validator import IAMIdentityValidator
        from server.oauth_helpers import check_authentication_and_challenge, MCPAuthenticationRequired
        from server.fastmcp_oauth_integration import get_user_from_request
        
        # Log ALL headers for debugging Amazon Q Developer
        logger.info(f"AUTH: All request headers: {dict(headers)}")
        
        # Try FastMCP OAuth first (NEW approach)
        try:
            user_from_oauth = get_user_from_request()
            if user_from_oauth:
                logger.info(f"AUTH: User from FastMCP OAuth: {user_from_oauth}")
                # For OAuth, the user_from_oauth is the login identifier (pass-through)
                return user_from_oauth, user_from_oauth
        except Exception as e:
            logger.debug(f"AUTH: FastMCP OAuth not available: {e}")
        
        # Fallback to IAM Identity Validator (existing approach)
        validator = IAMIdentityValidator()
        identity_info = validator.extract_identity_from_headers(headers)
        
        if identity_info:
            # Get login_identifier for pass-through CN (what user typed to login)
            login_identifier = identity_info.get('login_identifier')
            user_email = identity_info.get('email')
            
            # Extract username part (before @) for display, but keep login_identifier for CN
            if user_email:
                if '@' in user_email:
                    username = user_email.split('@')[0]
                    logger.info(f"AUTH: Extracted user identity: {username}, login_identifier: {login_identifier} (source: {identity_info.get('source')})")
                    return username, login_identifier or user_email
                else:
                    logger.info(f"AUTH: Extracted user identity: {user_email}, login_identifier: {login_identifier} (source: {identity_info.get('source')})")
                    return user_email, login_identifier or user_email
        
        # Fallback: If no identity found, check if OAuth challenge should be returned
        logger.warning(f"AUTH: No user identity found in headers. Available headers: {list(headers.keys())}")
        
        # Check if legacy OAuth challenge should be returned (feature-flagged)
        auth_challenge = check_authentication_and_challenge('anonymous')
        if auth_challenge:
            raise MCPAuthenticationRequired(
                "Authentication required. Please authenticate to access SAP tools.",
                auth_challenge
            )
        
        return None, None
    
    async def _get_auth_context(sap_system_id: str = None) -> Tuple[Any, Dict[str, Any], Dict[str, str]]:
        """
        Get SAP client and context with hybrid approach.
        
        Priority order for SAP system ID:
        1. Tool parameter (sap_system_id argument)
        2. HTTP header (x-sap-system-id)
        3. Environment variable (DEFAULT_SAP_SYSTEM_ID)
        
        Args:
            sap_system_id: Optional SAP system ID from tool parameter
            
        Returns:
            Tuple of (sap_client, context, headers)
        """
        from fastmcp.server.dependencies import get_http_headers
        
        try:
            headers = get_http_headers()
        except:
            headers = {}
        
        user_id, login_identifier = _extract_user_identity(headers)
        
        # Hybrid approach: Priority order for system_id
        # 1. Tool parameter (highest priority)
        # 2. HTTP header
        # 3. Environment variable (lowest priority)
        system_id = None
        source = None
        
        if sap_system_id:
            system_id = sap_system_id
            source = "tool parameter"
        elif headers.get('x-sap-system-id'):
            system_id = headers.get('x-sap-system-id')
            source = "HTTP header"
        else:
            system_id = os.getenv('DEFAULT_SAP_SYSTEM_ID', 'default-sap-system')
            source = "environment variable"
        
        logger.info(f"AUTH: Using SAP system ID '{system_id}' from {source}")
        
        # Fallback for user_id if principal propagation is enabled
        if server.principal_propagation_enabled and not user_id:
            user_id = os.getenv('DEFAULT_USER_ID', 'service-account')
            login_identifier = user_id  # Use same as user_id for fallback
            logger.info(f"AUTH: No user identity in headers, using default: {user_id}")
        
        sap_client, context = await server._get_sap_client_and_context(user_id, system_id, login_identifier)
        return sap_client, context, headers
    
    def _format_context_info(context: Dict[str, Any], extra_info: str = "") -> str:
        """Format context info for tool response."""
        auth_mode = context.get('auth_mode', 'unknown')
        info = f"Authentication: {auth_mode.upper()}\n"
        info += f"SAP User: {context.get('sap_username')}@{context.get('sap_host')}\n"
        if extra_info:
            info += extra_info
        info += "=" * 50 + "\n\n"
        return info
    
    def _track_usage(tool_name: str, context: Dict, headers: Dict, start_time: float, success: bool, error_message: str = None):
        """Track tool usage for analytics."""
        try:
            duration_ms = int((time.time() - start_time) * 1000)
            enterprise_usage_tracker.track_tool_usage(
                user_id=context.get('iam_identity', 'unknown'),
                system_id=headers.get('x-sap-system-id', 'unknown'),
                session_id=f"session_{int(time.time())}",
                tool_name=tool_name,
                duration_ms=duration_ms,
                success=success,
                error_message=error_message,
                team_id=headers.get('x-team-id', 'unknown'),
                request_id=f"req_{int(time.time())}"
            )
        except Exception as e:
            logger.error(f"Error tracking usage: {e}")

    # ==================== SAP TOOLS ====================
    
    @mcp.tool()
    async def aws_abap_cb_connection_status(sap_system_id: str = None) -> str:
        """
        Check SAP connection status
        
        Args:
            sap_system_id: Optional SAP system identifier (e.g., 'S4H-100'). 
                          If not provided, uses x-sap-system-id header or DEFAULT_SAP_SYSTEM_ID env var.
        """
        start_time = time.time()
        success = True
        error_message = None
        context = {}
        headers = {}
        
        try:
            sap_client, context, headers = await _get_auth_context(sap_system_id)
            
            from server.tool_handlers import ToolHandlers
            tool_handlers = ToolHandlers(sap_client)
            result = tool_handlers.handle_connection_status(True)
            
            return _format_context_info(context) + result
            
        except Exception as e:
            success = False
            error_message = str(e)
            logger.error(f"Error in connection status: {e}")
            return f"❌ Error: {str(e)}"
        finally:
            _track_usage("aws_abap_cb_connection_status", context, headers, start_time, success, error_message)
    
    @mcp.tool()
    async def aws_abap_cb_get_objects(package_name: str = None, sap_system_id: str = None) -> str:
        """
        Get ABAP objects from SAP system
        
        Args:
            package_name: Optional package name to filter objects
            sap_system_id: Optional SAP system identifier (e.g., 'S4H-100'). 
                          If not provided, uses x-sap-system-id header or DEFAULT_SAP_SYSTEM_ID env var.
        """
        start_time = time.time()
        success = True
        error_message = None
        context = {}
        headers = {}
        
        try:
            sap_client, context, headers = await _get_auth_context(sap_system_id)
            
            from server.tool_handlers import ToolHandlers
            tool_handlers = ToolHandlers(sap_client)
            result = await tool_handlers.handle_get_objects(package_name)
            
            extra = f"Package: {package_name or 'All packages'}\n"
            return _format_context_info(context, extra) + result
            
        except Exception as e:
            success = False
            error_message = str(e)
            logger.error(f"Error getting objects: {e}")
            return f"❌ Error: {str(e)}"
        finally:
            _track_usage("aws_abap_cb_get_objects", context, headers, start_time, success, error_message)
    
    @mcp.tool()
    async def aws_abap_cb_get_source(object_name: str, object_type: str, explanation: str = None, sap_system_id: str = None) -> str:
        """
        Get source code of ABAP object
        
        Args:
            object_name: Name of the ABAP object
            object_type: Type of object (e.g., 'CLAS', 'INTF', 'PROG')
            explanation: Optional explanation for the request
            sap_system_id: Optional SAP system identifier (e.g., 'S4H-100'). 
                          If not provided, uses x-sap-system-id header or DEFAULT_SAP_SYSTEM_ID env var.
        """
        start_time = time.time()
        success = True
        error_message = None
        context = {}
        headers = {}
        
        try:
            sap_client, context, headers = await _get_auth_context(sap_system_id)
            
            from server.tool_handlers import ToolHandlers
            tool_handlers = ToolHandlers(sap_client)
            result = await tool_handlers.handle_get_source(object_name, object_type)
            
            extra = f"Object: {object_name} ({object_type})\n"
            return _format_context_info(context, extra) + str(result)
            
        except Exception as e:
            success = False
            error_message = str(e)
            logger.error(f"Error getting source: {e}")
            return f"❌ Error: {str(e)}"
        finally:
            _track_usage("aws_abap_cb_get_source", context, headers, start_time, success, error_message)
    
    @mcp.tool()
    async def aws_abap_cb_search_object(query: str, object_type: str = None, package_name: str = None, max_results: int = 50, include_inactive: bool = False, sap_system_id: str = None) -> str:
        """
        Search for ABAP objects
        
        Args:
            query: Search query string
            object_type: Optional object type filter
            package_name: Optional package name filter
            max_results: Maximum number of results (default: 50)
            include_inactive: Include inactive objects (default: False)
            sap_system_id: Optional SAP system identifier (e.g., 'S4H-100'). 
                          If not provided, uses x-sap-system-id header or DEFAULT_SAP_SYSTEM_ID env var.
        """
        start_time = time.time()
        success = True
        error_message = None
        context = {}
        headers = {}
        
        try:
            sap_client, context, headers = await _get_auth_context(sap_system_id)
            
            from server.tool_handlers import ToolHandlers
            tool_handlers = ToolHandlers(sap_client)
            result = await tool_handlers.handle_search_object({
                'query': query,
                'object_type': object_type,
                'package_name': package_name,
                'max_results': max_results,
                'include_inactive': include_inactive
            })
            
            extra = f"Search: {query}\n"
            return _format_context_info(context, extra) + result
            
        except Exception as e:
            success = False
            error_message = str(e)
            logger.error(f"Error searching: {e}")
            return f"❌ Error: {str(e)}"
        finally:
            _track_usage("aws_abap_cb_search_object", context, headers, start_time, success, error_message)
    
    @mcp.tool()
    async def aws_abap_cb_create_object(name: str, type: str, description: str, package_name: str = None, source_code: str = None, service_definition: str = None, binding_type: str = None, behavior_definition: str = None, is_test_class: bool = False, interfaces: list = None, super_class: str = None, visibility: str = "PUBLIC", methods: list = None, transport_request: str = None, sap_system_id: str = None) -> str:
        """
        Create new ABAP object
        
        Args:
            name: Name of the object to create
            type: Type of object (e.g., 'CLAS', 'INTF', 'PROG')
            description: Description of the object
            package_name: Package name (default: $TMP)
            source_code: Optional source code
            service_definition: Optional service definition
            binding_type: Optional binding type
            behavior_definition: Optional behavior definition
            is_test_class: Whether this is a test class
            interfaces: List of interfaces to implement
            super_class: Super class name
            visibility: Visibility (PUBLIC, PROTECTED, PRIVATE)
            methods: List of methods
            transport_request: Transport request number
            sap_system_id: Optional SAP system identifier (e.g., 'S4H-100'). 
                          If not provided, uses x-sap-system-id header or DEFAULT_SAP_SYSTEM_ID env var.
        """
        start_time = time.time()
        success = True
        error_message = None
        context = {}
        headers = {}
        
        try:
            sap_client, context, headers = await _get_auth_context(sap_system_id)
            
            from server.tool_handlers import ToolHandlers
            tool_handlers = ToolHandlers(sap_client)
            result = await tool_handlers.handle_create_object({
                'name': name, 'type': type, 'description': description,
                'package_name': package_name or "$TMP", 'source_code': source_code,
                'service_definition': service_definition, 'binding_type': binding_type,
                'behavior_definition': behavior_definition, 'is_test_class': is_test_class,
                'interfaces': interfaces, 'super_class': super_class,
                'visibility': visibility, 'methods': methods, 'transport_request': transport_request
            })
            
            extra = f"Created: {name} ({type})\n"
            return _format_context_info(context, extra) + result
            
        except Exception as e:
            success = False
            error_message = str(e)
            logger.error(f"Error creating object: {e}")
            return f"❌ Error: {str(e)}"
        finally:
            _track_usage("aws_abap_cb_create_object", context, headers, start_time, success, error_message)
    
    @mcp.tool()
    async def aws_abap_cb_update_source(object_name: str, object_type: str, source_code: str = None, methods: list = None, add_interface: str = None, sap_system_id: str = None) -> str:
        """
        Update source code of ABAP object
        
        Args:
            object_name: Name of the object to update
            object_type: Type of object
            source_code: New source code
            methods: List of methods to update
            add_interface: Interface to add
            sap_system_id: Optional SAP system identifier (e.g., 'S4H-100'). 
                          If not provided, uses x-sap-system-id header or DEFAULT_SAP_SYSTEM_ID env var.
        """
        start_time = time.time()
        success = True
        error_message = None
        context = {}
        headers = {}
        
        try:
            sap_client, context, headers = await _get_auth_context(sap_system_id)
            
            from server.tool_handlers import ToolHandlers
            tool_handlers = ToolHandlers(sap_client)
            result = await tool_handlers.handle_update_source({
                'object_name': object_name, 'object_type': object_type,
                'source_code': source_code, 'methods': methods, 'add_interface': add_interface
            })
            
            extra = f"Updated: {object_name} ({object_type})\n"
            return _format_context_info(context, extra) + result
            
        except Exception as e:
            success = False
            error_message = str(e)
            logger.error(f"Error updating source: {e}")
            return f"❌ Error: {str(e)}"
        finally:
            _track_usage("aws_abap_cb_update_source", context, headers, start_time, success, error_message)
    
    @mcp.tool()
    async def aws_abap_cb_check_syntax(object_name: str, object_type: str, source_code: str = None, sap_system_id: str = None) -> str:
        """
        Check syntax of ABAP object
        
        Args:
            object_name: Name of the object
            object_type: Type of object
            source_code: Optional source code to check
            sap_system_id: Optional SAP system identifier (e.g., 'S4H-100'). 
                          If not provided, uses x-sap-system-id header or DEFAULT_SAP_SYSTEM_ID env var.
        """
        start_time = time.time()
        success = True
        error_message = None
        context = {}
        headers = {}
        
        try:
            sap_client, context, headers = await _get_auth_context(sap_system_id)
            
            from server.tool_handlers import ToolHandlers
            tool_handlers = ToolHandlers(sap_client)
            result = await tool_handlers.handle_check_syntax(object_name, object_type, source_code)
            
            extra = f"Syntax Check: {object_name} ({object_type})\n"
            return _format_context_info(context, extra) + result
            
        except Exception as e:
            success = False
            error_message = str(e)
            logger.error(f"Error checking syntax: {e}")
            return f"❌ Error: {str(e)}"
        finally:
            _track_usage("aws_abap_cb_check_syntax", context, headers, start_time, success, error_message)
    
    @mcp.tool()
    async def aws_abap_cb_activate_object(object_name: str = None, object_type: str = None, objects: list = None, sap_system_id: str = None) -> str:
        """
        Activate ABAP objects
        
        Args:
            object_name: Name of single object to activate
            object_type: Type of single object
            objects: List of objects to activate
            sap_system_id: Optional SAP system identifier (e.g., 'S4H-100'). 
                          If not provided, uses x-sap-system-id header or DEFAULT_SAP_SYSTEM_ID env var.
        """
        start_time = time.time()
        success = True
        error_message = None
        context = {}
        headers = {}
        
        try:
            sap_client, context, headers = await _get_auth_context(sap_system_id)
            
            from server.tool_handlers import ToolHandlers
            tool_handlers = ToolHandlers(sap_client)
            result = await tool_handlers.handle_activate_object({
                'object_name': object_name, 'object_type': object_type, 'objects': objects
            })
            
            extra = f"Activate: {object_name or 'Multiple objects'}\n"
            return _format_context_info(context, extra) + result
            
        except Exception as e:
            success = False
            error_message = str(e)
            logger.error(f"Error activating: {e}")
            return f"❌ Error: {str(e)}"
        finally:
            _track_usage("aws_abap_cb_activate_object", context, headers, start_time, success, error_message)
    
    @mcp.tool()
    async def aws_abap_cb_run_atc_check(object_name: str = None, object_type: str = None, package_name: str = None, include_subpackages: bool = False, transport_number: str = None, variant: str = None, include_documentation: bool = True, summary_mode: bool = False, sap_system_id: str = None) -> str:
        """
        Run ATC check on ABAP object
        
        Args:
            object_name: Name of object to check
            object_type: Type of object
            package_name: Package name to check
            include_subpackages: Include subpackages
            transport_number: Transport request number
            variant: ATC variant
            include_documentation: Include documentation
            summary_mode: Summary mode
            sap_system_id: Optional SAP system identifier (e.g., 'S4H-100'). 
                          If not provided, uses x-sap-system-id header or DEFAULT_SAP_SYSTEM_ID env var.
        """
        start_time = time.time()
        success = True
        error_message = None
        context = {}
        headers = {}
        
        try:
            sap_client, context, headers = await _get_auth_context(sap_system_id)
            
            from server.tool_handlers import ToolHandlers
            from sap_types.sap_types import ATCCheckArgs
            tool_handlers = ToolHandlers(sap_client)
            result = await tool_handlers.handle_run_atc_check(ATCCheckArgs(
                object_name=object_name, object_type=object_type, package_name=package_name,
                include_subpackages=include_subpackages, transport_number=transport_number,
                variant=variant, include_documentation=include_documentation
            ), summary_mode=summary_mode)
            
            extra = f"ATC Check: {object_name or package_name or 'General'}\n"
            return _format_context_info(context, extra) + result
            
        except Exception as e:
            success = False
            error_message = str(e)
            logger.error(f"Error running ATC: {e}")
            return f"❌ Error: {str(e)}"
        finally:
            _track_usage("aws_abap_cb_run_atc_check", context, headers, start_time, success, error_message)
    
    @mcp.tool()
    async def aws_abap_cb_run_unit_tests(object_name: str, object_type: str = "CLAS", with_coverage: bool = False, sap_system_id: str = None) -> str:
        """
        Run unit tests for ABAP object
        
        Args:
            object_name: Name of object to test
            object_type: Type of object (default: CLAS)
            with_coverage: Include coverage data
            sap_system_id: Optional SAP system identifier (e.g., 'S4H-100'). 
                          If not provided, uses x-sap-system-id header or DEFAULT_SAP_SYSTEM_ID env var.
        """
        start_time = time.time()
        success = True
        error_message = None
        context = {}
        headers = {}
        
        try:
            sap_client, context, headers = await _get_auth_context(sap_system_id)
            
            from server.tool_handlers import ToolHandlers
            tool_handlers = ToolHandlers(sap_client)
            result = await tool_handlers.handle_run_unit_tests(object_name, object_type, with_coverage)
            
            extra = f"Unit Tests: {object_name} ({object_type})\n"
            return _format_context_info(context, extra) + result
            
        except Exception as e:
            success = False
            error_message = str(e)
            logger.error(f"Error running tests: {e}")
            return f"❌ Error: {str(e)}"
        finally:
            _track_usage("aws_abap_cb_run_unit_tests", context, headers, start_time, success, error_message)
    
    @mcp.tool()
    async def aws_abap_cb_get_test_classes(class_name: str, object_type: str = "CLAS", sap_system_id: str = None) -> str:
        """
        Get test classes for ABAP class
        
        Args:
            class_name: Name of class
            object_type: Type of object (default: CLAS)
            sap_system_id: Optional SAP system identifier (e.g., 'S4H-100'). 
                          If not provided, uses x-sap-system-id header or DEFAULT_SAP_SYSTEM_ID env var.
        """
        start_time = time.time()
        success = True
        error_message = None
        context = {}
        headers = {}
        
        try:
            sap_client, context, headers = await _get_auth_context(sap_system_id)
            
            from server.tool_handlers import ToolHandlers
            tool_handlers = ToolHandlers(sap_client)
            result = await tool_handlers.handle_get_test_classes(class_name, object_type)
            
            extra = f"Test Classes: {class_name}\n"
            return _format_context_info(context, extra) + result
            
        except Exception as e:
            success = False
            error_message = str(e)
            logger.error(f"Error getting test classes: {e}")
            return f"❌ Error: {str(e)}"
        finally:
            _track_usage("aws_abap_cb_get_test_classes", context, headers, start_time, success, error_message)
    
    @mcp.tool()
    async def aws_abap_cb_get_migration_analysis(object_name: str, object_type: str, sap_system_id: str = None) -> str:
        """
        Get migration analysis for ABAP object
        
        Args:
            object_name: Name of object
            object_type: Type of object
            sap_system_id: Optional SAP system identifier (e.g., 'S4H-100'). 
                          If not provided, uses x-sap-system-id header or DEFAULT_SAP_SYSTEM_ID env var.
        """
        start_time = time.time()
        success = True
        error_message = None
        context = {}
        headers = {}
        
        try:
            sap_client, context, headers = await _get_auth_context(sap_system_id)
            
            from server.tool_handlers import ToolHandlers
            tool_handlers = ToolHandlers(sap_client)
            result = await tool_handlers.handle_get_migration_analysis(object_name, object_type)
            
            extra = f"Migration Analysis: {object_name} ({object_type})\n"
            return _format_context_info(context, extra) + result
            
        except Exception as e:
            success = False
            error_message = str(e)
            logger.error(f"Error getting migration analysis: {e}")
            return f"❌ Error: {str(e)}"
        finally:
            _track_usage("aws_abap_cb_get_migration_analysis", context, headers, start_time, success, error_message)
    
    @mcp.tool()
    async def aws_abap_cb_create_or_update_test_class(class_name: str, methods: list, sap_system_id: str = None) -> str:
        """
        Create or update test class
        
        Args:
            class_name: Name of test class
            methods: List of test methods
            sap_system_id: Optional SAP system identifier (e.g., 'S4H-100'). 
                          If not provided, uses x-sap-system-id header or DEFAULT_SAP_SYSTEM_ID env var.
        """
        start_time = time.time()
        success = True
        error_message = None
        context = {}
        headers = {}
        
        try:
            sap_client, context, headers = await _get_auth_context(sap_system_id)
            
            from server.tool_handlers import ToolHandlers
            tool_handlers = ToolHandlers(sap_client)
            result = await tool_handlers.handle_create_or_update_test_class(class_name, methods)
            
            extra = f"Test Class: {class_name} ({len(methods)} methods)\n"
            return _format_context_info(context, extra) + result
            
        except Exception as e:
            success = False
            error_message = str(e)
            logger.error(f"Error with test class: {e}")
            return f"❌ Error: {str(e)}"
        finally:
            _track_usage("aws_abap_cb_create_or_update_test_class", context, headers, start_time, success, error_message)
    
    @mcp.tool()
    async def aws_abap_cb_activate_objects_batch(objects: list, sap_system_id: str = None) -> str:
        """
        Activate multiple ABAP objects in batch
        
        Args:
            objects: List of objects to activate
            sap_system_id: Optional SAP system identifier (e.g., 'S4H-100'). 
                          If not provided, uses x-sap-system-id header or DEFAULT_SAP_SYSTEM_ID env var.
        """
        start_time = time.time()
        success = True
        error_message = None
        context = {}
        headers = {}
        
        try:
            sap_client, context, headers = await _get_auth_context(sap_system_id)
            
            from server.tool_handlers import ToolHandlers
            tool_handlers = ToolHandlers(sap_client)
            result = await tool_handlers.handle_activate_objects_batch({'objects': objects})
            
            extra = f"Batch Activate: {len(objects)} objects\n"
            return _format_context_info(context, extra) + result
            
        except Exception as e:
            success = False
            error_message = str(e)
            logger.error(f"Error batch activating: {e}")
            return f"❌ Error: {str(e)}"
        finally:
            _track_usage("aws_abap_cb_activate_objects_batch", context, headers, start_time, success, error_message)
    
    @mcp.tool()
    async def aws_abap_cb_get_transport_requests(username: str = None, sap_system_id: str = None) -> str:
        """
        Get transport requests
        
        Args:
            username: Optional username filter
            sap_system_id: Optional SAP system identifier (e.g., 'S4H-100'). 
                          If not provided, uses x-sap-system-id header or DEFAULT_SAP_SYSTEM_ID env var.
        """
        start_time = time.time()
        success = True
        error_message = None
        context = {}
        headers = {}
        
        try:
            sap_client, context, headers = await _get_auth_context(sap_system_id)
            
            from server.tool_handlers import ToolHandlers
            tool_handlers = ToolHandlers(sap_client)
            result = await tool_handlers.handle_get_transport_requests(username)
            
            extra = f"Transport Requests: {username or 'current user'}\n"
            return _format_context_info(context, extra) + result
            
        except Exception as e:
            success = False
            error_message = str(e)
            logger.error(f"Error getting transports: {e}")
            return f"❌ Error: {str(e)}"
        finally:
            _track_usage("aws_abap_cb_get_transport_requests", context, headers, start_time, success, error_message)
    
    logger.info("Registered 15 SAP tools with principal propagation support")
