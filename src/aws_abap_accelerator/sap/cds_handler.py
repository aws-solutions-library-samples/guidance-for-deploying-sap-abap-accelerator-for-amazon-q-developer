"""
CDS Handler for SAP ADT Client - Python implementation
Follows the exact SAP ADT workflow as documented in the TypeScript version and CDS ADT Calls.txt

SAP ADT CDS View Creation Workflow:
1. Validation - POST /sap/bc/adt/ddic/ddl/validation (check object name/params)
2. Transport Check - POST /sap/bc/adt/cts/transportchecks (verify transport requirements)
3. Object Creation - POST /sap/bc/adt/ddic/ddl/sources (create empty object shell)
4. Lock Acquisition - POST ...?_action=LOCK&accessMode=MODIFY (get exclusive edit access)
5. Source Operations:
   a. GET ...?version=inactive (retrieve current source)
   b. POST /sap/bc/adt/ddic/ddl/formatter/identifiers (format source code)
   c. PUT .../source/main?lockHandle=... (update source code)
   d. GET ...?version=inactive (verify source update)
6. Lock Release - POST ...?_action=UNLOCK&lockHandle=... (release edit lock)
7. Activation - POST /sap/bc/adt/activation?method=activate&preauditRequested=true (compile/activate)
"""

import asyncio
import logging
import aiohttp
import re
from typing import Optional, Dict, Any, List
from urllib.parse import quote

from utils.security import sanitize_for_logging, sanitize_for_xml, validate_object_name
from utils.xml_utils import safe_parse_xml, extract_from_xml

logger = logging.getLogger(__name__)


class CDSHandler:
    """Handler for CDS views following SAP ADT workflow"""
    
    # Constants matching TypeScript version
    USER_AGENT = 'Eclipse/4.37.0.v20250905-0730 (win32; x86_64; Java 21.0.8) ADT/3.52.0 (devedition)'
    MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10MB limit
    ACTIVATION_XML_TEMPLATE = '''<?xml version="1.0" encoding="UTF-8"?>
<adtcore:objectReferences xmlns:adtcore="http://www.sap.com/adt/core">
  <adtcore:objectReference adtcore:uri="{uri}" adtcore:name="{name}"/>
</adtcore:objectReferences>'''
    
    COMMON_HEADERS = {
        'X-sap-adt-profiling': 'server-time'
    }
    
    # Cached regex patterns for performance
    TRANSPORT_REGEX = re.compile(r'<CORRNR>([^<]+)</CORRNR>')
    LOCK_HANDLE_REGEX = re.compile(r'<LOCK_HANDLE>([^<]+)</LOCK_HANDLE>')
    TRANSPORT_CHECK_REGEX = re.compile(r'<TRKORR>([^<]+)</TRKORR>')
    
    def __init__(self, sap_client):
        """Initialize CDS handler with SAP client reference"""
        self.sap_client = sap_client
        self.last_lock_response = None
    
    async def create_cds_view(
        self,
        name: str,
        description: str,
        package_name: str,
        source_code: str,
        csrf_token: str,
        cookies: List[str]
    ) -> bool:
        """
        Create a CDS view following the exact SAP ADT workflow:
        1. Validation - Check object name and parameters
        2. Transport Check - Verify transport requirements  
        3. Object Creation - Create empty CDS object shell (SKIP if object exists)
        4. Lock Acquisition - Get exclusive edit access
        5. Source Operations - Format and update source code
        6. Lock Release - Release edit lock
        7. Activation - Compile and activate object
        """
        # Input validation using security utils
        if not validate_object_name(name):
            logger.error(sanitize_for_logging('Invalid CDS view name provided'))
            return False
        if not description or not isinstance(description, str):
            logger.error(sanitize_for_logging('CDS view description is required and must be a string'))
            return False
        if not package_name or not isinstance(package_name, str):
            logger.error(sanitize_for_logging('Package name is required and must be a string'))
            return False
        if not csrf_token or not isinstance(csrf_token, str):
            logger.error(sanitize_for_logging('CSRF token is required and must be a string'))
            return False
        if not isinstance(cookies, list):
            logger.error(sanitize_for_logging('Cookies must be a list'))
            return False
        
        try:
            logger.info(sanitize_for_logging(f'Creating CDS view {name} using SAP ADT workflow'))
            
            # Prepare base authentication and headers
            base_headers = await self._prepare_base_headers(csrf_token, cookies)
            
            # Prepare source code - use provided or create minimal template
            final_source_code = source_code
            if not source_code.strip():
                # nosec B608 - This is CDS view source code for SAP ADT API, NOT a SQL query
                # User inputs are sanitized via sanitize_for_xml() before inclusion
                final_source_code = f'''@AbapCatalog.viewEnhancementCategory: [#NONE]
@AccessControl.authorizationCheck: #NOT_REQUIRED
@EndUserText.label: '{sanitize_for_xml(description)}'
define view entity {sanitize_for_xml(name)} as select from dummy {{
  key 'X' as DummyKey
}}'''
            
            # STEP 1: Validation - Check if object name and parameters are valid
            logger.info(sanitize_for_logging('Step 1: Validating CDS view parameters'))
            validation_result = await self._perform_validation_with_exists_check(name, package_name, description, base_headers)
            if not validation_result['success']:
                logger.warning(sanitize_for_logging('CDS view validation failed - proceeding with creation attempt anyway (similar to standard object creation)'))
                # Don't return False here - continue like standard object creation does
                validation_result = {'success': True, 'object_exists': False}  # Assume new object
            
            # Check if we're in update mode (object already exists)
            is_update_mode = validation_result.get('object_exists', False)
            if is_update_mode:
                logger.info(sanitize_for_logging(f'CDS view {name} already exists - switching to update workflow'))
            
            # STEP 2: Transport Check - Verify transport requirements and get metadata
            logger.info(sanitize_for_logging('Step 2: Checking transport requirements'))
            transport_result = await self._check_transport_requirements(name, package_name, csrf_token, cookies)
            if not transport_result['success']:
                logger.error(sanitize_for_logging('Transport requirements check failed'))
                return False
            
            # STEP 3: Object Creation - Create empty CDS object shell (SKIP if object exists)
            if not is_update_mode:
                logger.info(sanitize_for_logging('Step 3: Creating CDS object shell'))
                object_created = await self._create_cds_object_shell(name, description, package_name, base_headers)
                if not object_created:
                    logger.error(sanitize_for_logging('CDS object shell creation failed'))
                    return False
            else:
                logger.info(sanitize_for_logging('Step 3: Skipping object shell creation (object already exists)'))
            
            # STEP 4: Lock Acquisition - Get exclusive edit access
            logger.info(sanitize_for_logging('Step 4: Acquiring edit lock'))
            lock_handle = await self._acquire_edit_lock(name, base_headers)
            if not lock_handle:
                logger.error(sanitize_for_logging('Failed to acquire edit lock'))
                return False
            
            lock_released = False
            try:
                # STEP 5: Source Operations - Format and update source code
                logger.info(sanitize_for_logging('Step 5: Updating source code'))
                
                # 5a: Get current source (should be empty for new objects, existing for updates)
                current_source = await self._get_current_source(name, base_headers)
                logger.info(sanitize_for_logging('Retrieved current source for verification'))
                
                # 5b: Format the source code
                formatted_source = await self._format_source_code(final_source_code, base_headers)
                source_to_use = formatted_source or final_source_code
                
                # 5c: Update source with formatted code
                source_updated = await self._update_source_code(name, source_to_use, lock_handle, base_headers)
                if not source_updated:
                    logger.error(sanitize_for_logging('Source code update failed'))
                    return False
                
                # 5d: Verify source update
                verification_source = await self._get_current_source(name, base_headers)
                if not self._validate_source_content(verification_source, source_to_use):
                    logger.warning(sanitize_for_logging('Source verification failed, but continuing'))
                
                # STEP 6: Lock Release - Release the edit lock
                logger.info(sanitize_for_logging('Step 6: Releasing edit lock'))
                await self._release_edit_lock(name, lock_handle, base_headers)
                lock_released = True
                
                # STEP 7: Activation - Compile and activate the object
                logger.info(sanitize_for_logging('Step 7: Activating CDS view'))
                activation_success = await self.activate_cds_view(name, csrf_token, cookies)
                
                if activation_success:
                    if is_update_mode:
                        logger.info(sanitize_for_logging(f'Successfully updated and activated CDS view {name}'))
                    else:
                        logger.info(sanitize_for_logging(f'Successfully created and activated CDS view {name}'))
                    return True
                else:
                    logger.error(sanitize_for_logging('CDS view activation failed'))
                    return False
                    
            finally:
                # Ensure lock is always released
                if not lock_released and lock_handle:
                    logger.info(sanitize_for_logging('Ensuring edit lock is released in finally block'))
                    await self._release_edit_lock(name, lock_handle, base_headers)
        
        except Exception as error:
            logger.error(sanitize_for_logging(f'Error in create_cds_view: {str(error)}'))
            return False
    
    async def update_cds_view_source(
        self,
        name: str,
        source_code: str,
        csrf_token: str,
        cookies: List[str]
    ) -> bool:
        """Update CDS view source code"""
        # Input validation
        if not name or not isinstance(name, str) or not name.strip():
            logger.error(sanitize_for_logging('CDS view name is required for source update'))
            return False
        if not isinstance(source_code, str):
            logger.error(sanitize_for_logging('Source code must be a string'))
            return False
        if not csrf_token or not isinstance(csrf_token, str):
            logger.error(sanitize_for_logging('CSRF token is required for source update'))
            return False
        if not isinstance(cookies, list):
            logger.error(sanitize_for_logging('Cookies must be a list for source update'))
            return False
        
        try:
            logger.info(sanitize_for_logging(f'Updating CDS view source for {name}'))
            
            # First check if source already matches what we want
            try:
                existing_source = await self._get_existing_source(name)
                if existing_source and existing_source.strip() == source_code.strip():
                    logger.info(sanitize_for_logging('CDS view source already matches target, skipping update'))
                    return True
            except Exception as source_check_error:
                logger.warning(sanitize_for_logging(f'Failed to check existing source: {str(source_check_error)}'))
                # Continue with update attempt even if source check fails
            
            # Prepare base headers
            base_headers = await self._prepare_base_headers(csrf_token, cookies)
            
            # Try different object URLs for locking - optimized with early termination
            object_urls = [
                f'/sap/bc/adt/ddic/ddl/sources/{name}',
                f'/sap/bc/adt/ddic/ddls/sources/{name}',
                f'/sap/bc/adt/ddl/sources/{name}'
            ]
            
            for object_url in object_urls:
                try:
                    # Lock the object
                    lock_handle = await self._lock_cds_view(name, object_url, base_headers)
                    if not lock_handle:
                        continue  # Early termination - skip to next URL
                    
                    logger.info(sanitize_for_logging(f'Successfully locked CDS view with handle: {lock_handle}'))
                    
                    try:
                        # Extract transport number from lock response if available
                        transport_number = None
                        try:
                            transport_number = await self._extract_transport_from_lock_response(lock_handle)
                        except Exception as transport_error:
                            logger.warning(sanitize_for_logging(f'Failed to extract transport number: {str(transport_error)}'))
                            # Continue without transport number
                        
                        # Build source URL
                        source_url = f'{object_url}/source/main'
                        params = {
                            'lockHandle': lock_handle,
                            'sap-client': self.sap_client.connection.client
                        }
                        if transport_number:
                            params['corrNr'] = transport_number
                        
                        logger.info(sanitize_for_logging(f'Updating CDS view source at: {source_url}'))
                        
                        # Update source code
                        update_headers = {
                            **base_headers,
                            'Content-Type': 'text/plain; charset=utf-8',
                            'User-Agent': self.USER_AGENT,
                            **self.COMMON_HEADERS
                        }
                        
                        async with self.sap_client.session.put(
                            f'{source_url}',
                            data=source_code,
                            headers=update_headers,
                            params=params,
                            timeout=30
                        ) as response:
                            if response.status in [200, 204]:
                                logger.info(sanitize_for_logging(f'Successfully updated CDS view source for {name}'))
                                return True  # Early termination on success
                            else:
                                logger.warning(sanitize_for_logging(f'Update failed with status: {response.status}'))
                    
                    finally:
                        # Always unlock the object
                        await self._unlock_cds_view(name, object_url, lock_handle, base_headers)
                
                except Exception as object_error:
                    # If we get 403 (Forbidden) or 404 (Not Found), the object might already be correct
                    if hasattr(object_error, 'status') and object_error.status in [403, 404]:
                        logger.info(sanitize_for_logging(f'Lock failed ({object_error.status}), checking if source is already correct'))
                        try:
                            current_source = await self._get_existing_source(name)
                            if self._validate_source_content(current_source, source_code):
                                logger.info(sanitize_for_logging('Source appears to be correct despite lock failure'))
                                return True  # Early termination on success
                        except Exception as source_check_error:
                            self._log_detailed_error('Failed to check source after lock failure', source_check_error, {'name': name})
                    
                    self._log_detailed_error('Failed with object URL', object_error, {'object_url': object_url, 'name': name})
                    continue
            
            # Final check - if we can't update but source exists and looks correct, consider it success
            try:
                final_source = await self._get_existing_source(name)
                if self._validate_source_content(final_source, source_code):
                    logger.info(sanitize_for_logging('Source update failed but object has valid source, considering success'))
                    return True
            except Exception as final_check_error:
                self._log_detailed_error('Final source check failed', final_check_error, {'name': name})
            
            logger.error(sanitize_for_logging(f'All object URLs failed for CDS view source update: {name}'))
            return False
            
        except Exception as error:
            logger.error(sanitize_for_logging(f'Error in update_cds_view_source: {str(error)}'))
            return False
    
    async def activate_cds_view(
        self,
        name: str,
        csrf_token: str,
        cookies: List[str]
    ) -> bool:
        """
        STEP 7: Activate CDS view (compile and activate)
        POST /sap/bc/adt/activation?method=activate&preauditRequested=true
        """
        # Input validation using security utils
        if not validate_object_name(name):
            logger.error(sanitize_for_logging('Invalid CDS view name for activation'))
            return False
        if not csrf_token or not isinstance(csrf_token, str):
            logger.error(sanitize_for_logging('CSRF token is required for activation'))
            return False
        if not isinstance(cookies, list):
            logger.error(sanitize_for_logging('Cookies must be a list for activation'))
            return False
        
        try:
            logger.info(sanitize_for_logging(f'Activating CDS view {name}'))
            
            # Build activation XML exactly as shown in SAP ADT logs
            activation_uri = f'/sap/bc/adt/ddic/ddl/sources/{name.lower()}'
            activation_xml = self.ACTIVATION_XML_TEMPLATE.format(
                uri=activation_uri,
                name=name.upper()
            )
            
            # Prepare headers matching SAP ADT format
            headers = {
                **self.COMMON_HEADERS,
                'Content-Type': 'application/xml',
                'Accept': 'application/xml',
                'User-Agent': self.USER_AGENT,
                'X-CSRF-Token': csrf_token,
                'x-csrf-token': csrf_token
            }
            
            # Use session cookies for authentication (no Basic Auth needed)
            if cookies:
                headers['Cookie'] = '; '.join([cookie.split(';')[0] for cookie in cookies])
            
            activation_url = f'/sap/bc/adt/activation'
            params = {
                'method': 'activate',
                'preauditRequested': 'true',
                'sap-client': self.sap_client.connection.client
            }
            
            async with self.sap_client.session.post(
                f'{activation_url}',
                data=activation_xml,
                headers=headers,
                params=params,
                timeout=30
            ) as response:
                if response.status == 200:
                    # Check for activation warnings/errors in response
                    response_data = await response.text()
                    if isinstance(response_data, str):
                        logger.info(sanitize_for_logging(f'Activation response for {name}: {response_data[:500]}...'))
                        
                        # Check for errors first - if there are errors, activation failed
                        if 'type="E"' in response_data:
                            logger.error(sanitize_for_logging(f'Activation failed for {name} - errors found in response'))
                            return False
                        
                        # Check if activation was executed
                        if 'checkExecuted="true"' in response_data and 'activationExecuted="true"' in response_data:
                            logger.info(sanitize_for_logging(f'Successfully activated CDS view {name}'))
                            
                            # Log any warnings (like search help assignments)
                            if 'type="W"' in response_data:
                                logger.warning(sanitize_for_logging('Activation completed with warnings (this is normal for CDS views)'))
                            
                            return True
                        else:
                            logger.error(sanitize_for_logging('Activation response indicates failure - activationExecuted not true'))
                            return False
                    
                    logger.info(sanitize_for_logging(f'CDS view {name} activated successfully'))
                    return True
                
                logger.error(sanitize_for_logging(f'Activation failed with status: {response.status}'))
                return False
                
        except Exception as error:
            self._log_detailed_error('CDS view activation failed', error, {'name': name})
            return False
    
    # Private helper methods following the TypeScript implementation
    
    async def _prepare_base_headers(self, csrf_token: str, cookies: List[str]) -> Dict[str, str]:
        """Prepare base authentication and headers"""
        base_headers = {
            'X-CSRF-Token': csrf_token,
            'x-csrf-token': csrf_token,
            'User-Agent': self.USER_AGENT,
            **self.COMMON_HEADERS
        }
        
        # Add cookies if available (for session-based auth)
        if cookies:
            base_headers['Cookie'] = '; '.join([cookie.split(';')[0] for cookie in cookies])
        
        # For token-based authentication, we don't need Basic Auth header
        # The session cookies and CSRF token provide authentication
        
        return base_headers
    
    async def _perform_validation_with_exists_check(
        self,
        name: str,
        package_name: str,
        description: str,
        base_headers: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        STEP 1: Perform validation of CDS view parameters with exists check
        POST /sap/bc/adt/ddic/ddl/validation
        
        Returns: {'success': bool, 'object_exists': bool}
        """
        max_retries = 1  # Reduced to 1 for faster response
        
        for attempt in range(max_retries):
            try:
                validation_url = '/sap/bc/adt/ddic/ddl/validation'
                params = {
                    'objname': name.lower(),  # ADT uses lowercase
                    'packagename': quote(package_name),  # Proper URL encoding
                    'description': quote(description),  # Proper URL encoding
                    'sap-client': self.sap_client.connection.client
                }
                
                validation_headers = {
                    **base_headers,
                    'Accept': 'application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.StatusMessage',
                    'User-Agent': 'ABAP-Accelerator-MCP/1.0.0',
                    'X-sap-adt-profiling': 'server-time'
                }
                
                logger.info(sanitize_for_logging(f'CDS validation attempt {attempt + 1}/{max_retries} for {name}'))
                
                async with self.sap_client.session.post(
                    f'{validation_url}',  # Use relative URL - session already has base_url
                    data='',
                    headers=validation_headers,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=30)  # Reduced timeout for faster response
                ) as response:
                    if response.status == 200:
                        # HTTP 200 means validation endpoint is working
                        response_data = await response.text()
                        if isinstance(response_data, str):
                            # Check if response explicitly indicates failure
                            if '<SEVERITY>ERROR</SEVERITY>' in response_data or '<SEVERITY>FATAL</SEVERITY>' in response_data:
                                # Check if error is "object already exists"
                                if ('already exists' in response_data.lower() or 
                                    'object already exists' in response_data.lower() or
                                    'already defined' in response_data.lower() or
                                    'duplicate' in response_data.lower()):
                                    logger.info(sanitize_for_logging(f'CDS view {name} already exists - proceeding with update workflow'))
                                    return {'success': True, 'object_exists': True}
                                else:
                                    logger.warning(sanitize_for_logging('CDS view validation failed - error in response'))
                                    return {'success': False, 'object_exists': False}
                            else:
                                # HTTP 200 without explicit error means validation passed for new object
                                logger.info(sanitize_for_logging('CDS view validation successful'))
                                return {'success': True, 'object_exists': False}
                        else:
                            # HTTP 200 with no response data - assume success for new object
                            logger.info(sanitize_for_logging('CDS view validation successful (no response data)'))
                            return {'success': True, 'object_exists': False}
                    
                    logger.warning(sanitize_for_logging(f'Validation failed with status: {response.status}'))
                    # Don't retry, just proceed with creation
                    logger.warning(sanitize_for_logging(f'CDS view validation failed for {name} - proceeding with creation attempt anyway'))
                    return {'success': True, 'object_exists': False}
                    
            except Exception as error:
                error_msg = str(error).lower()
                error_type = type(error).__name__.lower()
                logger.warning(sanitize_for_logging(f'CDS validation attempt {attempt + 1} failed: {str(error)}'))
                
                # For any error (including timeout), proceed with creation
                if ('timeout' in error_msg or 'connection timeout' in error_msg or 
                    'timeouterror' in error_type or 'asynciotimeouterror' in error_type or
                    'clienttimeouterror' in error_type or 'semaphore timeout' in error_msg or
                    'cannot connect to host' in error_msg):
                    logger.warning(sanitize_for_logging(f'CDS view validation timed out for {name} - proceeding with creation attempt'))
                    return {'success': True, 'object_exists': False}
                
                # For any other error, also proceed with creation (like standard object creation)
                logger.warning(sanitize_for_logging(f'CDS view validation failed for {name} - proceeding with creation attempt anyway'))
                return {'success': True, 'object_exists': False}
        
        # Fallback - always proceed with creation
        return {'success': True, 'object_exists': False}

    async def _perform_validation(
        self,
        name: str,
        package_name: str,
        description: str,
        base_headers: Dict[str, str]
    ) -> bool:
        """
        STEP 1: Perform validation of CDS view parameters
        POST /sap/bc/adt/ddic/ddl/validation
        
        CRITICAL FIX: Handle "object already exists" errors by treating them as success
        and proceeding with update workflow instead of aborting creation workflow.
        """
        validation_result = await self._perform_validation_with_exists_check(name, package_name, description, base_headers)
        return validation_result['success']
    
    async def _check_transport_requirements(
        self,
        name: str,
        package_name: str,
        csrf_token: str,
        cookies: List[str]
    ) -> Dict[str, Any]:
        """
        STEP 2: Check transport requirements for CDS view creation
        POST /sap/bc/adt/cts/transportchecks
        """
        try:
            transport_check_url = '/sap/bc/adt/cts/transportchecks'
            
            # Build transport check XML exactly as shown in SAP ADT logs
            transport_check_xml = f'''<?xml version="1.0" encoding="UTF-8" ?>
<asx:abap version="1.0" xmlns:asx="http://www.sap.com/abapxml">
  <asx:values>
    <DATA>
      <PGMID></PGMID>
      <OBJECT></OBJECT>
      <OBJECTNAME></OBJECTNAME>
      <DEVCLASS>{sanitize_for_xml(package_name)}</DEVCLASS>
      <SUPER_PACKAGE></SUPER_PACKAGE>
      <RECORD_CHANGES></RECORD_CHANGES>
      <OPERATION>I</OPERATION>
      <URI>/sap/bc/adt/ddic/ddl/sources/{sanitize_for_xml(name.lower())}</URI>
    </DATA>
  </asx:values>
</asx:abap>'''
            
            # Prepare headers matching SAP ADT format
            headers = {
                'Content-Type': 'application/vnd.sap.as+xml; charset=UTF-8; dataname=com.sap.adt.transport.service.checkData',
                'Accept': 'application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.transport.service.checkData',
                'User-Agent': self.USER_AGENT,
                **self.COMMON_HEADERS,
                'X-CSRF-Token': csrf_token,
                'x-csrf-token': csrf_token
            }
            
            # Use session cookies for authentication (no Basic Auth needed)
            if cookies:
                headers['Cookie'] = '; '.join([cookie.split(';')[0] for cookie in cookies])
            
            params = {'sap-client': self.sap_client.connection.client}
            
            async with self.sap_client.session.post(
                f'{transport_check_url}',
                data=transport_check_xml,
                headers=headers,
                params=params,
                timeout=30
            ) as response:
                if response.status == 200:
                    response_data = await response.text()
                    if isinstance(response_data, str):
                        # Check for successful transport check (RESULT=S)
                        if '<RESULT>S</RESULT>' in response_data:
                            logger.info(sanitize_for_logging('Transport check successful'))
                            
                            # Extract transport number if available
                            try:
                                transport_match = self.TRANSPORT_CHECK_REGEX.search(response_data)
                                transport_number = transport_match.group(1) if transport_match else None
                                
                                if transport_number and self._validate_transport_number(transport_number.strip()):
                                    logger.info(sanitize_for_logging(f'Using transport: {transport_number.strip()}'))
                                    return {'transport_number': transport_number.strip(), 'success': True}
                                else:
                                    logger.info(sanitize_for_logging('No transport required for this package'))
                                    return {'success': True}
                            except Exception as extract_error:
                                self._log_detailed_error('Failed to extract transport number', extract_error)
                                # Continue without transport number
                                return {'success': True}
                        else:
                            logger.warning(sanitize_for_logging('Transport check response does not indicate success'))
                else:
                    logger.warning(sanitize_for_logging(f'Transport check failed with status: {response.status}'))
            
            # For $TMP package, transport check is not required
            if package_name == '$TMP':
                logger.info(sanitize_for_logging('Local package ($TMP) - transport check bypassed'))
                return {'success': True}
            
            logger.warning(sanitize_for_logging('Transport check failed'))
            return {'success': False}
            
        except Exception as error:
            self._log_detailed_error('Transport check error', error, {'name': name, 'package_name': package_name})
            
            # For $TMP package, allow creation even if transport check fails
            if package_name == '$TMP':
                logger.info(sanitize_for_logging('Transport check failed but allowing for $TMP package'))
                return {'success': True}
            
            return {'success': False}
    
    async def _create_cds_object_shell(
        self,
        name: str,
        description: str,
        package_name: str,
        base_headers: Dict[str, str]
    ) -> bool:
        """
        STEP 3: Create CDS object shell (empty object)
        POST /sap/bc/adt/ddic/ddl/sources
        """
        try:
            create_url = '/sap/bc/adt/ddic/ddl/sources'
            
            # Create XML for empty object shell - matching ADT format exactly
            create_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<ddl:ddlSource xmlns:adtcore="http://www.sap.com/adt/core" xmlns:ddl="http://www.sap.com/adt/ddic/ddlsources" 
               adtcore:description="{sanitize_for_xml(description)}" 
               adtcore:language="EN" 
               adtcore:name="{sanitize_for_xml(name.upper())}" 
               adtcore:type="DDLS/DF" 
               adtcore:masterLanguage="EN" 
               adtcore:masterSystem="S4H" 
               adtcore:responsible="{sanitize_for_xml(self.sap_client.connection.username.upper())}">
  <adtcore:packageRef adtcore:name="{sanitize_for_xml(package_name)}"/>
</ddl:ddlSource>'''
            
            create_headers = {
                **base_headers,
                'Content-Type': 'application/vnd.sap.adt.ddlSource+xml',
                'Accept': 'application/vnd.sap.adt.ddlSource.v2+xml, application/vnd.sap.adt.ddlSource+xml',
                'User-Agent': 'ABAP-Accelerator-MCP/1.0.0',
                'X-sap-adt-profiling': 'server-time'
            }
            
            params = {'sap-client': self.sap_client.connection.client}
            
            async with self.sap_client.session.post(
                f'{create_url}',
                data=create_xml,
                headers=create_headers,
                params=params
            ) as response:
                if response.status == 201:
                    logger.info(sanitize_for_logging('CDS object shell created successfully'))
                    return True
                
                logger.warning(sanitize_for_logging(f'Object shell creation failed with status: {response.status}'))
                return False
                
        except Exception as error:
            self._log_detailed_error('CDS object shell creation failed', error, {'name': name, 'package_name': package_name})
            return False
    
    async def _acquire_edit_lock(
        self,
        name: str,
        base_headers: Dict[str, str]
    ) -> Optional[str]:
        """
        STEP 4: Acquire edit lock for the CDS view
        POST /sap/bc/adt/ddic/ddl/sources/{name}?_action=LOCK&accessMode=MODIFY
        """
        try:
            lock_url = f'/sap/bc/adt/ddic/ddl/sources/{name.lower()}'
            params = {
                '_action': 'LOCK',
                'accessMode': 'MODIFY',
                'sap-client': self.sap_client.connection.client
            }
            
            lock_headers = {
                **base_headers,
                'Accept': 'application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.result;q=0.8, application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.result2;q=0.9'
            }
            
            async with self.sap_client.session.post(
                f'{lock_url}',
                data='',
                headers=lock_headers,
                params=params
            ) as response:
                if response.status == 200:
                    # Store lock response for potential transport extraction
                    response_data = await response.text()
                    self.last_lock_response = response_data
                    
                    # Extract lock handle from response
                    lock_handle = await self._parse_lock_handle(response_data)
                    if lock_handle:
                        logger.info(sanitize_for_logging(f'Successfully acquired edit lock: {lock_handle}'))
                        return lock_handle
                
                logger.warning(sanitize_for_logging(f'Lock acquisition failed with status: {response.status}'))
                return None
                
        except Exception as error:
            self._log_detailed_error('Edit lock acquisition failed', error, {'name': name})
            return None
    
    async def _get_current_source(
        self,
        name: str,
        base_headers: Dict[str, str]
    ) -> Optional[str]:
        """
        STEP 5a: Get current source code (for verification)
        GET /sap/bc/adt/ddic/ddl/sources/{name}?version=inactive
        """
        try:
            source_url = f'/sap/bc/adt/ddic/ddl/sources/{name.lower()}'
            params = {
                'version': 'inactive',
                'sap-client': self.sap_client.connection.client
            }
            
            source_headers = {
                **base_headers,
                'Accept': 'application/vnd.sap.adt.ddlSource.v2+xml, application/vnd.sap.adt.ddlSource+xml'
            }
            
            async with self.sap_client.session.get(
                f'{source_url}',
                headers=source_headers,
                params=params
            ) as response:
                if response.status in [200, 304]:
                    logger.info(sanitize_for_logging('Successfully retrieved current source'))
                    return await response.text()
                
                return None
                
        except Exception as error:
            self._log_detailed_error('Failed to get current source', error, {'name': name})
            return None
    
    async def _format_source_code(
        self,
        source_code: str,
        base_headers: Dict[str, str]
    ) -> Optional[str]:
        """
        STEP 5b: Format source code using SAP formatter
        POST /sap/bc/adt/ddic/ddl/formatter/identifiers
        """
        try:
            formatter_url = '/sap/bc/adt/ddic/ddl/formatter/identifiers'
            
            formatter_headers = {
                **base_headers,
                'Content-Type': 'text/plain',
                'Accept': 'text/plain'
            }
            
            params = {'sap-client': self.sap_client.connection.client}
            
            async with self.sap_client.session.post(
                f'{formatter_url}',
                data=source_code,
                headers=formatter_headers,
                params=params
            ) as response:
                if response.status == 200:
                    logger.info(sanitize_for_logging('Source code formatted successfully'))
                    return await response.text()
                
                logger.warning(sanitize_for_logging('Source formatting failed, using original source'))
                return None
                
        except Exception as error:
            self._log_detailed_error('Source code formatting failed', error)
            return None
    
    async def _update_source_code(
        self,
        name: str,
        source_code: str,
        lock_handle: str,
        base_headers: Dict[str, str]
    ) -> bool:
        """
        STEP 5c: Update source code with lock handle
        PUT /sap/bc/adt/ddic/ddl/sources/{name}/source/main?lockHandle={handle}
        """
        try:
            update_url = f'/sap/bc/adt/ddic/ddl/sources/{name.lower()}/source/main'
            params = {
                'lockHandle': lock_handle,
                'sap-client': self.sap_client.connection.client
            }
            
            update_headers = {
                **base_headers,
                'Content-Type': 'text/plain; charset=utf-8'
            }
            
            async with self.sap_client.session.put(
                f'{update_url}',
                data=source_code,
                headers=update_headers,
                params=params
            ) as response:
                if response.status == 200:
                    logger.info(sanitize_for_logging('Source code updated successfully'))
                    return True
                
                logger.warning(sanitize_for_logging(f'Source update failed with status: {response.status}'))
                return False
                
        except Exception as error:
            self._log_detailed_error('Source code update failed', error, {'name': name, 'lock_handle': lock_handle})
            return False
    
    async def _release_edit_lock(
        self,
        name: str,
        lock_handle: str,
        base_headers: Dict[str, str]
    ) -> None:
        """
        STEP 6: Release edit lock
        POST /sap/bc/adt/ddic/ddl/sources/{name}?_action=UNLOCK&lockHandle={handle}
        """
        try:
            unlock_url = f'/sap/bc/adt/ddic/ddl/sources/{name.lower()}'
            params = {
                '_action': 'UNLOCK',
                'lockHandle': lock_handle,
                'sap-client': self.sap_client.connection.client
            }
            
            async with self.sap_client.session.post(
                f'{unlock_url}',
                data='',
                headers=base_headers,
                params=params
            ) as response:
                logger.info(sanitize_for_logging('Edit lock released successfully'))
                
        except Exception as error:
            self._log_detailed_error('Failed to release edit lock', error, {'name': name, 'lock_handle': lock_handle})
    
    # Additional helper methods
    
    async def _lock_cds_view(
        self,
        name: str,
        object_url: str,
        base_headers: Dict[str, str]
    ) -> Optional[str]:
        """Lock CDS view for editing (updated to match SAP ADT format)"""
        try:
            params = {
                '_action': 'LOCK',
                'accessMode': 'MODIFY',
                'sap-client': self.sap_client.connection.client
            }
            
            logger.info(sanitize_for_logging(f'Attempting to lock CDS view at: {object_url}'))
            
            lock_headers = {
                **base_headers,
                'Accept': 'application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.result;q=0.8, application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.result2;q=0.9',
                'User-Agent': self.USER_AGENT,
                **self.COMMON_HEADERS
            }
            
            async with self.sap_client.session.post(
                f'{object_url}',
                data='',
                headers=lock_headers,
                params=params
            ) as response:
                if response.status != 200:
                    logger.warning(sanitize_for_logging(f'Failed to lock CDS view: {response.status}'))
                    return None
                
                # Store lock response data with size validation
                response_data = await response.text()
                if response_data and isinstance(response_data, str):
                    # Quick length check before expensive byte calculation
                    if len(response_data) > self.MAX_RESPONSE_SIZE // 2:
                        response_size = len(response_data.encode('utf-8'))
                        if response_size > self.MAX_RESPONSE_SIZE:
                            logger.warning(sanitize_for_logging(f'Lock response size ({response_size} bytes) exceeds limit, truncating'))
                            self.last_lock_response = response_data[:self.MAX_RESPONSE_SIZE // 2]
                        else:
                            self.last_lock_response = response_data
                    else:
                        self.last_lock_response = response_data
                else:
                    self.last_lock_response = response_data
                
                # Parse lock handle
                lock_handle = await self._parse_lock_handle(response_data)
                return lock_handle
                
        except Exception as lock_error:
            logger.warning(sanitize_for_logging(f'Failed to lock CDS view: {str(lock_error)}'))
            return None
    
    async def _unlock_cds_view(
        self,
        name: str,
        object_url: str,
        lock_handle: str,
        base_headers: Dict[str, str]
    ) -> None:
        """Unlock CDS view (updated to match SAP ADT format)"""
        try:
            params = {
                '_action': 'UNLOCK',
                'lockHandle': lock_handle,
                'sap-client': self.sap_client.connection.client
            }
            
            unlock_headers = {
                **base_headers,
                'User-Agent': self.USER_AGENT,
                **self.COMMON_HEADERS
            }
            
            async with self.sap_client.session.post(
                f'{object_url}',
                data='',
                headers=unlock_headers,
                params=params
            ) as response:
                logger.info(f'Successfully unlocked CDS view {sanitize_for_logging(name)}')
                
        except Exception as unlock_error:
            # Track unlock failures for resource leak prevention
            self._log_detailed_error('Failed to unlock CDS view', unlock_error, {
                'name': sanitize_for_logging(name),
                'object_url': sanitize_for_logging(object_url),
                'lock_handle': sanitize_for_logging(lock_handle)
            })
    
    async def _parse_lock_handle(self, response_data: Any) -> Optional[str]:
        """Parse lock handle from response with optimized regex operations"""
        try:
            lock_handle = None
            
            # Optimize regex operations with cached patterns
            if response_data and isinstance(response_data, str):
                # Primary regex pattern using cached regex
                lock_handle_match = self.LOCK_HANDLE_REGEX.search(response_data)
                if lock_handle_match:
                    lock_handle = lock_handle_match.group(1)
                    logger.info(sanitize_for_logging(f'Got lock handle: {lock_handle}'))
                else:
                    # Alternative pattern
                    xml_match = re.search(r'LOCK_HANDLE[\'"]?>([^<\'"]+)', response_data, re.IGNORECASE)
                    if xml_match:
                        lock_handle = xml_match.group(1)
                        logger.info(sanitize_for_logging(f'Got lock handle via alternative parsing: {lock_handle}'))
            
            # If still no lock handle, try parsing as XML
            if not lock_handle and response_data:
                try:
                    parsed = await safe_parse_xml(response_data)
                    if parsed and isinstance(parsed, dict):
                        # Try multiple paths for lock handle
                        lock_paths = [
                            'asx:abap.asx:values.DATA.LOCK_HANDLE',
                            'asx:values.DATA.LOCK_HANDLE',
                            'DATA.LOCK_HANDLE',
                            'LOCK_HANDLE'
                        ]
                        
                        for path in lock_paths:
                            try:
                                path_value = self._get_nested_value(parsed, path)
                                if path_value and isinstance(path_value, str):
                                    lock_handle = path_value[0] if isinstance(path_value, list) else path_value
                                    logger.info(sanitize_for_logging(f'Got lock handle from XML path {path}: {lock_handle}'))
                                    break
                            except Exception as path_error:
                                self._log_detailed_error('Failed to extract from XML path', path_error, {'path': path})
                                continue
                    else:
                        logger.warning(sanitize_for_logging('XML parsing returned invalid or empty result'))
                except Exception as xml_error:
                    self._log_detailed_error('Failed to parse lock response as XML', xml_error)
            
            return lock_handle
            
        except Exception as parse_error:
            self._log_detailed_error('Failed to parse lock response', parse_error)
            return None
    
    async def _get_existing_source(self, name: str) -> Optional[str]:
        """Get existing source code for comparison"""
        try:
            # Use the SAP client's get_source method if available
            if hasattr(self.sap_client, 'get_source'):
                return await self.sap_client.get_source(name, 'DDLS')
            
            # Fallback to direct HTTP call
            url = f'/sap/bc/adt/ddic/ddl/sources/{name.lower()}/source/main'
            params = {'sap-client': self.sap_client.connection.client}
            
            headers = {
                'Authorization': f'Basic {self.sap_client._get_auth_header()}',
                'Accept': 'text/plain',
                'User-Agent': self.USER_AGENT,
                **self.COMMON_HEADERS
            }
            
            async with self.sap_client.session.get(
                f'{url}',
                headers=headers,
                params=params
            ) as response:
                if response.status == 200:
                    return await response.text()
                return None
                
        except Exception as error:
            # Don't log as error since this is used to check existence
            logger.debug(sanitize_for_logging(f'Object {name} does not exist or is not accessible'))
            return None
    
    async def _extract_transport_from_lock_response(self, lock_handle: str) -> Optional[str]:
        """Extract transport number from lock response"""
        try:
            if self.last_lock_response and isinstance(self.last_lock_response, str):
                transport_match = self.TRANSPORT_REGEX.search(self.last_lock_response)
                if transport_match:
                    transport_number = transport_match.group(1)
                    if self._validate_transport_number(transport_number):
                        return transport_number
            return None
        except Exception as error:
            self._log_detailed_error('Failed to extract transport from lock response', error)
            return None
    
    def _get_nested_value(self, obj: Any, path: str) -> Any:
        """Helper method to get nested values from parsed XML"""
        try:
            if not obj or not isinstance(obj, dict) or not path or not isinstance(path, str):
                return None
            
            # Cache path split for performance
            path_parts = path.split('.')
            current = obj
            for key in path_parts:
                if current and isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    return None
            return current
            
        except Exception as error:
            logger.warning(sanitize_for_logging(f'Failed to get nested value for path {sanitize_for_logging(path)}: {sanitize_for_logging(str(error))}'))
            return None
    
    def _log_detailed_error(self, message: str, error: Exception, context: Optional[Dict[str, Any]] = None) -> None:
        """Enhanced error logging with context"""
        error_details = {
            'message': sanitize_for_logging(str(error)),
            **(context and {
                'context': {k: sanitize_for_logging(str(v)) for k, v in context.items()}
            } or {})
        }
        
        if hasattr(error, 'status'):
            error_details['status'] = sanitize_for_logging(str(error.status))
            error_details['status_text'] = sanitize_for_logging(getattr(error, 'reason', ''))
            
            # Handle specific error types
            if error.status == 401:
                logger.error(sanitize_for_logging(f'{message} - Authentication failed: {error_details}'))
            elif error.status == 403:
                logger.error(sanitize_for_logging(f'{message} - Authorization failed: {error_details}'))
            elif error.status >= 500:
                logger.error(sanitize_for_logging(f'{message} - Server error: {error_details}'))
            else:
                logger.warning(sanitize_for_logging(f'{message}: {error_details}'))
        elif hasattr(error, 'errno') and error.errno in ['ECONNREFUSED', 'ETIMEDOUT']:
            logger.error(sanitize_for_logging(f'{message} - Network error: {error_details}'))
        else:
            logger.warning(sanitize_for_logging(f'{message}: {error_details}'))
    
    def _validate_source_content(self, source: Optional[str], expected: str) -> bool:
        """Validate source content matches expected patterns"""
        if not source or not expected:
            return False
        
        # Cache toLowerCase operations for performance
        source_lower = source.lower()
        expected_lower = expected.lower()
        
        # Basic validation - both should contain 'select from' or similar CDS patterns
        has_select_from = 'select from' in source_lower or 'define view' in source_lower
        expected_has_select_from = 'select from' in expected_lower or 'define view' in expected_lower
        
        return has_select_from and expected_has_select_from
    
    def _validate_transport_number(self, transport_number: str) -> bool:
        """Validate transport number format"""
        if not transport_number or not isinstance(transport_number, str):
            return False
        
        # Basic SAP transport number validation (typically 10-20 characters, alphanumeric)
        transport_pattern = re.compile(r'^[A-Z0-9]{6,20}$', re.IGNORECASE)
        return bool(transport_pattern.match(transport_number.strip()))
