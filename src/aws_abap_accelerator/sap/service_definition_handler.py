"""
Service Definition Handler for SAP ADT Client - Python implementation
Follows the TypeScript service definition creation pattern
"""

import logging
from typing import Optional, Dict, Any
from urllib.parse import quote

from utils.security import sanitize_for_logging, sanitize_for_xml, validate_object_name
from utils.xml_utils import safe_parse_xml

logger = logging.getLogger(__name__)


class ServiceDefinitionHandler:
    """Handler for Service Definitions following SAP ADT workflow"""
    
    # Constants matching TypeScript version
    USER_AGENT = 'Eclipse/4.37.0.v20250905-0730 (win32; x86_64; Java 21.0.8) ADT/3.52.0 (devedition)'
    
    def __init__(self, sap_client):
        """Initialize Service Definition handler with SAP client reference"""
        self.sap_client = sap_client
    
    async def create_service_definition(
        self,
        name: str,
        description: str,
        package_name: str,
        source_code: str = ""
    ) -> bool:
        """
        Create a Service Definition (SRVD) following TypeScript pattern:
        1. Create object with proper XML format
        2. Update source code if provided
        3. Activate object
        """
        # Input validation
        if not validate_object_name(name):
            logger.error(sanitize_for_logging('Invalid Service Definition name provided'))
            return False
        if not description or not isinstance(description, str):
            logger.error(sanitize_for_logging('Service Definition description is required and must be a string'))
            return False
        if not package_name or not isinstance(package_name, str):
            logger.error(sanitize_for_logging('Package name is required and must be a string'))
            return False
        
        try:
            logger.info(sanitize_for_logging(f'Creating Service Definition {name} with special handling'))
            
            # Step 1: Build Service Definition XML (matching TypeScript format exactly)
            object_xml = self._build_service_definition_xml(name, description, package_name)
            
            # Step 2: Create the service definition
            url = f'/sap/bc/adt/ddic/srvd/sources?sap-client={self.sap_client.connection.client}'
            
            logger.info(sanitize_for_logging(f'Creating Service Definition at URL: {url}'))
            logger.info(sanitize_for_logging(f'Service Definition XML: {object_xml}'))
            
            headers = await self.sap_client._get_appropriate_headers()
            headers.update({
                'Content-Type': 'application/vnd.sap.adt.ddic.srvd.v1+xml',
                'Accept': 'application/vnd.sap.adt.ddic.srvd.v1+xml',
                'User-Agent': self.USER_AGENT
            })
            
            async with self.sap_client.session.post(
                f'{url}',
                data=object_xml,
                headers=headers
            ) as response:
                logger.info(sanitize_for_logging(f'Service Definition creation response status: {response.status}'))
                
                basic_success = response.status in [201, 200]
                
                if not basic_success:
                    # Check if object already exists
                    if response.status == 400:
                        response_text = await response.text()
                        logger.info(sanitize_for_logging(f'Service Definition creation failed, checking response: {response_text[:200]}'))
                        
                        if ('does already exist' in response_text.lower() or 
                            'already exists' in response_text.lower() or
                            'duplicate' in response_text.lower() or
                            'object already exists' in response_text.lower()):
                            logger.info(sanitize_for_logging(f'Service Definition {name} already exists, treating as success'))
                            basic_success = True
                    
                    if not basic_success:
                        logger.error(sanitize_for_logging(f'Service Definition creation failed with status: {response.status}'))
                        response_text = await response.text()
                        logger.error(sanitize_for_logging(f'Response: {response_text[:500]}'))
                        return False
                
                logger.info(sanitize_for_logging(f'Service Definition {name} created successfully'))
                
                # Step 3: If source code is provided, update it
                if source_code and source_code.strip():
                    logger.info(sanitize_for_logging('Updating Service Definition source code'))
                    source_update_success = await self._update_service_definition_source(name, source_code)
                    
                    if source_update_success:
                        logger.info(sanitize_for_logging('Service Definition source updated successfully'))
                        
                        # Step 4: Try to activate the service definition
                        activation_success = await self._activate_service_definition(name)
                        if activation_success:
                            logger.info(sanitize_for_logging('Service Definition activated successfully'))
                        else:
                            logger.warning(sanitize_for_logging('Service Definition activation failed, but object exists'))
                    else:
                        logger.warning(sanitize_for_logging('Service Definition source update failed'))
                        # Don't return false here - the object was created, just source update failed
                
                return True
                
        except Exception as error:
            logger.error(sanitize_for_logging(f'Service Definition creation error: {str(error)}'))
            
            # Check if it's an "already exists" error
            error_text = str(error).lower()
            if ('does already exist' in error_text or 
                'already exists' in error_text or
                'duplicate' in error_text or
                'object already exists' in error_text):
                logger.info(sanitize_for_logging(f'Service Definition {name} already exists, treating as success'))
                return True
            
            return False
    
    def _build_service_definition_xml(
        self,
        name: str,
        description: str,
        package_name: str
    ) -> str:
        """Build Service Definition XML matching TypeScript format exactly"""
        safe_name = sanitize_for_xml(name)
        safe_description = sanitize_for_xml(description)
        safe_package = sanitize_for_xml(package_name)
        safe_username = sanitize_for_xml(self.sap_client.connection.username)
        
        # Use the correct XML format from TypeScript (srvdSource, not serviceDefinition)
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<srvd:srvdSource xmlns:adtcore="http://www.sap.com/adt/core" xmlns:srvd="http://www.sap.com/adt/ddic/srvdsources" adtcore:description="{safe_description}" adtcore:language="EN" adtcore:name="{safe_name}" adtcore:type="SRVD/SRV" adtcore:masterLanguage="EN" adtcore:masterSystem="S4H" adtcore:responsible="{safe_username}" srvd:srvdSourceType="S">
  <adtcore:packageRef adtcore:name="{safe_package}"/>
</srvd:srvdSource>'''
    
    async def _update_service_definition_source(
        self,
        name: str,
        source_code: str
    ) -> bool:
        """Update Service Definition source code"""
        try:
            # Use the SAP client's update source method
            if hasattr(self.sap_client, 'update_source_with_syntax_check'):
                result = await self.sap_client.update_source_with_syntax_check(name, 'SRVD', source_code)
                return result.updated
            else:
                # Fallback to basic source update
                return await self._basic_source_update(name, source_code)
                
        except Exception as error:
            logger.error(sanitize_for_logging(f'Error updating Service Definition source: {str(error)}'))
            return False
    
    async def _basic_source_update(
        self,
        name: str,
        source_code: str
    ) -> bool:
        """Basic source update implementation matching TypeScript workflow"""
        try:
            logger.info(sanitize_for_logging(f'Updating Service Definition source for {name}'))
            
            resource_uri = f'/sap/bc/adt/ddic/srvd/sources/{name}'
            
            # Try to lock the object first (matching TypeScript approach)
            lock_info = await self._try_lock_object(resource_uri)
            
            if not lock_info:
                logger.info(sanitize_for_logging(f'Could not lock Service Definition {name}, trying without lock'))
                # Try without lock for $TMP objects
                return await self._update_source_without_lock(resource_uri, source_code)
            
            try:
                # Update with lock
                return await self._update_source_with_lock(resource_uri, source_code, lock_info)
            finally:
                # Always unlock
                await self._unlock_object(resource_uri, lock_info.get('LOCK_HANDLE'))
                
        except Exception as error:
            logger.error(sanitize_for_logging(f'Failed to update Service Definition source: {str(error)}'))
            return False
    
    async def _try_lock_object(self, resource_uri: str) -> Optional[Dict[str, str]]:
        """Try to lock the object for editing"""
        try:
            lock_url = f'{resource_uri}?_action=LOCK&accessMode=MODIFY'
            params = {'sap-client': self.sap_client.connection.client}
            
            headers = await self.sap_client._get_appropriate_headers()
            headers['Accept'] = 'application/vnd.sap.as+xml'
            
            async with self.sap_client.session.post(
                f'{lock_url}',
                data='',
                headers=headers,
                params=params
            ) as response:
                if response.status == 200:
                    response_data = await response.text()
                    # Parse lock handle and transport number
                    lock_handle = self._extract_lock_handle(response_data)
                    transport_number = self._extract_transport_number(response_data)
                    
                    if lock_handle:
                        return {
                            'LOCK_HANDLE': lock_handle,
                            'CORRNR': transport_number
                        }
                
                return None
                
        except Exception as error:
            logger.warning(sanitize_for_logging(f'Failed to lock object: {str(error)}'))
            return None
    
    async def _update_source_without_lock(self, resource_uri: str, source_code: str) -> bool:
        """Update source without lock (for $TMP objects)"""
        try:
            source_url = f'{resource_uri}/source/main'
            params = {'sap-client': self.sap_client.connection.client}
            
            headers = await self.sap_client._get_appropriate_headers()
            headers.update({
                'Content-Type': 'text/plain; charset=utf-8',
                'Accept': 'text/plain',
                'User-Agent': self.USER_AGENT
            })
            
            async with self.sap_client.session.put(
                f'{source_url}',
                data=source_code,
                headers=headers,
                params=params
            ) as response:
                success = response.status in [200, 204]
                
                if success:
                    logger.info(sanitize_for_logging('Service Definition source updated successfully without lock'))
                else:
                    logger.error(sanitize_for_logging(f'Service Definition source update failed with status: {response.status}'))
                
                return success
                
        except Exception as error:
            logger.error(sanitize_for_logging(f'Service Definition source update without lock failed: {str(error)}'))
            return False
    
    async def _update_source_with_lock(self, resource_uri: str, source_code: str, lock_info: Dict[str, str]) -> bool:
        """Update source with lock"""
        try:
            source_url = f'{resource_uri}/source/main'
            params = {
                'sap-client': self.sap_client.connection.client,
                'lockHandle': lock_info['LOCK_HANDLE']
            }
            
            if lock_info.get('CORRNR'):
                params['corrNr'] = lock_info['CORRNR']
            
            headers = await self.sap_client._get_appropriate_headers()
            headers.update({
                'Content-Type': 'text/plain; charset=utf-8',
                'Accept': 'text/plain',
                'User-Agent': self.USER_AGENT
            })
            
            async with self.sap_client.session.put(
                f'{source_url}',
                data=source_code,
                headers=headers,
                params=params
            ) as response:
                success = response.status in [200, 204]
                
                if success:
                    logger.info(sanitize_for_logging('Service Definition source updated successfully'))
                else:
                    logger.error(sanitize_for_logging(f'Service Definition source update failed with status: {response.status}'))
                
                return success
                
        except Exception as error:
            logger.error(sanitize_for_logging(f'Service Definition source update with lock failed: {str(error)}'))
            return False
    
    async def _unlock_object(self, resource_uri: str, lock_handle: str) -> None:
        """Unlock the object"""
        try:
            if not lock_handle:
                return
                
            unlock_url = f'{resource_uri}?_action=UNLOCK&lockHandle={lock_handle}'
            params = {'sap-client': self.sap_client.connection.client}
            
            headers = await self.sap_client._get_appropriate_headers()
            
            async with self.sap_client.session.post(
                f'{unlock_url}',
                data='',
                headers=headers,
                params=params
            ) as response:
                logger.info(sanitize_for_logging('Object unlocked successfully'))
                
        except Exception as error:
            logger.warning(sanitize_for_logging(f'Failed to unlock object: {str(error)}'))
    
    def _extract_lock_handle(self, response_data: str) -> Optional[str]:
        """Extract lock handle from response"""
        import re
        try:
            match = re.search(r'<LOCK_HANDLE>([^<]+)</LOCK_HANDLE>', response_data)
            return match.group(1) if match else None
        except Exception:
            return None
    
    def _extract_transport_number(self, response_data: str) -> Optional[str]:
        """Extract transport number from response"""
        import re
        try:
            match = re.search(r'<CORRNR>([^<]+)</CORRNR>', response_data)
            return match.group(1) if match else None
        except Exception:
            return None
    
    async def _activate_service_definition(
        self,
        name: str
    ) -> bool:
        """Activate Service Definition"""
        try:
            # Use the SAP client's activation method if available
            if hasattr(self.sap_client, 'activate_object'):
                return await self.sap_client.activate_object(name, 'SRVD')
            else:
                # Fallback to basic activation
                return await self._basic_activation(name)
                
        except Exception as error:
            logger.error(sanitize_for_logging(f'Error activating Service Definition: {str(error)}'))
            return False
    
    async def _basic_activation(
        self,
        name: str
    ) -> bool:
        """Basic activation implementation"""
        try:
            # Build activation XML
            activation_uri = f'/sap/bc/adt/ddic/srvd/sources/{name.lower()}'
            activation_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<adtcore:objectReferences xmlns:adtcore="http://www.sap.com/adt/core">
  <adtcore:objectReference adtcore:uri="{activation_uri}" adtcore:name="{name.upper()}"/>
</adtcore:objectReferences>'''
            
            url = '/sap/bc/adt/activation'
            params = {
                'method': 'activate',
                'preauditRequested': 'true',
                'sap-client': self.sap_client.connection.client
            }
            
            headers = await self.sap_client._get_appropriate_headers()
            headers.update({
                'Content-Type': 'application/xml',
                'Accept': 'application/xml',
                'User-Agent': self.USER_AGENT
            })
            
            async with self.sap_client.session.post(
                f'{url}',
                data=activation_xml,
                headers=headers,
                params=params
            ) as response:
                if response.status == 200:
                    response_data = await response.text()
                    if 'activationExecuted="true"' in response_data:
                        logger.info(sanitize_for_logging(f'Service Definition {name} activated successfully'))
                        return True
                    else:
                        logger.warning(sanitize_for_logging('Activation response indicates failure'))
                        return False
                else:
                    logger.warning(sanitize_for_logging(f'Activation failed with status: {response.status}'))
                    return False
                    
        except Exception as error:
            logger.error(sanitize_for_logging(f'Basic activation failed: {str(error)}'))
            return False
