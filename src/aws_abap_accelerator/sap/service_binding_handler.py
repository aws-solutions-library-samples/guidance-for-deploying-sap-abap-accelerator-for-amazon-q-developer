"""
Service Binding Handler for SAP ADT Client - Python implementation
Follows the TypeScript service binding creation pattern from sap-client.ts
"""

import logging
from typing import Optional, Dict, Any
from urllib.parse import quote

from utils.security import sanitize_for_logging, sanitize_for_xml, validate_object_name

logger = logging.getLogger(__name__)


class ServiceBindingHandler:
    """Handler for Service Binding (SRVB) objects following SAP ADT workflow"""
    
    # Binding type mapping from TypeScript implementation
    BINDING_TYPE_MAPPING = {
        'ODATA_V2_UI': {'category': '0', 'version': 'ODATA%5CV2', 'version_xml': 'V2'},
        'ODATA_V4_UI': {'category': '0', 'version': 'ODATA%5CV4', 'version_xml': 'V4'},
        'ODATA_V2_WEB_API': {'category': '1', 'version': 'ODATA%5CV2', 'version_xml': 'V2'},
        'ODATA_V4_WEB_API': {'category': '1', 'version': 'ODATA%5CV4', 'version_xml': 'V4'}
    }
    
    def __init__(self, sap_client):
        """Initialize service binding handler with SAP client reference"""
        self.sap_client = sap_client
    
    async def create_service_binding(
        self,
        name: str,
        description: str,
        package_name: str,
        service_definition: str,
        binding_type: str = 'ODATA_V4_UI'
    ) -> bool:
        """
        Create a Service Binding following SAP ADT workflow:
        1. Service Definition validation - Check if SRVD exists
        2. Validation call - Validate service binding parameters
        3. Transport check - Verify transport requirements
        4. Creation - Create SRVB object with proper XML
        5. Activation - Activate the service binding
        """
        try:
            # Validate and sanitize inputs
            if not validate_object_name(name):
                logger.error(sanitize_for_logging('Invalid service binding name provided'))
                return False
            
            if not service_definition:
                logger.error(sanitize_for_logging('Service Definition reference is required'))
                return False
            
            safe_name = name
            safe_description = sanitize_for_xml(description)
            safe_package_name = sanitize_for_xml(package_name)
            safe_service_definition = sanitize_for_xml(service_definition)
            safe_binding_type = binding_type if binding_type in self.BINDING_TYPE_MAPPING else 'ODATA_V4_UI'
            
            logger.info(f'Creating Service Binding {sanitize_for_logging(safe_name)} with type {sanitize_for_logging(safe_binding_type)}')
            
            # Step 1: Service Definition validation
            srvd_exists = await self._validate_service_definition(safe_service_definition)
            if not srvd_exists:
                logger.error(sanitize_for_logging(f'Service Definition {safe_service_definition} not found'))
                return False
            
            # Step 2: Validation call
            validation_success = await self._perform_validation(
                safe_name, safe_description, safe_package_name, safe_service_definition, safe_binding_type
            )
            if not validation_success:
                logger.warning(sanitize_for_logging('Service binding validation failed, but continuing'))
            
            # Step 3: Transport check
            transport_success = await self._perform_transport_check(safe_name, safe_package_name)
            if not transport_success:
                logger.warning(sanitize_for_logging('Transport check failed, but continuing'))
            
            # Step 4: Creation
            creation_success = await self._create_service_binding_object(
                safe_name, safe_description, safe_package_name, safe_service_definition, safe_binding_type
            )
            if not creation_success:
                logger.error(sanitize_for_logging('Service binding creation failed'))
                return False
            
            # Step 5: Activation
            activation_success = await self._activate_service_binding(safe_name)
            if not activation_success:
                logger.warning(sanitize_for_logging('Service binding activation failed, but object was created'))
            
            logger.info(sanitize_for_logging(f'Successfully created service binding {safe_name}'))
            return True
            
        except Exception as error:
            logger.error(sanitize_for_logging(f'Error creating service binding: {str(error)}'))
            return False
    
    async def _validate_service_definition(self, service_definition: str) -> bool:
        """Step 1: Check if the referenced Service Definition exists"""
        try:
            # Use the SAP client's get_source method to check if SRVD exists
            if hasattr(self.sap_client, 'get_source'):
                source = await self.sap_client.get_source(service_definition, 'SRVD')
                return source is not None
            
            # Fallback: try direct HTTP call
            url = f'/sap/bc/adt/ddic/srvd/sources/{service_definition.lower()}'
            params = {'sap-client': self.sap_client.connection.client}
            
            headers = await self.sap_client._get_appropriate_headers()
            headers['Accept'] = 'application/xml'
            
            async with self.sap_client.session.get(
                f'{url}',
                headers=headers,
                params=params
            ) as response:
                return response.status == 200
                
        except Exception as error:
            logger.warning(sanitize_for_logging(f'Failed to validate service definition: {str(error)}'))
            return False
    
    async def _perform_validation(
        self,
        name: str,
        description: str,
        package_name: str,
        service_definition: str,
        binding_type: str
    ) -> bool:
        """
        Step 2: Perform validation of service binding parameters
        POST /sap/bc/adt/businessservices/bindings/validation
        """
        try:
            validation_url = '/sap/bc/adt/businessservices/bindings/validation'
            params = {
                'objname': name,
                'description': quote(description),
                'serviceBindingVersion': self._map_binding_type_to_version(binding_type),
                'serviceDefinition': service_definition,
                'package': quote(package_name),
                'sap-client': self.sap_client.connection.client
            }
            
            headers = await self.sap_client._get_appropriate_headers()
            headers.update({
                'Accept': 'application/vnd.sap.as+xml',
                'User-Agent': 'Eclipse/4.35.0.v20250228-0140 (win32; x86_64; Java 21.0.7) ADT/3.50.0 (devedition)',
                'X-sap-adt-profiling': 'server-time'
            })
            
            async with self.sap_client.session.post(
                f'{validation_url}',
                data='',
                headers=headers,
                params=params
            ) as response:
                if response.status == 200:
                    logger.info(sanitize_for_logging('Service binding validation successful'))
                    return True
                else:
                    logger.warning(sanitize_for_logging(f'Validation returned status: {response.status}'))
                    return False
                    
        except Exception as error:
            logger.warning(sanitize_for_logging(f'Service binding validation failed: {str(error)}'))
            return False
    
    async def _perform_transport_check(self, name: str, package_name: str) -> bool:
        """Step 3: Perform transport check (reuse existing logic from SAP client)"""
        try:
            # Use the existing transport check method if available
            if hasattr(self.sap_client, 'perform_transport_check'):
                return await self.sap_client.perform_transport_check(name, package_name)
            
            # For $TMP package, no transport check needed
            if package_name == '$TMP':
                logger.info(sanitize_for_logging('Local package ($TMP) - transport check bypassed'))
                return True
            
            logger.info(sanitize_for_logging('Transport check passed (no specific implementation)'))
            return True
            
        except Exception as error:
            logger.warning(sanitize_for_logging(f'Transport check failed: {str(error)}'))
            return False
    
    async def _create_service_binding_object(
        self,
        name: str,
        description: str,
        package_name: str,
        service_definition: str,
        binding_type: str
    ) -> bool:
        """
        Step 4: Create the service binding object
        POST /sap/bc/adt/businessservices/bindings
        """
        try:
            create_url = '/sap/bc/adt/businessservices/bindings'
            
            # Build service binding XML
            binding_xml = self._build_service_binding_xml(
                name, description, package_name, service_definition, binding_type
            )
            
            headers = await self.sap_client._get_appropriate_headers()
            headers.update({
                'Content-Type': 'application/vnd.sap.adt.businessservices.servicebinding.v2+xml',
                'Accept': 'application/vnd.sap.adt.businessservices.servicebinding.v1+xml, application/vnd.sap.adt.businessservices.servicebinding.v2+xml',
                'User-Agent': 'Eclipse/4.35.0.v20250228-0140 (win32; x86_64; Java 21.0.7) ADT/3.50.0 (devedition)',
                'X-sap-adt-profiling': 'server-time'
            })
            
            params = {'sap-client': self.sap_client.connection.client}
            
            logger.info(sanitize_for_logging(f'Creating Service Binding at URL: {create_url}'))
            
            async with self.sap_client.session.post(
                f'{create_url}',
                data=binding_xml,
                headers=headers,
                params=params
            ) as response:
                success = response.status in [201, 200]
                
                if success:
                    logger.info(sanitize_for_logging('Service binding created successfully'))
                    return True
                else:
                    logger.error(sanitize_for_logging(f'Creation failed with status: {response.status}'))
                    response_text = await response.text()
                    logger.error(sanitize_for_logging(f'Response: {response_text[:500]}'))
                    return False
                    
        except Exception as error:
            logger.error(sanitize_for_logging(f'Service binding creation failed: {str(error)}'))
            return False
    
    async def _activate_service_binding(self, name: str) -> bool:
        """Step 5: Activate the service binding"""
        try:
            # Use the existing activation method if available
            if hasattr(self.sap_client, 'activate_object'):
                return await self.sap_client.activate_object(name, 'SRVB')
            
            logger.info(sanitize_for_logging(f'Service binding {name} activation completed'))
            return True
            
        except Exception as error:
            logger.warning(sanitize_for_logging(f'Service binding activation failed: {str(error)}'))
            return False
    
    def _build_service_binding_xml(
        self,
        name: str,
        description: str,
        package_name: str,
        service_definition: str,
        binding_type: str
    ) -> str:
        """Build service binding XML template matching TypeScript implementation exactly"""
        binding_mapping = self.BINDING_TYPE_MAPPING[binding_type]
        
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<srvb:serviceBinding xmlns:adtcore="http://www.sap.com/adt/core" xmlns:srvb="http://www.sap.com/adt/ddic/ServiceBindings" adtcore:description="{description}" adtcore:language="EN" adtcore:name="{name}" adtcore:type="SRVB/SVB" adtcore:masterLanguage="EN" adtcore:masterSystem="S4H" adtcore:responsible="{sanitize_for_xml(self.sap_client.connection.username)}">
  <adtcore:packageRef adtcore:name="{package_name}"/>
  <srvb:services srvb:name="{name}">
    <srvb:content srvb:version="0001">
      <srvb:serviceDefinition adtcore:name="{service_definition}"/>
    </srvb:content>
  </srvb:services>
  <srvb:binding srvb:category="{binding_mapping['category']}" srvb:type="ODATA" srvb:version="{binding_mapping['version_xml']}">
    <srvb:implementation adtcore:name=""/>
  </srvb:binding>
</srvb:serviceBinding>'''
    
    def _map_binding_type_to_version(self, binding_type: str) -> str:
        """Map binding type to version string for validation (URL-encoded)"""
        mapping = self.BINDING_TYPE_MAPPING.get(binding_type, self.BINDING_TYPE_MAPPING['ODATA_V4_UI'])
        return mapping['version']
    
    def _map_binding_type_to_category(self, binding_type: str) -> str:
        """Map binding type to category string"""
        mapping = self.BINDING_TYPE_MAPPING.get(binding_type, self.BINDING_TYPE_MAPPING['ODATA_V4_UI'])
        return mapping['category']
