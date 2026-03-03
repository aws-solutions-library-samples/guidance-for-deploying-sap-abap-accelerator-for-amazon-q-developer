"""
Behavior Definition Handler for SAP ADT Client - Python implementation
Follows the TypeScript BdefHandler pattern for creating BDEF objects
"""

import logging
from typing import Optional, Dict, Any
from urllib.parse import quote

from utils.security import sanitize_for_logging, sanitize_for_xml, validate_object_name

logger = logging.getLogger(__name__)


class BehaviorDefinitionHandler:
    """Handler for Behavior Definition (BDEF) objects following SAP ADT workflow"""
    
    def __init__(self, sap_client):
        """Initialize behavior definition handler with SAP client reference"""
        self.sap_client = sap_client
    
    async def create_behavior_definition(
        self,
        name: str,
        description: str,
        package_name: str,
        implementation_type: str = 'Managed'
    ) -> bool:
        """
        Create a Behavior Definition following SAP ADT workflow:
        1. Validation - Check object name and parameters
        2. Creation - Create BDEF object with proper XML template
        """
        try:
            # Validate and sanitize inputs
            if not validate_object_name(name):
                logger.error(sanitize_for_logging('Invalid behavior definition name provided'))
                return False
            
            safe_name = name
            safe_description = sanitize_for_xml(description)
            safe_package_name = sanitize_for_xml(package_name)
            safe_implementation_type = implementation_type if implementation_type in ['Managed', 'Unmanaged'] else 'Managed'
            
            logger.info(f'Creating behavior definition {sanitize_for_logging(safe_name)} with {sanitize_for_logging(safe_implementation_type)} implementation')
            
            # Step 1: Validation
            validation_success = await self._perform_validation(
                safe_name, safe_description, safe_package_name, safe_implementation_type
            )
            if not validation_success:
                logger.error(sanitize_for_logging('Behavior definition validation failed'))
                return False
            
            # Step 2: Creation
            creation_success = await self._create_bdef_object(
                safe_name, safe_description, safe_package_name, safe_implementation_type
            )
            
            if creation_success:
                logger.info(sanitize_for_logging(f'Successfully created behavior definition {safe_name}'))
                return True
            else:
                logger.error(sanitize_for_logging('Behavior definition creation failed'))
                return False
                
        except Exception as error:
            logger.error(sanitize_for_logging(f'Error creating behavior definition: {str(error)}'))
            return False
    
    async def _perform_validation(
        self,
        name: str,
        description: str,
        package_name: str,
        implementation_type: str
    ) -> bool:
        """
        Step 1: Perform validation of behavior definition parameters
        POST /sap/bc/adt/bo/behaviordefinitions/validation
        """
        try:
            validation_url = '/sap/bc/adt/bo/behaviordefinitions/validation'
            params = {
                'objname': name,
                'rootEntity': name,
                'description': quote(description),
                'package': quote(package_name),
                'implementationType': implementation_type,
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
                    logger.info(sanitize_for_logging('Behavior definition validation successful'))
                    return True
                else:
                    logger.warning(sanitize_for_logging(f'Validation failed with status: {response.status}'))
                    return False
                    
        except Exception as error:
            logger.error(sanitize_for_logging(f'Behavior definition validation failed: {str(error)}'))
            return False
    
    async def _create_bdef_object(
        self,
        name: str,
        description: str,
        package_name: str,
        implementation_type: str
    ) -> bool:
        """
        Step 2: Create the behavior definition object
        POST /sap/bc/adt/bo/behaviordefinitions
        """
        try:
            create_url = '/sap/bc/adt/bo/behaviordefinitions'
            
            # Build BDEF XML exactly as shown in TypeScript version
            bdef_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<blue:blueSource xmlns:adtcore="http://www.sap.com/adt/core" xmlns:blue="http://www.sap.com/wbobj/blue" 
                 adtcore:description="{description}" 
                 adtcore:language="EN" 
                 adtcore:name="{name}" 
                 adtcore:type="BDEF/BDO" 
                 adtcore:masterLanguage="EN" 
                 adtcore:masterSystem="S4H" 
                 adtcore:responsible="{sanitize_for_xml(self.sap_client.connection.username)}">
  <adtcore:adtTemplate>
    <adtcore:adtProperty adtcore:key="implementation_type">{implementation_type}</adtcore:adtProperty>
  </adtcore:adtTemplate>
  <adtcore:packageRef adtcore:name="{package_name}"/>
</blue:blueSource>'''
            
            headers = await self.sap_client._get_appropriate_headers()
            headers.update({
                'Content-Type': 'application/vnd.sap.adt.blues.v1+xml',
                'Accept': 'application/vnd.sap.adt.blues.v1+xml',
                'User-Agent': 'Eclipse/4.35.0.v20250228-0140 (win32; x86_64; Java 21.0.7) ADT/3.50.0 (devedition)',
                'X-sap-adt-profiling': 'server-time'
            })
            
            params = {'sap-client': self.sap_client.connection.client}
            
            async with self.sap_client.session.post(
                f'{create_url}',
                data=bdef_xml,
                headers=headers,
                params=params
            ) as response:
                if response.status == 201:
                    logger.info(sanitize_for_logging('Behavior definition created successfully'))
                    return True
                else:
                    logger.warning(sanitize_for_logging(f'Creation failed with status: {response.status}'))
                    response_text = await response.text()
                    logger.warning(sanitize_for_logging(f'Response: {response_text[:500]}'))
                    return False
                    
        except Exception as error:
            logger.error(sanitize_for_logging(f'Behavior definition creation failed: {str(error)}'))
            return False
