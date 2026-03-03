"""
SAP Source Code Management Module

This module handles source code operations:
- Updating source code
- Locking/unlocking objects
- Source code validation
"""

from typing import Optional, Tuple, Dict, Any
import logging

from sap_types.sap_types import ObjectOperationResult, SAPSyntaxError
from utils.logger import rap_logger
from utils.security import sanitize_for_logging, sanitize_for_xml
from utils.xml_utils import get_object_url_patterns

logger = logging.getLogger(__name__)


class SAPSourceManager:
    """Manages SAP source code operations"""
    
    def __init__(self, connection_manager, session):
        self.connection_manager = connection_manager
        self.session = session
        self.connection = connection_manager.connection
    
    async def update_source_with_syntax_check(self, object_name: str, object_type: str, 
                                            source_code: str) -> ObjectOperationResult:
        """Update source code with syntax check"""
        try:
            print(f"[SAP-CLIENT] Updating source with syntax check for {sanitize_for_logging(object_name)}")
            
            # Step 1: Update source code
            updated, error_msg = await self._update_source(object_name, object_type, source_code)
            if not updated:
                print(f"[SAP-CLIENT] Source update failed for {sanitize_for_logging(object_name)}: {error_msg}")
                return ObjectOperationResult(
                    updated=False,
                    syntax_check_passed=False,
                    activated=False,
                    errors=[SAPSyntaxError(line=1, message=error_msg or "Failed to update source code", severity="ERROR")],
                    warnings=[]
                )
            
            print(f"[SAP-CLIENT] Source updated successfully, proceeding with activation")
            
            # Step 2: For CDS views, verify source before activation
            if object_type.upper() == 'DDLS':
                return await self._handle_cds_activation(object_name, object_type)
            
            # Step 3: Perform syntax check and activation for non-CDS objects
            from .activation_manager import SAPActivationManager
            activation_manager = SAPActivationManager(self.connection_manager, self.session)
            activation_result = await activation_manager.activate_object_with_details(object_name, object_type)
            
            return ObjectOperationResult(
                updated=True,
                syntax_check_passed=activation_result.success,
                activated=activation_result.activated,
                errors=activation_result.errors,
                warnings=activation_result.warnings
            )
            
        except Exception as e:
            logger.error(f"Error updating source with syntax check: {sanitize_for_logging(str(e))}")
            return ObjectOperationResult(
                updated=False,
                syntax_check_passed=False,
                activated=False,
                errors=[SAPSyntaxError(line=1, message=str(e), severity="ERROR")],
                warnings=[]
            )
    
    async def _handle_cds_activation(self, object_name: str, object_type: str) -> ObjectOperationResult:
        """Handle CDS view activation with verification"""
        from .object_manager import SAPObjectManager
        from .activation_manager import SAPActivationManager
        
        object_manager = SAPObjectManager(self.connection_manager, self.session)
        activation_manager = SAPActivationManager(self.connection_manager, self.session)
        
        verify_source = await object_manager.get_source(object_name, object_type)
        if verify_source and 'select from' in verify_source.lower():
            print(f"[SAP-CLIENT] CDS view source verified, attempting activation")
            activation_result = await activation_manager.activate_object_with_details(object_name, object_type)
            
            return ObjectOperationResult(
                updated=True,
                syntax_check_passed=activation_result.success,
                activated=activation_result.activated,
                errors=activation_result.errors,
                warnings=activation_result.warnings
            )
        else:
            print(f"[SAP-CLIENT] CDS view source not found or invalid after update")
            return ObjectOperationResult(
                updated=False,
                syntax_check_passed=False,
                activated=False,
                errors=[SAPSyntaxError(line=1, message="CDS view source not found or invalid after update", severity="ERROR")],
                warnings=[]
            )
    
    async def _update_source(self, object_name: str, object_type: str, source_code: str) -> Tuple[bool, Optional[str]]:
        """Update source code in SAP system. Returns (success, error_message)"""
        try:
            # Get resource URI for the object
            resource_uri = await self._get_resource_uri(object_name, object_type)
            if not resource_uri:
                return False, f"Could not determine resource URI for {object_name}"
            
            # Check transport requirements
            transport_info = await self._check_transport_requirements(object_name, object_type, resource_uri)
            
            # Try to lock the object
            object_url = f"{resource_uri}/source/main"
            lock_info = await self._lock_object(object_url)
            
            try:
                # Update the source code
                success = await self._perform_source_update(object_url, source_code, lock_info)
                return success, None if success else "Failed to update source code"
                
            finally:
                # Always unlock the object
                if lock_info and 'LOCK_HANDLE' in lock_info:
                    await self._unlock_object(object_url, lock_info['LOCK_HANDLE'])
            
        except Exception as e:
            logger.error(f"Error updating source: {sanitize_for_logging(str(e))}")
            return False, str(e)
    
    async def _perform_source_update(self, object_url: str, source_code: str, lock_info: Optional[Dict[str, str]]) -> bool:
        """Perform the actual source code update"""
        try:
            headers = await self.connection_manager.get_appropriate_headers()
            headers['Content-Type'] = 'text/plain'
            
            # Add lock handle if available
            if lock_info and 'LOCK_HANDLE' in lock_info:
                headers['Lock-Handle'] = lock_info['LOCK_HANDLE']
            
            url = f"{object_url}?sap-client={self.connection.client}"
            
            async with self.session.put(url, data=source_code, headers=headers) as response:
                if response.status == 200:
                    logger.info("Source code updated successfully")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to update source: {response.status} - {sanitize_for_logging(error_text[:500])}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error performing source update: {sanitize_for_logging(str(e))}")
            return False
    
    async def _lock_object(self, object_url: str) -> Optional[Dict[str, str]]:
        """Lock an object for editing - returns lock info with LOCK_HANDLE"""
        try:
            headers = await self.connection_manager.get_appropriate_headers()
            headers['X-sap-adt-sessiontype'] = 'stateful'
            
            url = f"{object_url}?sap-client={self.connection.client}&_action=LOCK"
            
            async with self.session.post(url, headers=headers) as response:
                if response.status == 200:
                    # Extract lock handle from response headers
                    lock_handle = response.headers.get('sap-adt-lock-handle')
                    if lock_handle:
                        logger.info(f"Object locked successfully with handle: {sanitize_for_logging(lock_handle)}")
                        return {'LOCK_HANDLE': lock_handle}
                    else:
                        logger.warning("Object locked but no lock handle received")
                        return {}
                else:
                    logger.warning(f"Failed to lock object: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error locking object: {sanitize_for_logging(str(e))}")
            return None
    
    async def _unlock_object(self, object_url: str, lock_handle: str) -> bool:
        """Unlock an object after editing"""
        try:
            headers = await self.connection_manager.get_appropriate_headers()
            headers['Lock-Handle'] = lock_handle
            
            url = f"{object_url}?sap-client={self.connection.client}&_action=UNLOCK"
            
            async with self.session.post(url, headers=headers) as response:
                if response.status == 200:
                    logger.info("Object unlocked successfully")
                    return True
                else:
                    logger.warning(f"Failed to unlock object: {response.status}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error unlocking object: {sanitize_for_logging(str(e))}")
            return False
    
    async def _check_transport_requirements(self, object_name: str, object_type: str, resource_uri: str) -> Dict[str, Any]:
        """Check transport requirements for an object"""
        try:
            url = f"{resource_uri}?sap-client={self.connection.client}"
            headers = await self.connection_manager.get_appropriate_headers()
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    # Parse transport information from response
                    # This is a simplified version - implement full parsing as needed
                    return {'transport_required': False}
                else:
                    logger.warning(f"Failed to check transport requirements: {response.status}")
                    return {}
                    
        except Exception as e:
            logger.error(f"Error checking transport requirements: {sanitize_for_logging(str(e))}")
            return {}
    
    async def _get_resource_uri(self, object_name: str, object_type: str) -> Optional[str]:
        """Get resource URI for object"""
        # Try to get from object patterns
        url_patterns = get_object_url_patterns(object_type, object_name)
        if url_patterns:
            return f"/sap/bc/adt/{url_patterns[0]}/{object_name}"
        
        return None
    
    async def update_class_source(self, object_name: str, source_code: str) -> Tuple[bool, Optional[str]]:
        """Update class source code with proper locking. Returns (success, error_message)"""
        try:
            logger.info(f"Updating class source for {sanitize_for_logging(object_name)}")
            
            # Check if this is a behavior pool (BIMPL)
            is_bimpl = await self._is_behavior_pool(object_name)
            
            if is_bimpl:
                # For behavior pools, use the implementations include
                resource_uri = f"/sap/bc/adt/oo/classes/{object_name}/includes/implementations"
            else:
                # For regular classes, use the main source
                resource_uri = f"/sap/bc/adt/oo/classes/{object_name}/source/main"
            
            # Lock the object
            lock_info = await self._lock_object(resource_uri)
            
            try:
                # Update source
                success = await self._perform_source_update(resource_uri, source_code, lock_info)
                return success, None if success else "Failed to update class source"
                
            finally:
                # Unlock the object
                if lock_info and 'LOCK_HANDLE' in lock_info:
                    await self._unlock_object(resource_uri, lock_info['LOCK_HANDLE'])
            
        except Exception as e:
            logger.error(f"Error updating class source: {sanitize_for_logging(str(e))}")
            return False, str(e)
    
    async def _is_behavior_pool(self, object_name: str) -> bool:
        """Check if a class is a behavior pool (BIMPL)"""
        try:
            url = f"/sap/bc/adt/oo/classes/{object_name}?sap-client={self.connection.client}"
            headers = await self.connection_manager.get_appropriate_headers()
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    # Check if the class has category="behaviorPool"
                    return 'category="behaviorPool"' in xml_content or 'behaviorPool' in xml_content
                else:
                    logger.warning(f"Failed to check class metadata: {response.status}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error checking if behavior pool: {sanitize_for_logging(str(e))}")
            return False