"""
SAP Object Management Module

This module handles ABAP object operations:
- Getting object lists
- Reading object source code
- Creating objects
- Object metadata operations
"""

from typing import Optional, List, Dict, Any
import logging
from urllib.parse import quote

from sap_types.sap_types import (
    ADTObject, CreateObjectRequest, ObjectOperationResult, 
    SAPSyntaxError
)
from utils.logger import rap_logger
from utils.security import sanitize_for_logging, sanitize_file_path
from utils.xml_utils import (
    safe_parse_xml, get_object_url_patterns, build_object_xml,
    is_include_program
)

logger = logging.getLogger(__name__)


class SAPObjectManager:
    """Manages ABAP object operations"""
    
    def __init__(self, connection_manager, session):
        self.connection_manager = connection_manager
        self.session = session
        self.connection = connection_manager.connection
    
    async def get_objects(self, package_name: Optional[str] = None) -> List[ADTObject]:
        """Get ABAP objects from SAP system"""
        try:
            # Build URL exactly like TypeScript version
            base_url = "/sap/bc/adt/repository/nodestructure"
            url = f"{base_url}?sap-client={self.connection.client}"
            
            # Create parameters for POST request
            if package_name:
                params = {
                    'parent_type': 'DEVC/K',
                    'parent_name': package_name,
                    'withShortDescriptions': 'true'
                }
            else:
                params = {
                    'withShortDescriptions': 'true'
                }
            
            headers = await self.connection_manager.get_appropriate_headers()
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            headers['Accept'] = 'application/xml, application/vnd.sap.as+xml'
            
            logger.info(f"Making POST request to {sanitize_for_logging(url)} with params: {sanitize_for_logging(params)}")
            
            # Use POST request with empty body and params
            async with self.session.post(url, data='', params=params, headers=headers) as response:
                logger.info(f"Response status: {response.status}")
                if response.status == 200:
                    xml_content = await response.text()
                    logger.info(f"Response XML length: {len(xml_content)}")
                    
                    objects = self._parse_objects_xml(xml_content)
                    logger.info(f"Parsed {len(objects)} objects from main endpoint")
                    
                    # If main endpoint returns no objects and we have a package, try alternatives
                    if len(objects) == 0 and package_name:
                        objects = await self._try_alternative_endpoints(package_name, headers)
                    
                    return objects
                else:
                    logger.error(f"Failed to get objects: {response.status}")
                    response_text = await response.text()
                    logger.error(f"Response text: {sanitize_for_logging(response_text[:500])}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error getting objects: {sanitize_for_logging(str(e))}")
            return []
    
    async def _try_alternative_endpoints(self, package_name: str, headers: Dict[str, str]) -> List[ADTObject]:
        """Try alternative endpoints when main endpoint returns no objects"""
        logger.info("Main endpoint returned no objects, trying alternative endpoints")
        
        alternative_endpoints = [
            f"/sap/bc/adt/packages/{package_name}/objects?sap-client={self.connection.client}",
            f"/sap/bc/adt/repository/informationsystem/search?sap-client={self.connection.client}"
        ]
        
        for alt_url in alternative_endpoints:
            try:
                logger.info(f"Trying alternative endpoint: {sanitize_for_logging(alt_url)}")
                async with self.session.get(alt_url, headers=headers) as alt_response:
                    if alt_response.status == 200:
                        alt_xml = await alt_response.text()
                        alt_objects = self._parse_objects_xml(alt_xml)
                        if len(alt_objects) > 0:
                            logger.info(f"Found {len(alt_objects)} objects using alternative endpoint")
                            return alt_objects
                    else:
                        logger.info(f"Alternative endpoint returned status: {alt_response.status}")
            except Exception as alt_e:
                logger.info(f"Alternative endpoint failed: {sanitize_for_logging(str(alt_e))}")
                continue
        
        return []
    
    def _parse_objects_xml(self, xml_content: str) -> List[ADTObject]:
        """Parse objects from XML response"""
        objects = []
        
        try:
            root = safe_parse_xml(xml_content)
            if root is None:
                logger.warning("Failed to parse XML content")
                return objects
            
            logger.info("Parsing objects from XML response")
            
            # Try SAP ADT repository structure first
            repo_nodes = self._find_repository_nodes(root)
            
            if repo_nodes:
                objects = self._parse_repository_nodes(repo_nodes)
                if objects:
                    return objects
            
            # Fallback to atom feed parsing
            objects = self._parse_atom_entries(root)
            if objects:
                return objects
            
            # Final fallback to simple node parsing
            objects = self._parse_simple_nodes(root)
            
        except Exception as e:
            logger.error(f"Error parsing objects XML: {sanitize_for_logging(str(e))}")
        
        return objects
    
    def _find_repository_nodes(self, root):
        """Find repository nodes in XML"""
        possible_paths = [
            './/SEU_ADT_REPOSITORY_OBJ_NODE',
            './/*[local-name()="SEU_ADT_REPOSITORY_OBJ_NODE"]',
            './/TREE_CONTENT/SEU_ADT_REPOSITORY_OBJ_NODE',
            './/DATA/TREE_CONTENT/SEU_ADT_REPOSITORY_OBJ_NODE'
        ]
        
        for path in possible_paths:
            repo_nodes = root.findall(path)
            logger.info(f"Trying path '{path}': found {len(repo_nodes)} nodes")
            if repo_nodes:
                return repo_nodes
        
        return []
    
    def _parse_repository_nodes(self, repo_nodes) -> List[ADTObject]:
        """Parse repository nodes into ADTObject list"""
        objects = []
        
        for i, node in enumerate(repo_nodes):
            # Handle SAP's XML format where values are in child elements
            name_elem = node.find('OBJECT_NAME')
            tech_name_elem = node.find('TECH_NAME')
            type_elem = node.find('OBJECT_TYPE')
            desc_elem = node.find('DESCRIPTION')
            uri_elem = node.find('OBJECT_URI')
            
            # Use TECH_NAME if OBJECT_NAME is empty
            name = ''
            if name_elem is not None and name_elem.text:
                name = name_elem.text.strip()
            elif tech_name_elem is not None and tech_name_elem.text:
                name = tech_name_elem.text.strip()
            
            obj_type = type_elem.text.strip() if type_elem is not None and type_elem.text else ''
            description = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else ''
            uri = uri_elem.text.strip() if uri_elem is not None and uri_elem.text else ''
            
            # Only add if we have both name and type, and it's not just a package structure node
            if name and obj_type and not obj_type.startswith('DEVC/'):
                objects.append(ADTObject(
                    name=name,
                    type=obj_type,
                    description=description,
                    package_name='',
                    uri=uri
                ))
        
        return objects
    
    def _parse_atom_entries(self, root) -> List[ADTObject]:
        """Parse atom entries into ADTObject list"""
        objects = []
        
        atom_paths = [
            './/{http://www.w3.org/2005/Atom}entry',
            './/entry',
            './/atom:entry'
        ]
        
        entries = []
        for atom_path in atom_paths:
            entries = root.findall(atom_path)
            if entries:
                break
        
        if entries:
            for entry in entries:
                title_elem = entry.find('.//{http://www.w3.org/2005/Atom}title') or entry.find('.//title')
                name = title_elem.text if title_elem is not None else ''
                
                category_elem = entry.find('.//{http://www.w3.org/2005/Atom}category') or entry.find('.//category')
                obj_type = category_elem.get('term', '') if category_elem is not None else ''
                
                if name:
                    objects.append(ADTObject(
                        name=name,
                        type=obj_type,
                        description='',
                        package_name='',
                        uri=''
                    ))
        
        return objects
    
    def _parse_simple_nodes(self, root) -> List[ADTObject]:
        """Parse simple nodes into ADTObject list"""
        objects = []
        
        node_patterns = ['.//node', './/item', './/object', './/*[@name]']
        
        for pattern in node_patterns:
            nodes = root.findall(pattern)
            
            if nodes:
                for node in nodes:
                    name = node.get('name', '') or node.text or ''
                    obj_type = node.get('type', '') or node.get('objectType', '')
                    description = node.get('description', '') or node.get('desc', '')
                    package_name = node.get('package', '') or node.get('packageName', '')
                    uri = node.get('uri', '') or node.get('href', '')
                    
                    if name and obj_type:
                        objects.append(ADTObject(
                            name=name,
                            type=obj_type,
                            description=description,
                            package_name=package_name,
                            uri=uri
                        ))
                
                if objects:
                    break
        
        return objects
    
    async def get_source(self, object_name: str, object_type: str) -> Optional[str]:
        """Get source code of ABAP object"""
        try:
            # Validate object name to prevent path traversal
            validated_object_name = sanitize_file_path(object_name)
            
            print(f"[SAP-CLIENT] Getting source code for {sanitize_for_logging(validated_object_name)} ({sanitize_for_logging(object_type)})")
            
            # Special handling for Service Bindings (SRVB)
            if object_type.upper() == 'SRVB':
                return await self._get_service_binding_metadata(validated_object_name)
            
            # Special handling for Data Elements (DTEL) and Table Types (TTYP)
            # These objects don't have /source/main endpoint, only metadata XML
            # Handle type variants like DTEL/DE and TTYP/DA
            type_base = object_type.upper().split('/')[0]
            if type_base in ['DTEL', 'TTYP']:
                return await self._get_ddic_metadata(validated_object_name, object_type)
            
            # Special handling for Structures (STRU or TABL/DS)
            # These have /source/main for CDS-style definitions
            if object_type.upper() in ['STRU', 'TABL/DS']:
                return await self._get_structure_source(validated_object_name, object_type)
            
            # Special handling for include programs
            if object_type.upper() == 'PROG' and is_include_program(validated_object_name):
                return await self._get_include_source(validated_object_name)
            
            # Try resource URI discovery first
            resource_uri = await self._get_resource_uri(validated_object_name, object_type)
            if resource_uri:
                source = await self._get_source_from_uri(resource_uri, validated_object_name, object_type)
                if source:
                    return source
            
            # Fallback to pattern-based approach
            return await self._get_source_from_patterns(validated_object_name, object_type)
            
        except Exception as e:
            print(f"[SAP-CLIENT] Failed to get source: {sanitize_for_logging(str(e))}")
            logger.error(f"Failed to get source: {sanitize_for_logging(str(e))}")
            return None
    
    async def _get_service_binding_metadata(self, object_name: str) -> Optional[str]:
        """Get Service Binding metadata"""
        try:
            url = f"/sap/bc/adt/businessservices/bindings/{object_name}?sap-client={self.connection.client}"
            headers = await self.connection_manager.get_appropriate_headers()
            headers['Accept'] = 'application/xml'
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.text()
        except Exception as error:
            print(f"[SAP-CLIENT] Service Binding metadata failed: {sanitize_for_logging(str(error))}")
        
        return None
    
    async def _get_ddic_metadata(self, object_name: str, object_type: str) -> Optional[str]:
        """
        Get DDIC object metadata for objects that don't have /source/main endpoint.
        This includes Data Elements (DTEL, DTEL/DE) and Table Types (TTYP, TTYP/DA).
        
        For structures (STRU/TABL/DS), we first try /source/main (for CDS-style definitions),
        and if that fails, fall back to metadata XML.
        """
        try:
            # Extract base type (e.g., DTEL from DTEL/DE, TTYP from TTYP/DA)
            type_base = object_type.upper().split('/')[0]
            
            # Get URL pattern for the object type
            url_patterns = get_object_url_patterns(type_base, object_name)
            if not url_patterns:
                return None
            
            pattern = url_patterns[0]
            
            # For structures, first try to get CDS-style source from /source/main
            if type_base in ['STRU'] or object_type.upper() == 'TABL/DS':
                source_url = f"/sap/bc/adt/{pattern}/{object_name}/source/main?sap-client={self.connection.client}"
                headers = await self.connection_manager.get_appropriate_headers()
                headers['Accept'] = 'text/plain'
                
                try:
                    async with self.session.get(source_url, headers=headers) as response:
                        if response.status == 200:
                            cds_source = await response.text()
                            if cds_source and cds_source.strip():
                                print(f"[SAP-CLIENT] Retrieved CDS-style source for structure {sanitize_for_logging(object_name)}")
                                return cds_source
                except Exception as e:
                    print(f"[SAP-CLIENT] CDS-style source not available, falling back to metadata: {sanitize_for_logging(str(e))}")
            
            # Get metadata XML (works for DTEL, TTYP, and as fallback for STRU)
            metadata_url = f"/sap/bc/adt/{pattern}/{object_name}?sap-client={self.connection.client}"
            headers = await self.connection_manager.get_appropriate_headers()
            
            # Set appropriate Accept headers based on object type
            if type_base == 'DTEL':
                headers['Accept'] = 'application/vnd.sap.adt.dataelements.v1+xml, application/vnd.sap.adt.dataelements.v2+xml'
            elif type_base == 'TTYP':
                headers['Accept'] = 'application/vnd.sap.adt.tabletype.v1+xml'
            elif type_base == 'STRU' or object_type.upper() == 'TABL/DS':
                headers['Accept'] = 'application/vnd.sap.adt.blues.v1+xml, application/vnd.sap.adt.structures.v2+xml'
            else:
                headers['Accept'] = 'application/xml'
            
            async with self.session.get(metadata_url, headers=headers) as response:
                if response.status == 200:
                    metadata_xml = await response.text()
                    print(f"[SAP-CLIENT] Retrieved metadata XML for {sanitize_for_logging(object_type)} {sanitize_for_logging(object_name)}")
                    return metadata_xml
                else:
                    print(f"[SAP-CLIENT] Failed to get metadata: {response.status}")
                    return None
                    
        except Exception as error:
            print(f"[SAP-CLIENT] DDIC metadata retrieval failed: {sanitize_for_logging(str(error))}")
            logger.error(f"DDIC metadata retrieval failed: {sanitize_for_logging(str(error))}")
        
        return None
    
    async def _get_structure_source(self, object_name: str, object_type: str) -> Optional[str]:
        """
        Get structure source code. Structures have /source/main endpoint for CDS-style definitions.
        Based on ADT API: GET /sap/bc/adt/ddic/structures/{name}/source/main with Accept: text/plain
        """
        try:
            # Structures always use ddic/structures endpoint regardless of type variant
            source_url = f"/sap/bc/adt/ddic/structures/{object_name}/source/main?sap-client={self.connection.client}"
            headers = await self.connection_manager.get_appropriate_headers()
            headers['Accept'] = 'text/plain'
            
            async with self.session.get(source_url, headers=headers) as response:
                if response.status == 200:
                    cds_source = await response.text()
                    if cds_source and cds_source.strip():
                        print(f"[SAP-CLIENT] Retrieved CDS-style source for structure {sanitize_for_logging(object_name)}")
                        return cds_source
                else:
                    print(f"[SAP-CLIENT] Structure /source/main returned {response.status}, trying metadata")
            
            # Fallback to metadata XML if /source/main fails
            return await self._get_ddic_metadata(object_name, object_type)
                    
        except Exception as error:
            print(f"[SAP-CLIENT] Structure source retrieval failed: {sanitize_for_logging(str(error))}")
            # Fallback to metadata
            return await self._get_ddic_metadata(object_name, object_type)
    
    async def _get_source_from_uri(self, resource_uri: str, object_name: str, object_type: str) -> Optional[str]:
        """Get source from discovered resource URI"""
        try:
            url = f"{resource_uri}/source/main?sap-client={self.connection.client}"
            headers = await self.connection_manager.get_appropriate_headers()
            headers['Accept'] = 'text/plain'
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    main_source = await response.text()
                    
                    # For classes, also try to get implementations include
                    if object_type.upper() in ['CLAS', 'BIMPL']:
                        impl_source = await self._get_implementations_include(resource_uri)
                        if impl_source:
                            return self._combine_class_sources(main_source, impl_source)
                    
                    return main_source
        except Exception as error:
            print(f"[SAP-CLIENT] Discovered URI failed: {sanitize_for_logging(str(error))}")
        
        return None
    
    async def _get_implementations_include(self, resource_uri: str) -> Optional[str]:
        """Get implementations include for classes"""
        try:
            impl_url = f"{resource_uri}/includes/implementations?sap-client={self.connection.client}"
            headers = await self.connection_manager.get_appropriate_headers()
            headers['Accept'] = 'text/plain'
            
            async with self.session.get(impl_url, headers=headers) as response:
                if response.status == 200:
                    return await response.text()
        except Exception:
            pass
        
        return None
    
    def _combine_class_sources(self, main_source: str, impl_source: str) -> str:
        """Combine main source with implementations include"""
        return f"{main_source}\n\n{'=' * 80}\n{'=' * 80}\n** LOCAL HANDLER CLASSES (includes/implementations) **\n{'=' * 80}\n\n{impl_source}"
    
    async def _get_source_from_patterns(self, object_name: str, object_type: str) -> Optional[str]:
        """Get source using URL patterns"""
        url_patterns = get_object_url_patterns(object_type, object_name)
        
        for pattern in url_patterns:
            try:
                url = f"/sap/bc/adt/{pattern}/{object_name}/source/main?sap-client={self.connection.client}"
                headers = await self.connection_manager.get_appropriate_headers()
                headers['Accept'] = 'text/plain'
                
                async with self.session.get(url, headers=headers) as response:
                    if response.status == 200:
                        main_source = await response.text()
                        
                        # For classes, also try implementations
                        if object_type.upper() in ['CLAS', 'BIMPL']:
                            impl_url = f"/sap/bc/adt/{pattern}/{object_name}/includes/implementations?sap-client={self.connection.client}"
                            impl_source = await self._get_source_from_url(impl_url)
                            if impl_source:
                                return self._combine_class_sources(main_source, impl_source)
                        
                        return main_source
                    elif response.status == 404:
                        # For structures, if /source/main doesn't exist, try metadata
                        if object_type.upper() in ['STRU', 'TABL/DS']:
                            print(f"[SAP-CLIENT] /source/main not found for structure, trying metadata")
                            return await self._get_ddic_metadata(object_name, object_type)
                        
            except Exception as error:
                if hasattr(error, 'response') and error.response and error.response.status not in [404, 406]:
                    raise error
        
        return None
    
    async def _get_source_from_url(self, url: str) -> Optional[str]:
        """Helper to get source from a specific URL"""
        try:
            headers = await self.connection_manager.get_appropriate_headers()
            headers['Accept'] = 'text/plain'
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.text()
        except Exception:
            pass
        
        return None
    
    async def _get_resource_uri(self, object_name: str, object_type: str) -> Optional[str]:
        """Get resource URI for object (placeholder - implement based on your needs)"""
        # This would implement the resource URI discovery logic
        # For now, return None to use pattern-based approach
        return None
    
    async def _get_include_source(self, object_name: str) -> Optional[str]:
        """Get source for include programs (placeholder - implement based on your needs)"""
        # This would implement include-specific source retrieval
        return None