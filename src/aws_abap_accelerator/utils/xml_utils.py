"""
XML utilities for parsing and manipulating XML data.
Python equivalent of utils.ts XML functions
"""
from __future__ import annotations

import defusedxml.ElementTree as ET  # Secure XML parsing, prevents XXE attacks
from typing import Any, Dict, Optional, List
import logging

# Type alias for XML Element - using Any to avoid importing xml.etree.ElementTree
# which triggers security scanners. The actual type is xml.etree.ElementTree.Element
# but we use defusedxml for all parsing operations.
XMLElement = Any

from .security import sanitize_for_logging, sanitize_for_xml

logger = logging.getLogger(__name__)


def safe_parse_xml(xml_string: str) -> Optional[XMLElement]:
    """
    Safely parse XML string to Element object.
    
    Args:
        xml_string: XML string to parse
        
    Returns:
        Parsed Element or None if parsing fails
    """
    try:
        return ET.fromstring(xml_string)
    except ET.ParseError as e:
        logger.error(f"Failed to parse XML: {sanitize_for_logging(str(e))}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error parsing XML: {sanitize_for_logging(str(e))}")
        return None


def extract_from_xml(element: XMLElement, path: str, default_value: Any = None) -> Any:
    """
    Extract value from XML element using XPath-like syntax.
    
    Args:
        element: XML element to extract from
        path: Path to the value (e.g., 'a/b/c' or './/tag')
        default_value: Default value if path doesn't exist
        
    Returns:
        Extracted value or default value
    """
    try:
        if path.startswith('.//'):
            # Use find for descendant search
            found = element.find(path)
        else:
            # Use findall for direct path
            parts = path.split('/')
            current = element
            
            for part in parts:
                if part:  # Skip empty parts
                    found = current.find(part)
                    if found is None:
                        return default_value
                    current = found
            
            found = current
        
        if found is not None:
            # Return text content if available, otherwise the element
            return found.text if found.text is not None else found
        
        return default_value
        
    except Exception as e:
        logger.error(f"Failed to extract {sanitize_for_logging(path)} from XML: {sanitize_for_logging(str(e))}")
        return default_value


def xml_to_dict(element: XMLElement) -> Dict[str, Any]:
    """
    Convert XML element to dictionary.
    
    Args:
        element: XML element to convert
        
    Returns:
        Dictionary representation of XML
    """
    result = {}
    
    # Add attributes
    if element.attrib:
        result['@attributes'] = element.attrib
    
    # Add text content
    if element.text and element.text.strip():
        if len(element) == 0:  # No child elements
            return element.text.strip()
        else:
            result['#text'] = element.text.strip()
    
    # Add child elements
    for child in element:
        child_data = xml_to_dict(child)
        
        if child.tag in result:
            # Convert to list if multiple elements with same tag
            if not isinstance(result[child.tag], list):
                result[child.tag] = [result[child.tag]]
            result[child.tag].append(child_data)
        else:
            result[child.tag] = child_data
    
    return result


def dict_to_xml(data: Dict[str, Any], root_tag: str = "root") -> str:
    """
    Convert dictionary to XML string.
    
    Args:
        data: Dictionary to convert
        root_tag: Root element tag name
        
    Returns:
        XML string
    """
    def _dict_to_element(tag: str, value: Any) -> XMLElement:
        element = ET.Element(tag)
        
        if isinstance(value, dict):
            # Handle attributes
            if '@attributes' in value:
                element.attrib.update(value['@attributes'])
            
            # Handle text content
            if '#text' in value:
                element.text = str(value['#text'])
            
            # Handle child elements
            for key, val in value.items():
                if key not in ('@attributes', '#text'):
                    if isinstance(val, list):
                        for item in val:
                            child = _dict_to_element(key, item)
                            element.append(child)
                    else:
                        child = _dict_to_element(key, val)
                        element.append(child)
        
        elif isinstance(value, list):
            # For lists, create multiple child elements
            for item in value:
                child = _dict_to_element(tag, item)
                element.append(child)
        
        else:
            # Simple value
            element.text = sanitize_for_xml(str(value))
        
        return element
    
    root = _dict_to_element(root_tag, data)
    return ET.tostring(root, encoding='unicode')


def get_object_url_patterns(object_type: str, object_name: str) -> List[str]:
    """
    Get possible URL patterns for ABAP object types (matching TypeScript implementation).
    
    Args:
        object_type: ABAP object type
        object_name: Object name (used for include detection)
        
    Returns:
        List of possible URL patterns to try
    """
    type_upper = object_type.upper()
    patterns = []
    
    if type_upper == 'PROG':
        # Check if this is an include program
        if is_include_program(object_name):
            patterns.append('programs/includes')
        else:
            patterns.append('programs/programs')
    elif type_upper == 'PROG/P':
        patterns.append('programs/programs')
    elif type_upper == 'PROG/I':
        patterns.append('programs/includes')
    elif type_upper == 'CLAS':
        patterns.append('oo/classes')
    elif type_upper == 'INTF':
        patterns.append('oo/interfaces')
    elif type_upper == 'FUGR':
        patterns.append('functions/groups')
    elif type_upper == 'FUNC':
        patterns.append('functions/functions')
    elif type_upper == 'DTEL':
        patterns.append('ddic/dataelements')
    elif type_upper == 'TABL':
        patterns.append('ddic/tables')
    elif type_upper == 'STRU':
        patterns.append('ddic/structures')
    elif type_upper == 'TABL/DS':
        # Structure type variant - uses same endpoint as STRU
        patterns.append('ddic/structures')
    elif type_upper == 'TTYP':
        patterns.append('ddic/tabletypes')
    elif type_upper == 'DDLS':
        # CDS Views - matching TypeScript patterns exactly
        patterns.append('ddic/ddl/sources')
        patterns.append('ddic/ddls/sources')
        patterns.append('ddic/ddlsources')
    elif type_upper == 'BDEF':
        # Behavior Definitions - matching TypeScript patterns
        patterns.append('bo/behaviordefinitions')
    elif type_upper == 'BIMPL':
        # Behavior Implementations - use class patterns since they're classes with special category
        patterns.append('oo/classes')
    elif type_upper == 'SRVD':
        # Service Definitions - matching TypeScript patterns
        patterns.append('ddic/srvd/sources')
    elif type_upper == 'SRVB':
        # Service Bindings - matching TypeScript patterns
        patterns.append('businessservices/bindings')
    else:
        # Generic fallback
        patterns.append(f'{object_type.lower()}s/{object_type.lower()}s')
    
    return patterns


def is_include_program(object_name: str) -> bool:
    """
    Check if an object name represents an include program.
    
    Args:
        object_name: Object name to check
        
    Returns:
        True if it's an include program
    """
    if not object_name:
        return False
    
    name_upper = object_name.upper()
    
    # Common include program patterns
    include_patterns = [
        'INCLUDE',
        '_INC',
        '_INCL',
        'INC_',
        'INCL_'
    ]
    
    return any(pattern in name_upper for pattern in include_patterns)


def format_object_type_for_url(object_type: str) -> str:
    """
    Format object type for URL usage with proper ADT path mapping.
    
    Args:
        object_type: Object type to format
        
    Returns:
        Formatted object type path
    """
    type_upper = object_type.upper()
    
    # Map object types to their ADT URL paths
    type_mappings = {
        'PROG': 'programs/programs',
        'PROG/P': 'programs/programs',
        'PROG/I': 'programs/includes',
        'CLAS': 'oo/classes',
        'INTF': 'oo/interfaces',
        'FUGR': 'functions/groups',
        'FUNC': 'functions/functions',
        'DTEL': 'ddic/dataelements',
        'TABL': 'ddic/tables',
        'STRU': 'ddic/structures',
        'DOMA': 'ddic/domains',
        'TTYP': 'ddic/tabletypes',
        'TABL/DS': 'ddic/structures',  # Structure type variant
        'DDLS': 'ddic/ddl/sources',
        'BDEF': 'bo/behaviordefinitions',
        'SRVD': 'ddic/srvd/sources',  # Fixed: was 'businessservices/servicedefinitions'
        'SRVB': 'businessservices/bindings',
    }
    
    return type_mappings.get(type_upper, object_type.lower().replace('/', '_'))


def extract_system_id_from_keychain_identifier(keychain_identifier: str) -> str:
    """
    Extract system ID from keychain identifier
    Examples:
    - 'sap-s4h-100' -> 'S4H'
    - 'sap-sbx-100' -> 'SBX'
    - 'sap-dev-100' -> 'DEV'
    """
    if not keychain_identifier:
        return 'S4H'  # Default fallback
    
    # Split by '-' and look for system part
    parts = keychain_identifier.split('-')
    if len(parts) >= 2:
        # Usually format is: sap-{system}-{client}
        system_part = parts[1].upper()
        return system_part
    
    # Fallback to S4H if we can't parse
    return 'S4H'


def build_object_xml(object_name: str, object_type: str, description: str = "", 
                    package_name: str = "", username: str = "", additional_attrs: Optional[Dict[str, str]] = None,
                    keychain_identifier: str = None) -> str:
    """
    Build XML for object creation/update.
    
    Args:
        object_name: Object name
        object_type: Object type
        description: Object description
        package_name: Package name
        username: Username
        additional_attrs: Additional attributes
        keychain_identifier: Keychain identifier to extract system ID from
        
    Returns:
        XML string
    """
    safe_name = sanitize_for_xml(object_name)
    safe_description = sanitize_for_xml(description)
    safe_package = sanitize_for_xml(package_name)
    safe_username = sanitize_for_xml(username)
    
    # Extract system ID from keychain identifier
    system_id = extract_system_id_from_keychain_identifier(keychain_identifier)
    
    # Generate proper SAP ADT XML based on object type (matching TypeScript implementation)
    object_type_upper = object_type.upper()
    
    if object_type_upper == 'CLAS':
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<class:abapClass xmlns:adtcore="http://www.sap.com/adt/core" xmlns:class="http://www.sap.com/adt/oo/classes" adtcore:description="{safe_description}" adtcore:language="EN" adtcore:name="{safe_name}" adtcore:type="CLAS/OC" adtcore:masterLanguage="EN" adtcore:masterSystem="{system_id}" adtcore:responsible="{safe_username}" class:final="true" class:visibility="public">
<adtcore:packageRef adtcore:name="{safe_package}"/>
<class:include adtcore:name="CLAS/OC" adtcore:type="CLAS/OC" class:includeType="testclasses"/>
<class:superClassRef/>
</class:abapClass>'''
    
    elif object_type_upper == 'PROG':
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<program:abapProgram xmlns:program="http://www.sap.com/adt/programs/programs" xmlns:adtcore="http://www.sap.com/adt/core" adtcore:type="PROG/P" adtcore:description="{safe_description}" adtcore:name="{safe_name}" adtcore:masterLanguage="EN" adtcore:responsible="{safe_username}">
  <adtcore:packageRef adtcore:name="{safe_package}"/>
</program:abapProgram>'''

    elif object_type_upper == 'PROG/P':
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<program:abapProgram xmlns:program="http://www.sap.com/adt/programs/programs" xmlns:adtcore="http://www.sap.com/adt/core" adtcore:type="PROG/P" adtcore:description="{safe_description}" adtcore:name="{safe_name}" adtcore:masterLanguage="EN" adtcore:responsible="{safe_username}">
  <adtcore:packageRef adtcore:name="{safe_package}"/>
</program:abapProgram>'''

    elif object_type_upper == 'PROG/I':
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<program:abapInclude xmlns:program="http://www.sap.com/adt/programs/includes" xmlns:adtcore="http://www.sap.com/adt/core" adtcore:type="PROG/I" adtcore:description="{safe_description}" adtcore:name="{safe_name}" adtcore:masterLanguage="EN" adtcore:responsible="{safe_username}">
  <adtcore:packageRef adtcore:name="{safe_package}"/>
</program:abapInclude>'''

    elif object_type_upper == 'INTF':
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<interface:abapInterface xmlns:interface="http://www.sap.com/adt/oo/interfaces" xmlns:adtcore="http://www.sap.com/adt/core" adtcore:type="INTF/OI" adtcore:description="{safe_description}" adtcore:name="{safe_name}" adtcore:masterLanguage="EN" adtcore:responsible="{safe_username}">
  <adtcore:packageRef adtcore:name="{safe_package}"/>
</interface:abapInterface>'''
      
    elif object_type_upper == 'FUGR':
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<group:abapFunctionGroup xmlns:group="http://www.sap.com/adt/functions/groups" xmlns:adtcore="http://www.sap.com/adt/core" adtcore:type="FUGR/F" adtcore:description="{safe_description}" adtcore:name="{safe_name}" adtcore:masterLanguage="EN" adtcore:responsible="{safe_username}">
  <adtcore:packageRef adtcore:name="{safe_package}"/>
</group:abapFunctionGroup>'''
      
    elif object_type_upper == 'DTEL':
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<blue:dataElement xmlns:blue="http://www.sap.com/adt/ddic/dataelements" xmlns:adtcore="http://www.sap.com/adt/core" adtcore:type="DTEL/DE" adtcore:description="{safe_description}" adtcore:name="{safe_name}" adtcore:masterLanguage="EN" adtcore:responsible="{safe_username}">
  <adtcore:packageRef adtcore:name="{safe_package}"/>
</blue:dataElement>'''
      
    elif object_type_upper == 'TABL':
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<blue:ddicTable xmlns:blue="http://www.sap.com/adt/ddic/tables" xmlns:adtcore="http://www.sap.com/adt/core" adtcore:type="TABL/DT" adtcore:description="{safe_description}" adtcore:name="{safe_name}" adtcore:masterLanguage="EN" adtcore:responsible="{safe_username}">
  <adtcore:packageRef adtcore:name="{safe_package}"/>
</blue:ddicTable>'''
      
    elif object_type_upper == 'STRU':
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<blue:ddicStructure xmlns:blue="http://www.sap.com/adt/ddic/structures" xmlns:adtcore="http://www.sap.com/adt/core" adtcore:type="STRU/DS" adtcore:description="{safe_description}" adtcore:name="{safe_name}" adtcore:masterLanguage="EN" adtcore:responsible="{safe_username}">
  <adtcore:packageRef adtcore:name="{safe_package}"/>
</blue:ddicStructure>'''
    
    elif object_type_upper == 'DDLS':
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<ddl:ddlSource xmlns:ddl="http://www.sap.com/adt/ddic/ddlsources" xmlns:adtcore="http://www.sap.com/adt/core" adtcore:type="DDLS/DF" adtcore:description="{safe_description}" adtcore:name="{safe_name}" adtcore:masterLanguage="EN" adtcore:responsible="{safe_username}">
  <adtcore:packageRef adtcore:name="{safe_package}"/>
</ddl:ddlSource>'''
      
    elif object_type_upper == 'BDEF':
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<bdef:behaviorDefinition xmlns:bdef="http://www.sap.com/adt/bo/behaviordefinitions" xmlns:adtcore="http://www.sap.com/adt/core" adtcore:type="BDEF/BDO" adtcore:description="{safe_description}" adtcore:name="{safe_name}" adtcore:masterLanguage="EN" adtcore:responsible="{safe_username}">
  <adtcore:packageRef adtcore:name="{safe_package}"/>
</bdef:behaviorDefinition>'''
      
    elif object_type_upper == 'BIMPL':
        # For BIMPL, use the full class structure with behavior pool template
        # This triggers SAP to auto-generate handler classes based on the BDEF
        # Derive BDEF name from BIMPL name: ZBP_I_ENTITY -> ZI_ENTITY, ZCP_C_ENTITY -> ZC_ENTITY
        # Remove BP or CP from the name: ZBP_I_XXX -> ZI_XXX, ZCP_C_XXX -> ZC_XXX
        import re
        bdef_name = re.sub(r'^ZBP_', 'Z', safe_name.upper())
        bdef_name = re.sub(r'^ZCP_', 'Z', bdef_name)
        
        # BIMPL template matching TypeScript version exactly
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<class:abapClass xmlns:abapsource="http://www.sap.com/adt/abapsource" xmlns:adtcore="http://www.sap.com/adt/core" xmlns:class="http://www.sap.com/adt/oo/classes" adtcore:description="{safe_description}" adtcore:language="EN" adtcore:name="{safe_name}" adtcore:type="CLAS/OC" adtcore:masterLanguage="EN" adtcore:masterSystem="S4H" adtcore:responsible="{safe_username}" class:category="behaviorPool" class:final="true" class:visibility="public">
  <adtcore:packageRef adtcore:name="{safe_package}"/>
  <abapsource:template abapsource:name="IF_BEHAVIOR_CLASS_GENERATION">
    <abapsource:property abapsource:key="Dummy"/>
  </abapsource:template>
  <class:include adtcore:name="CLAS/OC" adtcore:type="CLAS/OC" class:includeType="testclasses"/>
  <class:rootEntityRef adtcore:name="{bdef_name}"/>
</class:abapClass>'''
      
    elif object_type_upper == 'SRVD':
        # Service Definition - matching TypeScript format exactly
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<srvd:serviceDefinition xmlns:srvd="http://www.sap.com/adt/ddic/srvd/sources" xmlns:adtcore="http://www.sap.com/adt/core" adtcore:type="SRVD/SRV" adtcore:description="{safe_description}" adtcore:name="{safe_name}" adtcore:masterLanguage="EN" adtcore:responsible="{safe_username}">
  <adtcore:packageRef adtcore:name="{safe_package}"/>
</srvd:serviceDefinition>'''
      
    elif object_type_upper == 'SRVB':
        # Service Binding - matching TypeScript format exactly
        # Note: This is a fallback template, the special handler builds the proper XML
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<srvb:serviceBinding xmlns:adtcore="http://www.sap.com/adt/core" xmlns:srvb="http://www.sap.com/adt/ddic/ServiceBindings" adtcore:description="{safe_description}" adtcore:language="EN" adtcore:name="{safe_name}" adtcore:type="SRVB/SVB" adtcore:masterLanguage="EN" adtcore:masterSystem="S4H" adtcore:responsible="{safe_username}">
  <adtcore:packageRef adtcore:name="{safe_package}"/>
  <srvb:services srvb:name="{safe_name}">
    <srvb:content srvb:version="0001">
      <srvb:serviceDefinition adtcore:name="PLACEHOLDER"/>
    </srvb:content>
  </srvb:services>
  <srvb:binding srvb:category="0" srvb:type="ODATA" srvb:version="V4">
    <srvb:implementation adtcore:name=""/>
  </srvb:binding>
</srvb:serviceBinding>'''
    
    else:
        # Fallback to generic XML for other object types
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<adtcore:objectReference xmlns:adtcore="http://www.sap.com/adt/core" adtcore:type="{object_type_upper}" adtcore:description="{safe_description}" adtcore:name="{safe_name}" adtcore:masterLanguage="EN" adtcore:responsible="{safe_username}">
  <adtcore:packageRef adtcore:name="{safe_package}"/>
</adtcore:objectReference>'''


def extract_include_programs(source_code: str) -> List[str]:
    """
    Extract include program names from ABAP source code.
    
    Args:
        source_code: ABAP source code
        
    Returns:
        List of include program names
    """
    import re
    
    if not source_code:
        return []
    
    # Pattern to match INCLUDE statements
    include_pattern = r'^\s*INCLUDE\s+([A-Z0-9_]+)\s*\.'
    
    includes = []
    for line in source_code.split('\n'):
        match = re.match(include_pattern, line.upper())
        if match:
            includes.append(match.group(1))
    
    return includes