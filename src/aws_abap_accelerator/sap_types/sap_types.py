"""
Type definitions for SAP operations.
Python equivalent of types.ts
"""

from typing import Optional, List, Dict, Any, Union, Literal
from pydantic import BaseModel
from enum import Enum


class AuthType(str, Enum):
    BASIC = "basic"
    CERTIFICATE = "certificate"
    OAUTH = "oauth"
    SAML = "saml"


class SAPConnection(BaseModel):
    """SAP connection configuration"""
    host: str
    instance_number: Optional[str] = None
    client: str
    username: str
    password: str
    encrypted_password: Optional[str] = None
    language: Optional[str] = "EN"
    secure: Optional[bool] = True
    system_id: Optional[str] = None
    url: Optional[str] = None
    auth_type: Optional[AuthType] = AuthType.BASIC


class ADTObject(BaseModel):
    """ADT object representation"""
    name: str
    type: str
    description: Optional[str] = None
    package_name: Optional[str] = None
    uri: Optional[str] = None
    version: Optional[str] = None
    changed_by: Optional[str] = None
    changed_at: Optional[str] = None
    created_by: Optional[str] = None
    created_at: Optional[str] = None


class AuthConfig(BaseModel):
    """Authentication configuration"""
    method: Literal["basic"]
    
    # Basic auth config
    basic: Optional[Dict[str, str]] = None


class AuthState(BaseModel):
    """Authentication state"""
    is_authenticated: bool
    method: Literal["basic"]
    cookies: Optional[str] = None


class SeverityType(str, Enum):
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


class ATCResult(BaseModel):
    """ATC check result"""
    severity: SeverityType
    message: str
    line: Optional[int] = None
    column: Optional[int] = None
    check_id: Optional[str] = None
    documentation_url: Optional[str] = None
    documentation: Optional[str] = None
    documentation_note: Optional[str] = None
    check_title: Optional[str] = None
    message_id: Optional[str] = None
    priority: Optional[str] = None
    quickfixes: Optional[List["QuickfixEvaluation"]] = None
    marker_ids: Optional[List[str]] = None
    # Additional fields from detailed ATC response
    processor: Optional[str] = None
    last_changed_by: Optional[str] = None
    exemption_approval: Optional[str] = None
    exemption_kind: Optional[str] = None
    checksum: Optional[str] = None
    tags: Optional[List["ATCTag"]] = None
    quickfix_info: Optional[str] = None
    quickfix_capabilities: Optional[Dict[str, bool]] = None


class ATCWorklist(BaseModel):
    """ATC worklist"""
    id: str
    timestamp: str
    objects: List["ATCObject"]


class ATCObject(BaseModel):
    """ATC object"""
    uri: str
    type: str
    name: str
    package_name: str
    findings: List["ATCFinding"]


class ATCFinding(BaseModel):
    """ATC finding"""
    uri: str
    location: str
    priority: int
    check_id: str
    check_title: str
    message_id: str
    message_title: str
    quickfix_info: str
    documentation_url: Optional[str] = None
    documentation: Optional[str] = None
    tags: List["ATCTag"]


class ATCTag(BaseModel):
    """ATC tag"""
    name: str
    value: str


class ATCRunStatus(BaseModel):
    """ATC run status"""
    status: Literal["running", "finished", "failed"]
    result_url: Optional[str] = None
    worklist_url: Optional[str] = None


class ObjectReference(BaseModel):
    """Object reference"""
    uri: str


class SyntaxError(BaseModel):
    """Syntax error"""
    line: int
    column: Optional[int] = None
    message: str
    severity: Literal["ERROR", "FATAL"]


class SyntaxWarning(BaseModel):
    """Syntax warning"""
    line: int
    column: Optional[int] = None
    message: str
    severity: Literal["WARNING", "INFO"]


class SyntaxCheckResult(BaseModel):
    """Syntax check result"""
    success: bool
    errors: List[SyntaxError]
    warnings: List[SyntaxWarning]


class ActivationResult(BaseModel):
    """Activation result"""
    success: bool
    activated: bool
    errors: List[SyntaxError]
    warnings: List[SyntaxWarning]
    messages: List[str]


class ObjectOperationResult(BaseModel):
    """Object operation result"""
    created: Optional[bool] = None
    updated: Optional[bool] = None
    syntax_check_passed: bool
    activated: bool
    errors: List[SyntaxError]
    warnings: List[SyntaxWarning]


class UnitTestResult(BaseModel):
    """Unit test result"""
    test_class: str
    test_method: str
    status: Literal["SUCCESS", "FAILURE", "ERROR"]
    message: Optional[str] = None
    duration: Optional[float] = None


class ObjectType(str, Enum):
    PROG = "PROG"
    PROG_P = "PROG/P"
    PROG_I = "PROG/I"
    CLAS = "CLAS"
    INTF = "INTF"
    FUGR = "FUGR"
    DTEL = "DTEL"
    TABL = "TABL"
    STRU = "STRU"
    DDLS = "DDLS"
    BDEF = "BDEF"
    BIMPL = "BIMPL"
    SRVD = "SRVD"
    SRVB = "SRVB"
    # Enhancement types
    ENHOXH = "ENHOXH"    # Enhancement Implementation
    ENHOXHB = "ENHOXHB"  # BAdI Implementation
    ENHOXHH = "ENHOXHH"  # Source Code Plugin
    ENHSXS = "ENHSXS"    # Enhancement Spot
    ENHSXSB = "ENHSXSB"  # BAdI Enhancement Spot
    # DDIC types
    DOMA = "DOMA"        # Domain
    TTYP = "TTYP"        # Table Type
    SHLP = "SHLP"        # Search Help
    VIEW = "VIEW"        # View
    MCID = "MCID"        # Matchcode ID
    ENQU = "ENQU"        # Lock Object
    XINX = "XINX"        # Extension Index
    TABLDTI = "TABLDTI"  # Table Index
    TABLDTT = "TABLDTT"  # Technical Table Settings


class BindingType(str, Enum):
    ODATA_V2_UI = "ODATA_V2_UI"
    ODATA_V4_UI = "ODATA_V4_UI"
    ODATA_V2_WEB_API = "ODATA_V2_WEB_API"
    ODATA_V4_WEB_API = "ODATA_V4_WEB_API"


class CreateObjectRequest(BaseModel):
    """Create object request"""
    name: str
    type: ObjectType
    description: str
    package_name: Optional[str] = None  # Optional - defaults to $TMP if not provided
    source_code: Optional[str] = None
    service_definition: Optional[str] = None  # For SRVB
    binding_type: Optional[BindingType] = None  # For SRVB
    behavior_definition: Optional[str] = None  # For BIMPL
    transport_request: Optional[str] = None  # Transport number for object creation


class ATCCheckArgs(BaseModel):
    """ATC check arguments"""
    object_name: Optional[str] = None
    object_type: Optional[str] = None
    package_name: Optional[str] = None
    include_subpackages: Optional[bool] = None
    transport_number: Optional[str] = None
    variant: Optional[str] = None
    include_documentation: Optional[bool] = True
    max_wait_time: Optional[int] = None
    poll_interval: Optional[int] = None


class SearchResult(BaseModel):
    """Search result"""
    name: str
    type: str
    description: str
    package_name: str
    uri: str


class SearchOptions(BaseModel):
    """Search options"""
    query: str
    object_type: Optional[str] = None
    package_name: Optional[str] = None
    max_results: Optional[int] = 50
    include_inactive: Optional[bool] = False


class QuickfixEvaluation(BaseModel):
    """Quickfix evaluation"""
    quickfix_id: str
    name: str
    description: str
    marker_id: str


class QuickfixProposal(BaseModel):
    """Quickfix proposal"""
    quickfix_id: str
    name: str
    description: str
    source_changes: str
    success: bool


class ATCResultWithQuickfixes(ATCResult):
    """ATC result with quickfixes"""
    marker_ids: Optional[List[str]] = None
    quickfixes: Optional[List[QuickfixEvaluation]] = None


class PackageInfo(BaseModel):
    """Package information"""
    name: str
    description: Optional[str] = None
    package_type: Optional[str] = None
    software_component: Optional[str] = None
    application_component: Optional[str] = None
    transport_layer: Optional[str] = None
    translation_relevance: Optional[str] = None
    abap_language_version: Optional[str] = None
    super_package: Optional[str] = None
    created_by: Optional[str] = None
    created_at: Optional[str] = None
    changed_by: Optional[str] = None
    changed_at: Optional[str] = None


class TransportRequest(BaseModel):
    """Transport request information"""
    number: str
    description: Optional[str] = None
    type: Optional[str] = None
    status: Optional[str] = None
    owner: Optional[str] = None
    target: Optional[str] = None
    created_at: Optional[str] = None
    changed_at: Optional[str] = None
    objects: Optional[List[str]] = None


class CreatePackageRequest(BaseModel):
    """Create package request"""
    name: str
    description: str
    package_type: Optional[str] = "development"
    software_component: Optional[str] = None
    application_component: Optional[str] = None
    transport_layer: Optional[str] = None
    translation_relevance: Optional[str] = "not_relevant"
    abap_language_version: Optional[str] = "standard"
    super_package: Optional[str] = None
    transport_request: Optional[str] = None


class CreateTransportRequest(BaseModel):
    """Create transport request"""
    description: str
    type: Optional[str] = "K"  # Workbench request
    target: Optional[str] = None
    attributes: Optional[Dict[str, str]] = None


class PackageOperationResult(BaseModel):
    """Package operation result"""
    success: bool
    package_name: Optional[str] = None
    created: Optional[bool] = None
    updated: Optional[bool] = None
    message: str
    errors: List[str] = []
    warnings: List[str] = []


class TransportOperationResult(BaseModel):
    """Transport operation result"""
    success: bool
    transport_number: Optional[str] = None
    created: Optional[bool] = None
    updated: Optional[bool] = None
    message: str
    errors: List[str] = []
    warnings: List[str] = []


class InterfaceInfo(BaseModel):
    """Interface information"""
    name: str
    description: Optional[str] = None
    package_name: Optional[str] = None
    methods: Optional[List[str]] = None
    events: Optional[List[str]] = None
    types: Optional[List[str]] = None
    constants: Optional[List[str]] = None
    created_by: Optional[str] = None
    created_at: Optional[str] = None
    changed_by: Optional[str] = None
    changed_at: Optional[str] = None


class FunctionGroupInfo(BaseModel):
    """Function group information"""
    name: str
    description: Optional[str] = None
    package_name: Optional[str] = None
    function_modules: Optional[List[str]] = None
    includes: Optional[List[str]] = None
    created_by: Optional[str] = None
    created_at: Optional[str] = None
    changed_by: Optional[str] = None
    changed_at: Optional[str] = None


class FunctionModuleInfo(BaseModel):
    """Function module information"""
    name: str
    function_group: str
    description: Optional[str] = None
    importing_parameters: Optional[List[Dict[str, Any]]] = None
    exporting_parameters: Optional[List[Dict[str, Any]]] = None
    changing_parameters: Optional[List[Dict[str, Any]]] = None
    tables_parameters: Optional[List[Dict[str, Any]]] = None
    exceptions: Optional[List[str]] = None
    created_by: Optional[str] = None
    created_at: Optional[str] = None
    changed_by: Optional[str] = None
    changed_at: Optional[str] = None


class FunctionGroupIncludeInfo(BaseModel):
    """Function group include information"""
    name: str
    function_group: str
    description: Optional[str] = None
    include_type: Optional[str] = None
    created_by: Optional[str] = None
    created_at: Optional[str] = None


class CreateInterfaceRequest(BaseModel):
    """Create interface request"""
    name: str
    description: str
    package_name: str
    methods: Optional[List[Dict[str, Any]]] = None
    events: Optional[List[Dict[str, Any]]] = None
    types: Optional[List[Dict[str, Any]]] = None
    constants: Optional[List[Dict[str, Any]]] = None
    transport_request: Optional[str] = None


class CreateFunctionGroupRequest(BaseModel):
    """Create function group request"""
    name: str
    description: str
    package_name: str
    transport_request: Optional[str] = None


class CreateFunctionModuleRequest(BaseModel):
    """Create function module request"""
    name: str
    function_group: str
    description: str
    importing_parameters: Optional[List[Dict[str, Any]]] = None
    exporting_parameters: Optional[List[Dict[str, Any]]] = None
    changing_parameters: Optional[List[Dict[str, Any]]] = None
    tables_parameters: Optional[List[Dict[str, Any]]] = None
    exceptions: Optional[List[str]] = None
    source_code: Optional[str] = None
    transport_request: Optional[str] = None


class InterfaceOperationResult(BaseModel):
    """Interface operation result"""
    success: bool
    interface_name: Optional[str] = None
    created: Optional[bool] = None
    updated: Optional[bool] = None
    message: str
    errors: List[str] = []
    warnings: List[str] = []


class FunctionOperationResult(BaseModel):
    """Function operation result"""
    success: bool
    object_name: Optional[str] = None
    created: Optional[bool] = None
    updated: Optional[bool] = None
    message: str
    errors: List[str] = []
    warnings: List[str] = []


class EnhancementType(str, Enum):
    """Enhancement types"""
    ENHANCEMENT_IMPLEMENTATION = "enhoxh"
    BADI_IMPLEMENTATION = "enhoxhb"
    SOURCE_CODE_PLUGIN = "enhoxhh"
    ENHANCEMENT_SPOT = "enhsxs"
    BADI_ENHANCEMENT_SPOT = "enhsxsb"


class EnhancementInfo(BaseModel):
    """Enhancement information"""
    name: str
    type: EnhancementType
    description: Optional[str] = None
    package_name: Optional[str] = None
    enhancement_spot: Optional[str] = None
    badi_definition: Optional[str] = None
    implementing_class: Optional[str] = None
    filter_values: Optional[Dict[str, str]] = None
    active: Optional[bool] = None
    created_by: Optional[str] = None
    created_at: Optional[str] = None
    changed_by: Optional[str] = None
    changed_at: Optional[str] = None


class CreateEnhancementRequest(BaseModel):
    """Create enhancement request"""
    name: str
    type: EnhancementType
    description: str
    package_name: str
    enhancement_spot: Optional[str] = None
    badi_definition: Optional[str] = None
    implementing_class: Optional[str] = None
    filter_values: Optional[Dict[str, str]] = None
    source_code: Optional[str] = None
    transport_request: Optional[str] = None


class EnhancementSpotInfo(BaseModel):
    """Enhancement spot information"""
    name: str
    description: Optional[str] = None
    package_name: Optional[str] = None
    spot_type: Optional[str] = None
    badi_definitions: Optional[List[str]] = None
    enhancement_points: Optional[List[str]] = None
    created_by: Optional[str] = None
    created_at: Optional[str] = None


class BadiDefinitionInfo(BaseModel):
    """BAdI definition information"""
    name: str
    description: Optional[str] = None
    interface_name: Optional[str] = None
    enhancement_spot: Optional[str] = None
    multiple_use: Optional[bool] = None
    filter_dependent: Optional[bool] = None
    context_dependent: Optional[bool] = None
    instantiation: Optional[str] = None
    created_by: Optional[str] = None
    created_at: Optional[str] = None


class EnhancementOperationResult(BaseModel):
    """Enhancement operation result"""
    success: bool
    enhancement_name: Optional[str] = None
    created: Optional[bool] = None
    updated: Optional[bool] = None
    message: str
    errors: List[str] = []
    warnings: List[str] = []


# DDIC Object Types and Operations

class DDICObjectType(str, Enum):
    """DDIC object types"""
    DATA_ELEMENT = "dtel"
    DOMAIN = "doma"
    TABLE = "tabl"
    STRUCTURE = "stru"
    TABLE_TYPE = "ttyp"
    SEARCH_HELP = "shlp"
    VIEW = "view"
    LOCK_OBJECT = "enqu"
    EXTENSION_INDEX = "xinx"
    TABLE_INDEX = "tabldti"
    TECHNICAL_SETTINGS = "tabldtt"


class DataElementInfo(BaseModel):
    """Data element information"""
    name: str
    description: Optional[str] = None
    package_name: Optional[str] = None
    domain_name: Optional[str] = None
    data_type: Optional[str] = None
    length: Optional[int] = None
    decimals: Optional[int] = None
    output_length: Optional[int] = None
    field_labels: Optional[Dict[str, str]] = None  # Short, Medium, Long, Heading
    documentation: Optional[str] = None
    created_by: Optional[str] = None
    created_at: Optional[str] = None
    changed_by: Optional[str] = None
    changed_at: Optional[str] = None


class DomainInfo(BaseModel):
    """Domain information"""
    name: str
    description: Optional[str] = None
    package_name: Optional[str] = None
    data_type: Optional[str] = None
    length: Optional[int] = None
    decimals: Optional[int] = None
    output_length: Optional[int] = None
    conversion_exit: Optional[str] = None
    value_table: Optional[str] = None
    fixed_values: Optional[List[Dict[str, str]]] = None
    value_range: Optional[Dict[str, Any]] = None
    created_by: Optional[str] = None
    created_at: Optional[str] = None
    changed_by: Optional[str] = None
    changed_at: Optional[str] = None


class TableInfo(BaseModel):
    """Database table information"""
    name: str
    description: Optional[str] = None
    package_name: Optional[str] = None
    table_category: Optional[str] = None  # Transparent, Pooled, Cluster
    delivery_class: Optional[str] = None
    data_class: Optional[str] = None
    size_category: Optional[str] = None
    buffering: Optional[str] = None
    fields: Optional[List[Dict[str, Any]]] = None
    key_fields: Optional[List[str]] = None
    indexes: Optional[List[str]] = None
    foreign_keys: Optional[List[Dict[str, Any]]] = None
    created_by: Optional[str] = None
    created_at: Optional[str] = None
    changed_by: Optional[str] = None
    changed_at: Optional[str] = None


class StructureInfo(BaseModel):
    """Structure information"""
    name: str
    description: Optional[str] = None
    package_name: Optional[str] = None
    fields: Optional[List[Dict[str, Any]]] = None
    includes: Optional[List[str]] = None
    created_by: Optional[str] = None
    created_at: Optional[str] = None
    changed_by: Optional[str] = None
    changed_at: Optional[str] = None


class TableTypeInfo(BaseModel):
    """Table type information"""
    name: str
    description: Optional[str] = None
    package_name: Optional[str] = None
    line_type: Optional[str] = None
    access_type: Optional[str] = None  # Standard, Sorted, Hashed
    unique_key: Optional[bool] = None
    key_fields: Optional[List[str]] = None
    created_by: Optional[str] = None
    created_at: Optional[str] = None
    changed_by: Optional[str] = None
    changed_at: Optional[str] = None


class SearchHelpInfo(BaseModel):
    """Search help information"""
    name: str
    description: Optional[str] = None
    package_name: Optional[str] = None
    search_help_type: Optional[str] = None  # Elementary, Collective
    selection_method: Optional[str] = None
    dialog_type: Optional[str] = None
    parameters: Optional[List[Dict[str, Any]]] = None
    included_search_helps: Optional[List[str]] = None
    created_by: Optional[str] = None
    created_at: Optional[str] = None
    changed_by: Optional[str] = None
    changed_at: Optional[str] = None


class ViewInfo(BaseModel):
    """View information"""
    name: str
    description: Optional[str] = None
    package_name: Optional[str] = None
    view_type: Optional[str] = None  # Database, Projection, Maintenance, Help
    base_tables: Optional[List[str]] = None
    fields: Optional[List[Dict[str, Any]]] = None
    join_conditions: Optional[List[Dict[str, Any]]] = None
    selection_conditions: Optional[List[Dict[str, Any]]] = None
    created_by: Optional[str] = None
    created_at: Optional[str] = None
    changed_by: Optional[str] = None
    changed_at: Optional[str] = None


class LockObjectInfo(BaseModel):
    """Lock object information"""
    name: str
    description: Optional[str] = None
    package_name: Optional[str] = None
    primary_table: Optional[str] = None
    secondary_tables: Optional[List[str]] = None
    lock_parameters: Optional[List[Dict[str, Any]]] = None
    lock_mode: Optional[str] = None
    created_by: Optional[str] = None
    created_at: Optional[str] = None
    changed_by: Optional[str] = None
    changed_at: Optional[str] = None


class CreateDataElementRequest(BaseModel):
    """Create data element request"""
    name: str
    description: str
    package_name: str
    domain_name: Optional[str] = None
    data_type: Optional[str] = None
    length: Optional[int] = None
    decimals: Optional[int] = None
    field_labels: Optional[Dict[str, str]] = None
    transport_request: Optional[str] = None


class CreateDomainRequest(BaseModel):
    """Create domain request"""
    name: str
    description: str
    package_name: str
    data_type: str
    length: Optional[int] = None
    decimals: Optional[int] = None
    conversion_exit: Optional[str] = None
    value_table: Optional[str] = None
    fixed_values: Optional[List[Dict[str, str]]] = None
    transport_request: Optional[str] = None


class CreateTableRequest(BaseModel):
    """Create table request"""
    name: str
    description: str
    package_name: str
    table_category: Optional[str] = "TRANSP"
    delivery_class: Optional[str] = "A"
    fields: List[Dict[str, Any]]
    key_fields: List[str]
    transport_request: Optional[str] = None


class CreateStructureRequest(BaseModel):
    """Create structure request"""
    name: str
    description: str
    package_name: str
    fields: List[Dict[str, Any]]
    includes: Optional[List[str]] = None
    transport_request: Optional[str] = None


class CreateTableTypeRequest(BaseModel):
    """Create table type request"""
    name: str
    description: str
    package_name: str
    line_type: str
    access_type: Optional[str] = "STANDARD"
    unique_key: Optional[bool] = False
    key_fields: Optional[List[str]] = None
    transport_request: Optional[str] = None


class CreateSearchHelpRequest(BaseModel):
    """Create search help request"""
    name: str
    description: str
    package_name: str
    search_help_type: str  # ELEMENTARY or COLLECTIVE
    selection_method: Optional[str] = None
    parameters: Optional[List[Dict[str, Any]]] = None
    included_search_helps: Optional[List[str]] = None
    transport_request: Optional[str] = None


class CreateViewRequest(BaseModel):
    """Create view request"""
    name: str
    description: str
    package_name: str
    view_type: str  # D (Database), P (Projection), M (Maintenance), H (Help)
    base_tables: List[str]
    fields: List[Dict[str, Any]]
    join_conditions: Optional[List[Dict[str, Any]]] = None
    selection_conditions: Optional[List[Dict[str, Any]]] = None
    transport_request: Optional[str] = None


class CreateLockObjectRequest(BaseModel):
    """Create lock object request"""
    name: str
    description: str
    package_name: str
    primary_table: str
    secondary_tables: Optional[List[str]] = None
    lock_parameters: Optional[List[Dict[str, Any]]] = None
    lock_mode: Optional[str] = "E"
    transport_request: Optional[str] = None


class DDICOperationResult(BaseModel):
    """DDIC operation result"""
    success: bool
    object_name: Optional[str] = None
    object_type: Optional[str] = None
    created: Optional[bool] = None
    updated: Optional[bool] = None
    message: str
    errors: List[str] = []
    warnings: List[str] = []


# Update forward references
ATCResult.model_rebuild()
ATCWorklist.model_rebuild()
ATCObject.model_rebuild()
ATCFinding.model_rebuild()
ATCTag.model_rebuild()