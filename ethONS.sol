/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control 
 * functions, this simplifies the implementation of "user permissions". 
 */
contract Ownable {
  address public owner;

  /** 
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  function Ownable() {
    owner = msg.sender;
  }

  /**
   * @dev Throws if called by any account other than the owner. 
   */
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  /**
   * @dev Allows the current owner to transfer control of the contract to a newOwner.
   * @param newOwner The address to transfer ownership to. 
   */
  function transferOwnership(address newOwner) onlyOwner public {
    if (newOwner != address(0)) {
      owner = newOwner;
    }
  }

}


/**
 * @title Authorizable
 * @dev Allows to authorize access to certain function calls
 */
contract Authorizable is Ownable {

  address[] authorizers;
  mapping(address => uint) authorizerIndex;

  /**
   * @dev Throws if called by any account tat is not authorized. 
   */
  modifier onlyAuthorized {
    require(isAuthorized(msg.sender));
    _;
  }

  /**
   * @dev Contructor that authorizes the msg.sender. 
   */
  function Authorizable() {
    authorizers.length = 2;
    authorizers[1] = msg.sender;
    authorizerIndex[msg.sender] = 1;
  }

  /**
   * @dev Function to get a specific authorizer
   * @param authorizerIndex index of the authorizer to be retrieved.
   * @return The address of the authorizer.
   */
  function getAuthorizer(uint authorizerIndex) external view returns(address) {
    return address(authorizers[authorizerIndex + 1]);
  }

  /**
   * @dev Function to check if an address is authorized
   * @param _addr the address to check if it is authorized.
   * @return boolean flag if address is authorized.
   */
  function isAuthorized(address _addr) view returns(bool) {
    return authorizerIndex[_addr] > 0;
  }

  /**
   * @dev Function to add a new authorizer
   * @param _addr the address to add as a new authorizer.
   */
  function addAuthorized(address _addr) external onlyOwner {
    authorizerIndex[_addr] = authorizers.length;
    authorizers.length++;
    authorizers[authorizers.length - 1] = _addr;
  }
  
  /**
   * @dev Function to delete a authorizer
   * @param _addr the address to delete as a new authorizer.
   */
  function deleteAuthorized(address _addr) external onlyOwner {
    authorizerIndex[_addr] = 0;
  }

}


/**
 * Math operations with safety checks
 */
library SafeMath {
  function mul(uint a, uint b) internal returns (uint) {
    uint c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint a, uint b) internal returns (uint) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint a, uint b) internal returns (uint) {
    assert(b <= a);
    return a - b;
  }

  function add(uint a, uint b) internal returns (uint) {
    uint c = a + b;
    assert(c >= a);
    return c;
  }

  function max64(uint64 a, uint64 b) internal pure returns (uint64) {
    return a >= b ? a : b;
  }

  function min64(uint64 a, uint64 b) internal pure returns (uint64) {
    return a < b ? a : b;
  }

  function max256(uint256 a, uint256 b) internal pure returns (uint256) {
    return a >= b ? a : b;
  }

  function min256(uint256 a, uint256 b) internal pure returns (uint256) {
    return a < b ? a : b;
  }

}


/**
 * @title ONS
 * @dev Object Name Server 
 */
contract ONS is Ownable, Authorizable
{
    using SafeMath for uint;

    // GS1 code
    struct GS1code {
        uint gs1CodeListPointer; // needed to delete a "GS1code"
        // GS1code has many "ONSrecord"
        bytes32[] ONSrecordKeys;
        mapping(bytes32 => uint) ONSrecordKeyPointers;
    }
    
    mapping(bytes32 => GS1code) public GS1codes;
    bytes32[] public GS1codeList;

    // ONS record NAPTR format
    struct ONSrecord
    {
        uint ONSrecordListPointer; // needed to delete a "ONSrecord"
        bytes32 GS1codeKey; // ONSrecord has exactly one "GS1code"    
		bytes32 ServiceTypeKey; // ONSrecord has one "ServiceType"
		
        // ONS record properties
        //uint32 order;
        //uint32 pref;
        uint8 flags;
        bytes32 service;
        string regexp;
        //string replacement;
    }
    
    mapping(bytes32 => ONSrecord) public ONSrecords;
    bytes32[] public ONSrecordList;

    // Servicetype xml
    struct ServiceType
    {
		uint ServiceTypeListPointer; // needed to delete a "ServiceType"
       
        // ONS ServiceType properties
        //bytes32 _serviceTypeKeyentifier;
        bool abstrct;
        bytes32 extends;
        string WSDL;
        string homepage;
        mapping(bytes32 => string) documentations;
        bytes32[] obsoletes;
        bytes32[] obsoletedBy;
    }
	
	mapping(bytes32 => ServiceType) public ServiceTypes;
	bytes32[] public ServiceTypeList;
    
    event LogNewGS1code(address sender, bytes32 _gs1CodeKey);
    event LogNewONSrecord(address sender, bytes32 _onsRecordKey, bytes32 _serviceTypeKey, bytes32 _gs1CodeKey);
    event LogNewServiceType(address sender, bytes32 _serviceTypeKey);
    event LogGS1codeDeleted(address sender, bytes32 _gs1CodeKey);
    event LogONSrecordDeleted(address sender, bytes32 _onsRecordKey);
    event LogServiceTypeDeleted(address sender, bytes32 _serviceTypeKey);
    
    /**
    * @dev Function to get the number of GS1codes
    * @return uint GS1codeCount.
    */
    function getGS1codeCount() public view returns(uint gs1CodeCount) 
    {
        return GS1codeList.length;
    }
    
    /**
    * @dev Function to get the number of ONSrecords
    * @return uint ONSrecordCount.
    */
    function getONSrecordCount() public view returns(uint ONSrecordCount)
    {
        return ONSrecordList.length;
    }
    
	/**
    * @dev Function to get the number of ServiceTypes
    * @return uint ServiceTypeCount.
    */
    function getServiceTypeCount() public view returns(uint ServiceTypeCount)
    {
        return ServiceTypeList.length;
    }
	
    /**
    * @dev Function to check if _gs1CodeKey exist
    * @param _gs1CodeKey the bytes32 to check if it exist.
    * @return boolean flag if _gs1CodeKey exist.
    */
    function isGS1code(bytes32 _gs1CodeKey) public view returns(bool isIndeed) 
    {
        if(GS1codeList.length==0) return false;
        return GS1codeList[GS1codes[_gs1CodeKey].gs1CodeListPointer]==_gs1CodeKey;
    }
    
    /**
    * @dev Function to check if _onsRecordKey exist
    * @param _onsRecordKey the bytes32 to check if it exist.
    * @return boolean flag if _onsRecordKey exist.
    */
    function isONSrecord(bytes32 _onsRecordKey) public view returns(bool isIndeed) 
    {
        if(ONSrecordList.length==0) return false;
        return ONSrecordList[ONSrecords[_onsRecordKey].ONSrecordListPointer]==_onsRecordKey;
    }
	
	/**
    * @dev Function to check if _serviceTypeKey exist
    * @param _serviceTypeKey the bytes32 to check if it exist.
    * @return boolean flag if _serviceTypeKey exist.
    */
    function isServiceType(bytes32 _serviceTypeKey) public view returns(bool isIndeed) 
    {
        if(ServiceTypeList.length==0) return false;
        return ServiceTypeList[ServiceTypes[_serviceTypeKey].ServiceTypeListPointer]==_serviceTypeKey;
    }
    
    /**
    * @dev Function to get the number of ONSrecords which depend on _gs1CodeKey
    * @param _gs1CodeKey the bytes32 to find the number of ONSrecords which depend on _gs1CodeKey.
    * @return uint the number of ONSrecords which depend on _gs1CodeKey.
    */
    function getGS1codeONSrecordCount(bytes32 _gs1CodeKey) public view returns(uint onsRecordCount) 
    {
        if(!isGS1code(_gs1CodeKey)) throw;
        return GS1codes[_gs1CodeKey].ONSrecordKeys.length;
    }
    
    /**
    * @dev Function to get ONSrecordKey using index of ONSrecords included in _gs1CodeKey
    * @param _gs1CodeKey the bytes32 to get ONSrecordKey.
    * @param row the row to get ONSrecordKey.
    * @return bytes32 the ONSrecordKey.
    */
    function getGS1codeONSrecordAtIndex(bytes32 _gs1CodeKey, uint row) public view returns(bytes32 ONSrecordKey) 
    {
        if(!isGS1code(_gs1CodeKey)) throw;
        return GS1codes[_gs1CodeKey].ONSrecordKeys[row];
    }
    
    /**
    * @dev Function to get ONSRecord properties using _onsRecordKey
    * @param _onsRecordKey the bytes32 to get ONSrecord properties.
    * @return bytes32 bytes32 _onsRecordKey_, bytes32 _gs1CodeKey_, uint8 _flags_, bytes32 _serviceTypeKey, string _regexp_.
    */
    function getONSrecord(bytes32 _onsRecordKey) public view returns(bytes32 _onsRecordKey_, bytes32 _gs1CodeKey_, uint8 _flags_, bytes32 _serviceTypeKey, string _regexp_) 
    {
        bytes32 _gs1CodeKey = ONSrecords[_onsRecordKey].GS1codeKey;
        uint8 flags = ONSrecords[_onsRecordKey].flags;
        bytes32 service = ONSrecords[_onsRecordKey].service;
        string regexp = ONSrecords[_onsRecordKey].regexp;
        
        return (_onsRecordKey, _gs1CodeKey, flags, service, regexp);
    }

	/**
    * @dev Function to get GS1codeKey using _onsRecordKey
    * @param _onsRecordKey the bytes32 to get GS1codeKey.
    * @return bytes32 the GS1codeKey.
    */
    function getONSrecordGS1code(bytes32 _onsRecordKey) public view returns(bytes32 GS1codeKey) 
    {
        if(!isONSrecord(_onsRecordKey)) throw;
        return ONSrecords[_onsRecordKey].GS1codeKey;
    }
	
	/**
    * @dev Function to get ServiceTypeKey using _onsRecordKey
    * @param _onsRecordKey the bytes32 to get ServiceTypeKey.
    * @return bytes32 the ServiceTypeKey.
    */
    function getONSrecordServiceType(bytes32 _onsRecordKey) public view returns(bytes32 ServiceTypeKey) 
    {
        if(!isONSrecord(_onsRecordKey)) throw;
        return ONSrecords[_onsRecordKey].ServiceTypeKey;
    }
	
	/**
    * @dev Function to get ServiceType properties using _serviceTypeKey
    * @param _serviceTypeKey the bytes32 to get ServiceType properties.
    * @param _languageCodeKey the bytes32 to get documentation.
    * @return bytes32 _serviceTypeKey_, bool _abstrct_, bytes32 _extends_, string _WSDL_, string _homepage_, string _domentation_ (, bytes32 _obsoletes_, bytes32 _obsoletedBy_)
    */
    function getServiceType(bytes32 _serviceTypeKey, bytes32 _languageCodeKey) public view returns(bytes32 _serviceTypeKey_, bool _abstrct_, bytes32 _extends_, string _WSDL_, string _homepage_, string _domentation_/*, bytes32 _obsoletes_, bytes32 _obsoletedBy_*/) 
    {
		bool abstrct = ServiceTypes[_serviceTypeKey].abstrct;
        bytes32 extends = ServiceTypes[_serviceTypeKey].extends;
        string WSDL = ServiceTypes[_serviceTypeKey].WSDL;
        string homepage = ServiceTypes[_serviceTypeKey].homepage;
        string documentation = ServiceTypes[_serviceTypeKey].documentations[_languageCodeKey];
        //bytes32 obsoleteLast = ServiceTypes[_serviceTypeKey].obsoletes[ServiceTypes[_serviceTypeKey].obsoletes.length-1];
        //bytes32 obsoletedByLast = ServiceTypes[_serviceTypeKey].obsoletedBy[ServiceTypes[_serviceTypeKey].obsoletedBy.length-1];
        
        return (_serviceTypeKey, abstrct, extends, WSDL, homepage, documentation/*, obsoleteLast, obsoletedByLast*/);
    }
    
    /**
    * @dev Function to add new GS1code
    * @param _gs1CodeKey the bytes32 to add new GS1code.
    * @return boolean flag if GS1code is added.
    */
    function addGS1code(bytes32 _gs1CodeKey) public returns(bool success) 
    {
        if(isGS1code(_gs1CodeKey)) throw; // duplicate key prohibited
        GS1codes[_gs1CodeKey].gs1CodeListPointer = GS1codeList.push(_gs1CodeKey)-1;
        LogNewGS1code(msg.sender, _gs1CodeKey);
        return true;
    }
    
    /**
    * @dev Function to add new ONSRecord
    * @param _onsRecordKey the bytes32 to add new ONSRecord.
    * @param _gs1CodeKey the bytes32 to bind ONSRecord to GS1code.
    * @param _flags the uint8 to flags ('T' or 'U')
    * @param _serviceTypeKey the string to URI pointing ServiceType.
    * @param _regexp the string to URI pointing service page.
    * @return boolean flag if ONSrecord is added.
    */
    function addONSrecord(bytes32 _onsRecordKey, bytes32 _gs1CodeKey, uint8 _flags, bytes32 _serviceTypeKey, string _regexp) public returns(bool success) 
    {
        if(!isGS1code(_gs1CodeKey)) throw;
        if(isONSrecord(_onsRecordKey)) throw; // duplicate key prohibited
        ONSrecords[_onsRecordKey].ONSrecordListPointer = ONSrecordList.push(_onsRecordKey)-1;
        ONSrecords[_onsRecordKey].GS1codeKey = _gs1CodeKey; 
        
        ONSrecords[_onsRecordKey].flags = _flags;
        ONSrecords[_onsRecordKey].service = _serviceTypeKey; // This is _serviceTypeKey
        ONSrecords[_onsRecordKey].regexp = _regexp;
        
        // We also maintain a list of "ONSrecord" that refer to the "GS1code", so ... 
        GS1codes[_gs1CodeKey].ONSrecordKeyPointers[_onsRecordKey] = GS1codes[_gs1CodeKey].ONSrecordKeys.push(_onsRecordKey) - 1;
        LogNewONSrecord(msg.sender, _onsRecordKey, _serviceTypeKey, _gs1CodeKey);
        return true;
    }
	
	/**
    * @dev Function to add new ServiceType
    * @param _serviceTypeKey the bytes32 to add new serviceType.
    * @param _abstrct the boolean to notice that serviceType is abstrct or not.
    * @param _extends the bytes32 to point extends serviceType.
    * @param _WSDL the string to URI of WSDL.
    * @param _homepage the string to URI pointing serviceType homepage.
    * @param _languageCodeKey the bytes32 to string of languageCode.
    * @param _location the string to point URI of documentation location.
    * @param _obsoletes the array of bytes32 to point obsoletes serviceType.
    * @param _obsoletedBy the array of bytes32 to point obsoleteBy serviceTypes.    
    * @return boolean flag if ONSrecord is added.
    */
    function addServiceType(bytes32 _serviceTypeKey, bool _abstrct, bytes32 _extends, string _WSDL, string _homepage, bytes32 _languageCodeKey, string _location, bytes32 _obsoletes, bytes32 _obsoletedBy) public returns(bool success) 
    {
        if(!isServiceType(_serviceTypeKey)) throw; // duplicate key prohibited
        ServiceTypes[_serviceTypeKey].ServiceTypeListPointer = ServiceTypeList.push(_serviceTypeKey)-1;
		
		ServiceTypes[_serviceTypeKey].abstrct = _abstrct;
		ServiceTypes[_serviceTypeKey].extends = _extends;
		ServiceTypes[_serviceTypeKey].WSDL = _WSDL;
		ServiceTypes[_serviceTypeKey].homepage = _homepage;
		ServiceTypes[_serviceTypeKey].documentations[_languageCodeKey] = _location;
		ServiceTypes[_serviceTypeKey].obsoletes[ServiceTypes[_serviceTypeKey].obsoletes.length] = _obsoletes;
		ServiceTypes[_serviceTypeKey].obsoletedBy[ServiceTypes[_serviceTypeKey].obsoletedBy.length] = _obsoletedBy;
       
        LogNewServiceType(msg.sender, _serviceTypeKey);
        return true;
    }

    /**
    * @dev Function to delete GS1code
    * @param _gs1CodeKey the bytes32 to delete GS1code. 
    * @return boolean flag if GS1code is deleted.
    */
    function deleteGS1code(bytes32 _gs1CodeKey) onlyOwner returns(bool succes) 
    {
        if(!isGS1code(_gs1CodeKey)) throw;
        
        // the following would break referential integrity
        if(GS1codes[_gs1CodeKey].ONSrecordKeys.length > 0) throw; 
        
        uint rowToDelete = GS1codes[_gs1CodeKey].gs1CodeListPointer;
        bytes32 keyToMove = GS1codeList[GS1codeList.length-1];
        GS1codeList[rowToDelete] = keyToMove;
        GS1codes[keyToMove].gs1CodeListPointer = rowToDelete;
        GS1codeList.length--;
        LogGS1codeDeleted(msg.sender, _gs1CodeKey);
        return true;
    }    

    /**
    * @dev Function to delete ONSRecord
    * @param _onsRecordKey the bytes32 to delete ONSRecord. 
    * @return boolean flag if ONSRecord is deleted.
    */
    function deleteONSrecord(bytes32 _onsRecordKey) onlyOwner returns(bool success) 
    {
        if(!isONSrecord(_onsRecordKey)) throw; // non-existant key
        
        // delete from the Many table
        uint rowToDelete = ONSrecords[_onsRecordKey].ONSrecordListPointer;
        bytes32 keyToMove = ONSrecordList[ONSrecordList.length-1];
        ONSrecordList[rowToDelete] = keyToMove;
        ONSrecords[_onsRecordKey].ONSrecordListPointer = rowToDelete;
        ONSrecordList.length--;
        
        // we ALSO have to delete this key from the list in the GS1code
        bytes32 _gs1CodeKey = ONSrecords[_onsRecordKey].GS1codeKey; 
        rowToDelete = GS1codes[_gs1CodeKey].ONSrecordKeyPointers[_onsRecordKey];
        keyToMove = GS1codes[_gs1CodeKey].ONSrecordKeys[GS1codes[_gs1CodeKey].ONSrecordKeys.length-1];
        GS1codes[_gs1CodeKey].ONSrecordKeys[rowToDelete] = keyToMove;
        GS1codes[_gs1CodeKey].ONSrecordKeyPointers[keyToMove] = rowToDelete;
        GS1codes[_gs1CodeKey].ONSrecordKeys.length--;
        LogONSrecordDeleted(msg.sender, _onsRecordKey);
        return true;
    }
	
	/**
    * @dev Function to delete ServiceType
    * @param _serviceTypeKey the bytes32 to delete ServiceType. 
    * @return boolean flag if ServiceType is deleted.
    */
    function deleteServiceType(bytes32 _serviceTypeKey) onlyOwner returns(bool succes) 
    {
		// this function will be never used
        if(isServiceType(_serviceTypeKey)) throw;
         
        uint rowToDelete = ServiceTypes[_serviceTypeKey].ServiceTypeListPointer;
        bytes32 keyToMove = ServiceTypeList[ServiceTypeList.length-1];
        ServiceTypeList[rowToDelete] = keyToMove;
        ServiceTypes[keyToMove].ServiceTypeListPointer = rowToDelete;
        ServiceTypeList.length--;
        LogServiceTypeDeleted(msg.sender, _serviceTypeKey);
        return true;
    }
    
}
