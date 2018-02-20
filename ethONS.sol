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
contract Authorizable {

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
  function addAuthorized(address _addr) external onlyAuthorized {
    authorizerIndex[_addr] = authorizers.length;
    authorizers.length++;
    authorizers[authorizers.length - 1] = _addr;
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
        uint gs1CodePointer; // needed to delete a "GS1code"
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

        // ONS record properties
        //uint32 order;
        //uint32 pref;
        uint8 flags;
        string service;
        string regexp;
        //string replacement;
    }
    
    mapping(bytes32 => ONSrecord) public ONSrecords;
    bytes32[] public ONSrecordList;

    // Servicetype xml
    struct documentation
    {
        // ONS Servicetype's documentation properties
        string languageCode;
        string location;
    }

    struct ServiceType
    {
        // ONS ServiceType properties
        string serviceTypeIdentifier;
        bool abstrac;
        string extends;
        string WSDL;
        string homepage;
        mapping(uint8 => documentation) docs;
        string[] obsoletes;
        string[] obsoletedBy;
    }
 
    //uint256 totalONSrecord = 0;
    //ONSrecord[] ONSrecords;
    //mapping(string => uint32[]) ONSrecordIndex;
    //mapping(string => ServiceType) ServiceTypes;
    
    event LogNewGS1code(address sender, bytes32 gs1CodeId);
    event LogNewONSrecord(address sender, bytes32 onsRecordId, bytes32 gs1CodeId);
    event LogGS1codeDeleted(address sender, bytes32 gs1CodeId);
    event LogONSrecordDeleted(address sender, bytes32 onsRecordId);
    
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
    * @dev Function to check if gs1CodeId exist
    * @param gs1CodeId the bytes32 to check if it exist.
    * @return boolean flag if gs1CodeId exist.
    */
    function isGS1code(bytes32 gs1CodeId) public view returns(bool isIndeed) 
    {
        if(GS1codeList.length==0) return false;
        return GS1codeList[GS1codes[gs1CodeId].gs1CodePointer]==gs1CodeId;
    }
    
    /**
    * @dev Function to check if onsRecordId exist
    * @param onsRecordId the bytes32 to check if it exist.
    * @return boolean flag if onsRecordId exist.
    */
    function isONSrecord(bytes32 onsRecordId) public view returns(bool isIndeed) 
    {
        if(ONSrecordList.length==0) return false;
        return ONSrecordList[ONSrecords[onsRecordId].ONSrecordListPointer]==onsRecordId;
    }
    
    /**
    * @dev Function to get the number of ONSrecords which depedn on gs1CodeId
    * @param gs1CodeId the bytes32 to find the number of ONSrecords which depedn on gs1CodeId.
    * @return uint the number of ONSrecords which depedn on gs1CodeId.
    */
    function getGS1codeONSrecordCount(bytes32 gs1CodeId) public view returns(uint onsRecordCount) 
    {
        if(!isGS1code(gs1CodeId)) throw;
        return GS1codes[gs1CodeId].ONSrecordKeys.length;
    }
    
    /**
    * @dev Function to get ONSrecordKey using index of ONSrecords included in gs1CodeId
    * @param gs1CodeId the bytes32 to get ONSrecordKey.
    * @param row the row to get ONSrecordKey.
    * @return bytes32 the ONSrecordKey.
    */
    function getGS1codeONSrecordAtIndex(bytes32 gs1CodeId, uint row) public view returns(bytes32 ONSrecordKey) 
    {
        if(!isGS1code(gs1CodeId)) throw;
        return GS1codes[gs1CodeId].ONSrecordKeys[row];
    }
    
    /**
    * @dev Function to check if an address is authorized
    * @param onsRecordId the bytes32 to get ONSrecord properties.
    * @return bytes32 onsRecordId, bytes32 gs1CodeId, uint8 flags, string service, string regexp.
    */
    function getONSrecord(bytes32 onsRecordId) public view returns(bytes32 o, bytes32 g, uint8 f, string s, string r) 
    {
        bytes32 gs1CodeId = ONSrecords[onsRecordId].GS1codeKey;
        uint8 flags = ONSrecords[onsRecordId].flags;
        string service = ONSrecords[onsRecordId].service;
        string regexp = ONSrecords[onsRecordId].regexp;
        
        return (onsRecordId, gs1CodeId, flags, service, regexp);
    }
    
    /**
    * @dev Function to add new GS1code
    * @param gs1CodeId the bytes32 to add new GS1code.
    * @return boolean flag if GS1code is added.
    */
    function addGS1code(bytes32 gs1CodeId) public returns(bool success) 
    {
        if(isGS1code(gs1CodeId)) throw; // duplicate key prohibited
        GS1codes[gs1CodeId].gs1CodePointer = GS1codeList.push(gs1CodeId)-1;
        LogNewGS1code(msg.sender, gs1CodeId);
        return true;
    }
    
    /**
    * @dev Function to add new ONSRecord
    * @param onsRecordId the bytes32 to add new ONSRecord.
    * @param gs1CodeId the bytes32 to bind ONSRecord to GS1code.
    * @param f the uint8 to flags ('T' or 'U')
    * @param s the string to service URI pointing ServiceType.
    * @param r the string to regexp URI pointing service page.
    * @return boolean flag if ONSrecord is added.
    */
    function addONSrecord(bytes32 onsRecordId, bytes32 gs1CodeId, uint8 f, string s, string r) public returns(bool success) 
    {
        if(!isGS1code(gs1CodeId)) throw;
        if(isONSrecord(onsRecordId)) throw; // duplicate key prohibited
        ONSrecords[onsRecordId].ONSrecordListPointer = ONSrecordList.push(onsRecordId)-1;
        ONSrecords[onsRecordId].GS1codeKey = gs1CodeId; 
        
        ONSrecords[onsRecordId].flags = f;
        ONSrecords[onsRecordId].service = s;
        ONSrecords[onsRecordId].regexp = r;
        
        // We also maintain a list of "ONSrecord" that refer to the "GS1code", so ... 
        GS1codes[gs1CodeId].ONSrecordKeyPointers[onsRecordId] = GS1codes[gs1CodeId].ONSrecordKeys.push(onsRecordId) - 1;
        LogNewONSrecord(msg.sender, onsRecordId, gs1CodeId);
        return true;
    }

    /**
    * @dev Function to delete GS1code
    * @param gs1CodeId the bytes32 to delete GS1code. 
    * @return boolean flag if GS1code is deleted.
    */
    function deleteGS1code(bytes32 gs1CodeId) onlyOwner returns(bool succes) 
    {
        if(!isGS1code(gs1CodeId)) throw;
        
        // the following would break referential integrity
        if(GS1codes[gs1CodeId].ONSrecordKeys.length > 0) throw; 
        
        uint rowToDelete = GS1codes[gs1CodeId].gs1CodePointer;
        bytes32 keyToMove = GS1codeList[GS1codeList.length-1];
        GS1codeList[rowToDelete] = keyToMove;
        GS1codes[keyToMove].gs1CodePointer = rowToDelete;
        GS1codeList.length--;
        LogGS1codeDeleted(msg.sender, gs1CodeId);
        return true;
    }    

    /**
    * @dev Function to delete ONSRecord
    * @param onsRecordId the bytes32 to delete ONSRecord. 
    * @return boolean flag if ONSRecord is deleted.
    */
    function deleteONSrecord(bytes32 onsRecordId) onlyOwner returns(bool success) 
    {
        if(!isONSrecord(onsRecordId)) throw; // non-existant key
        
        // delete from the Many table
        uint rowToDelete = ONSrecords[onsRecordId].ONSrecordListPointer;
        bytes32 keyToMove = ONSrecordList[ONSrecordList.length-1];
        ONSrecordList[rowToDelete] = keyToMove;
        ONSrecords[onsRecordId].ONSrecordListPointer = rowToDelete;
        ONSrecordList.length--;
        
        // we ALSO have to delete this key from the list in the GS1code
        bytes32 gs1CodeId = ONSrecords[onsRecordId].GS1codeKey; 
        rowToDelete = GS1codes[gs1CodeId].ONSrecordKeyPointers[onsRecordId];
        keyToMove = GS1codes[gs1CodeId].ONSrecordKeys[GS1codes[gs1CodeId].ONSrecordKeys.length-1];
        GS1codes[gs1CodeId].ONSrecordKeys[rowToDelete] = keyToMove;
        GS1codes[gs1CodeId].ONSrecordKeyPointers[keyToMove] = rowToDelete;
        GS1codes[gs1CodeId].ONSrecordKeys.length--;
        LogONSrecordDeleted(msg.sender, onsRecordId);
        return true;
    }
    
}
