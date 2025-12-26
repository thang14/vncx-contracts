// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/**
 * @title VNCXMasterAnchor
 * @dev Optimized supply chain data verification system for enterprises (Multi-tenancy).
 * Supports: Direct submission and Relay submission with a single signature for the entire batch.
 * Uses EIP-712 for structured data signing.
 */
contract VNCXMasterAnchor is Ownable, EIP712 {
    bytes32 private constant BATCH_RECORD_TYPEHASH = keccak256(
        "BatchRecord(bytes32 orgId,bytes32 batchHash)"
    );

    constructor() Ownable(msg.sender) EIP712("VNCXMasterAnchor", "1") {}

    // --- Data Structures & State ---

    /**
     * @dev Struct to store detailed verification information for an organization
     */
    struct OrgVerificationInfo {
        bool isVerified;              // Verification status
        address verifier;              // Address that performed verification (owner or operator)
        uint256 verifiedAt;            // Timestamp when verified
        bytes32 metadataHash;          // Hash of verified metadata (org name, domain, etc.)
        string verificationNote;       // Optional note about what was verified
    }

    // mapping(orgId => enterprise owner wallet address)
    mapping(bytes32 => address) public orgOwners;
    
    // mapping(orgId => verification information)
    mapping(bytes32 => OrgVerificationInfo) public orgVerificationInfo;
    
    // mapping(orgId => mapping(worker wallet address => authorization status))
    mapping(bytes32 => mapping(address => bool)) public authorizedWorkers;
    
    // mapping(operator wallet address => operator status)
    mapping(address => bool) public operators;
    
    // mapping(dataHash => status) prevents duplicate evidence recording
    mapping(bytes32 => bool) public processedHashes;

    // --- Events ---

    event OrgRegistered(bytes32 indexed orgId, address indexed owner);
    event OrgVerified(
        bytes32 indexed orgId, 
        bool status, 
        address indexed verifier,
        bytes32 metadataHash,
        string verificationNote
    );
    event OperatorRegistered(address indexed operator, bool status);
    event WorkerAuthorized(bytes32 indexed orgId, address indexed worker, bool status);
    event AnchorRecorded(
        bytes32 indexed orgId, 
        bytes32 indexed batchId, 
        bytes32 dataHash, 
        address indexed submitter
    );

    // --- Admin Functions (Only VNCX can call) ---

    function registerOrg(bytes32 _orgId, address _owner) external onlyOwner {
        require(orgOwners[_orgId] == address(0), "VNCX: Org already registered");
        require(_owner != address(0), "VNCX: Invalid address");
        orgOwners[_orgId] = _owner;
        emit OrgRegistered(_orgId, _owner);
    }

    function registerOperator(address _operator, bool _status) external onlyOwner {
        require(_operator != address(0), "VNCX: Invalid address");
        operators[_operator] = _status;
        emit OperatorRegistered(_operator, _status);
    }

    /**
     * @dev Verify or unverify an organization with detailed information.
     * Only contract owner or registered operators can call this function.
     * @param _orgId Organization ID as bytes32
     * @param _status true to verify, false to unverify
     * @param _metadataHash Hash of verified metadata (org name, domain, registration info, etc.)
     * @param _verificationNote Optional note describing what was verified
     */
    function verifyOrg(
        bytes32 _orgId, 
        bool _status,
        bytes32 _metadataHash,
        string calldata _verificationNote
    ) external {
        require(
            msg.sender == owner() || operators[msg.sender],
            "VNCX: Only Owner or Operator can verify"
        );
        require(orgOwners[_orgId] != address(0), "VNCX: Org not registered");
        
        orgVerificationInfo[_orgId] = OrgVerificationInfo({
            isVerified: _status,
            verifier: msg.sender,
            verifiedAt: block.timestamp,
            metadataHash: _metadataHash,
            verificationNote: _verificationNote
        });
        
        emit OrgVerified(_orgId, _status, msg.sender, _metadataHash, _verificationNote);
    }

    // --- Enterprise Functions (Org Owner calls) ---

    function authorizeWorker(bytes32 _orgId, address _worker, bool _status) external {
        require(msg.sender == orgOwners[_orgId], "VNCX: Only Org Owner can authorize");
        authorizedWorkers[_orgId][_worker] = _status;
        emit WorkerAuthorized(_orgId, _worker, _status);
    }

    // --- MECHANISM 1: DIRECT SUBMISSION (Worker pays their own Gas) ---

    /**
     * @dev Records a batch of data when msg.sender is an authorized wallet.
     * Optimized: Check authorization once for the entire array.
     * @param _orgId Organization ID as bytes32 (should be keccak256 of original string)
     * @param _batchIds Array of batch IDs as bytes32
     * @param _dataHashes Array of data hashes as bytes32
     */
    function recordOrgBatch(
        bytes32 _orgId,
        bytes32[] calldata _batchIds,
        bytes32[] calldata _dataHashes
    ) external {
        // Check msg.sender authorization
        require(
            msg.sender == orgOwners[_orgId] || authorizedWorkers[_orgId][msg.sender],
            "VNCX: Not authorized for this Org"
        );
        
        _processBatch(_orgId, _batchIds, _dataHashes);
    }

    // --- MECHANISM 2: RELAY SUBMISSION (User signs, Backend pays Gas) ---

    /**
     * @dev Records a batch of data based on signature authentication using EIP-712.
     * OPTIMIZED: Client pre-computes batchHash and splits signature to r, s, v to save gas.
     * @param _orgId Organization ID as bytes32
     * @param _batchIds Array of batch IDs as bytes32
     * @param _dataHashes Array of data hashes as bytes32
     * @param _batchHash Pre-computed hash of the batch (keccak256(abi.encode(_orgId, _batchIds, _dataHashes)))
     * @param _r First 32 bytes of the EIP-712 signature (bytes32)
     * @param _s Next 32 bytes of the EIP-712 signature (bytes32)
     * @param _v Recovery byte (uint8)
     */
    function recordRelayedBatch(
        bytes32 _orgId,
        bytes32[] calldata _batchIds,
        bytes32[] calldata _dataHashes,
        bytes32 _batchHash,
        bytes32 _r,
        bytes32 _s,
        uint8 _v
    ) external {
        // 1. Verify that the provided batchHash matches the actual batch data
        bytes32 computedBatchHash = keccak256(abi.encode(_orgId, _batchIds, _dataHashes));
        require(computedBatchHash == _batchHash, "VNCX: Batch hash mismatch");
        
        // 2. Hash the structured data according to EIP-712
        // Typed data hash: keccak256(abi.encode(BATCH_RECORD_TYPEHASH, orgId, batchHash))
        bytes32 structHash = keccak256(abi.encode(BATCH_RECORD_TYPEHASH, _orgId, _batchHash));
        
        // 3. Hash with domain separator (EIP-712 standard)
        bytes32 typedDataHash = _hashTypedDataV4(structHash);
        
        // 4. Recover signer from EIP-712 signature (r, s, v)
        address signer = ECDSA.recover(typedDataHash, _v, _r, _s);
        
        // 5. Check if the signer has permission for this Org
        require(
            signer == orgOwners[_orgId] || authorizedWorkers[_orgId][signer],
            "VNCX: Invalid Batch Signature or Signer"
        );

        _processBatch(_orgId, _batchIds, _dataHashes);
    }

    // --- Internal function to process data recording logic ---

    function _processBatch(
        bytes32 _orgId,
        bytes32[] calldata _batchIds,
        bytes32[] calldata _dataHashes
    ) internal {
        uint256 length = _dataHashes.length;
        require(length > 0, "VNCX: Empty batch");
        require(length == _batchIds.length, "VNCX: Array mismatch");

        for (uint256 i = 0; i < length; i++) {
            // dataHashes are already bytes32, no need to hash again
            bytes32 hashKey = _dataHashes[i];
            
            if (!processedHashes[hashKey]) {
                processedHashes[hashKey] = true;
                emit AnchorRecorded(_orgId, _batchIds[i], _dataHashes[i], msg.sender);
            }
        }
    }

    // --- View Functions ---

    /**
     * @dev Verify if a data hash has been recorded.
     * @param _dataHash Data hash as bytes32
     * @return true if the hash has been processed, false otherwise
     */
    function verifyHash(bytes32 _dataHash) external view returns (bool) {
        return processedHashes[_dataHash];
    }

    /**
     * @dev Check if an organization is verified.
     * @param _orgId Organization ID as bytes32
     * @return true if the org is verified, false otherwise
     */
    function isOrgVerified(bytes32 _orgId) external view returns (bool) {
        return orgVerificationInfo[_orgId].isVerified;
    }

    /**
     * @dev Get detailed verification information for an organization.
     * This allows anyone to verify what information was checked during verification.
     * @param _orgId Organization ID as bytes32
     * @return verificationInfo Struct containing verification details
     */
    function getOrgVerificationInfo(bytes32 _orgId) external view returns (OrgVerificationInfo memory) {
        return orgVerificationInfo[_orgId];
    }

    /**
     * @dev Verify organization metadata hash matches the stored verification.
     * This allows third parties to verify that the claimed metadata matches what was verified on-chain.
     * @param _orgId Organization ID as bytes32
     * @param _claimedMetadataHash Hash of the metadata being verified
     * @return true if metadata hash matches the stored verification, false otherwise
     */
    function verifyOrgMetadata(bytes32 _orgId, bytes32 _claimedMetadataHash) external view returns (bool) {
        OrgVerificationInfo memory info = orgVerificationInfo[_orgId];
        return info.isVerified && info.metadataHash == _claimedMetadataHash;
    }

    /**
     * @dev Compute batch hash for off-chain signature preparation.
     * This view function helps clients compute the correct batchHash before signing.
     * @param _orgId Organization ID as bytes32
     * @param _batchIds Array of batch IDs as bytes32
     * @param _dataHashes Array of data hashes as bytes32
     * @return batchHash The hash that should be signed
     */
    function computeBatchHash(
        bytes32 _orgId,
        bytes32[] calldata _batchIds,
        bytes32[] calldata _dataHashes
    ) external pure returns (bytes32) {
        return keccak256(abi.encode(_orgId, _batchIds, _dataHashes));
    }
}

