contract CallCounter {

    // Structure to hold call counts between addresses
    mapping(address => mapping(address => uint256)) public callCounts;

    // Maximum staleness in seconds
    uint256 public maxStaleness;

    constructor(uint256 _maxStaleness) {
        maxStaleness = _maxStaleness;
    }

    /**
     * @dev Updates the call count between two addresses if the signatures and timestamp are valid.
     * @param jsonString The JSON string containing the timestamp.
     * @param signatureA Signature of the jsonString by address A.
     * @param signatureB Signature of the jsonString by address B.
     */
    function updateCallCount(
        string memory jsonString,
        bytes memory signatureA,
        bytes memory signatureB
    ) public {

        // Parse the JSON string to extract the timestamp
        uint256 timestamp = extractTimestamp(jsonString);

        // Check staleness
        require(block.timestamp - timestamp <= maxStaleness, "Data is stale");

        // Recover addresses from signatures
        address addressA = recoverSigner(jsonString, signatureA);
        address addressB = recoverSigner(jsonString, signatureB);

        // Verify that signatures are from different addresses
        require(addressA != addressB, "Signatures must be from different addresses");

        // Increment the call count
        callCounts[addressA][addressB] += 1;
    }

    /**
     * @dev Extracts the timestamp from the JSON string.
     * Note: This is a placeholder function. In practice, parsing JSON on-chain is expensive.
     * Consider passing the timestamp separately or encoding the data efficiently.
     */
    function extractTimestamp(string memory jsonString) internal pure returns (uint256) {
        // For simplicity, we'll assume jsonString is in the format '{"timestamp":TIMESTAMP}'
        // and extract TIMESTAMP directly.

        bytes memory jsonBytes = bytes(jsonString);
        uint256 len = jsonBytes.length;
        uint256 timestamp;

        for (uint256 i = 0; i < len; i++) {
            if (jsonBytes[i] == ':') {
                // Extract the number after ':'
                for (uint256 j = i + 1; j < len - 1; j++) {
                    uint256 digit = uint8(jsonBytes[j]) - 48; // ASCII '0' = 48
                    if (digit >= 0 && digit <= 9) {
                        timestamp = timestamp * 10 + digit;
                    } else {
                        break;
                    }
                }
                break;
            }
        }

        return timestamp;
    }

    /**
     * @dev Recovers the signer address from a message and signature.
     * @param message The original message.
     * @param signature The signature of the message.
     */
    function recoverSigner(string memory message, bytes memory signature) internal pure returns (address) {
        bytes32 messageHash = getMessageHash(message);
        return recoverSignerFromHash(messageHash, signature);
    }

    /**
     * @dev Hashes the message using Ethereum's message prefix.
     * @param message The original message.
     */
    function getMessageHash(string memory message) internal pure returns (bytes32) {
        bytes32 hash = keccak256(abi.encodePacked(message));
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    /**
     * @dev Recovers the signer address from the message hash and signature.
     * @param hash The hashed message.
     * @param signature The signature of the message.
     */
    function recoverSignerFromHash(bytes32 hash, bytes memory signature) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        // Split the signature into r, s, v components
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        // Version of signature should be 27 or 28
        require(v == 27 || v == 28, "Invalid signature version");

        // Recover the signer address
        return ecrecover(hash, v, r, s);
    }
}
