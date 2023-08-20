pragma solidity ^0.8.13;

library Bytes {
    // Copies 'len' bytes from 'self' into a new 'bytes memory', starting at index '0'.
    // Returns the newly created 'bytes memory'
    // The returned bytes will be of length 'len'.
    function toBytes(bytes32 self, uint8 len) internal pure returns (bytes memory bts) {
        require(len <= 32);
        bts = new bytes(len);
        // Even though the bytes will allocate a full word, we don't want
        // any potential garbage bytes in there.
        uint256 data = uint256(self) & ~uint256(0) << (32 - len) * 8;
        assembly {
            mstore(add(bts, 32), data)
        }
    }

    // Copies 'self' into a new 'bytes memory'.
    // Returns the newly created 'bytes memory'
    // The returned bytes will be of length '32'.
    function toBytes(uint256 self) internal pure returns (bytes memory bts) {
        bts = toBytes(bytes32(self), 32);
    }

    // Converts an int64 to its 8 byte representation.
    function toBytes(int64 self) internal pure returns (bytes memory bts) {
        bts = new bytes(8);
        assembly {
            mstore(add(bts, 32), self)
        }
    }

    // Converts a bytes8 to its 8 byte representation.
    function toBytes(bytes8 self) internal pure returns (bytes memory bts) {
        bts = new bytes(8);
        assembly {
            mstore(add(bts, 32), self)
        }
    }

    // Copies 'self' into a new 'bytes memory'.
    // Returns the newly created 'bytes memory'
    // Requires that:
    //  - '8 <= bitsize <= 256'
    //  - 'bitsize % 8 == 0'
    // The returned bytes will be of length 'bitsize / 8'.
    function toBytes(uint256 self, uint16 bitsize) internal pure returns (bytes memory bts) {
        require(8 <= bitsize && bitsize <= 256 && bitsize % 8 == 0);
        self <<= 256 - bitsize;
        bts = toBytes(bytes32(self), uint8(bitsize / 8));
    }
}
