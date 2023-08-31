// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/Bytes.sol";

contract FHETest is Test {
    using Bytes for *;

    bytes8 public constant frac64_5 = 0x40_14_00_00_00_00_00_00;
    bytes8 public constant frac64_4 = 0x40_10_00_00_00_00_00_00;

    function setUp() public {}

    function testBytesToUint256() public {
        uint256 value1 = 5;
        bytes memory bts1 = value1.toBytes();
        uint256 out1 = bts1.fromBytesUint256();
        assertEq(out1, value1);

        uint256 value2 = 4129075;
        bytes memory bts2 = value2.toBytes();
        uint256 out2 = bts2.fromBytesUint256();
        assertEq(out2, value2);
    }

    function testBytesToUint64() public {
        uint64 value = 4129075;
        bytes memory bts = value.toBytes(64);
        uint64 out = bts.fromBytesUint64();
        assertEq(out, value);
    }

    function testBytesToInt64() public {
        int64 value = -4129075;
        bytes memory bts = value.toBytes();
        int64 out = bts.fromBytesInt64();
        assertEq(out, value);
    }

    function testBytesToFrac64() public {
        bytes8 value = frac64_5;
        bytes memory bts = value.toBytes();
        bytes8 out = bts.fromBytesFrac64();
        assertEq(out, value);
    }
}
