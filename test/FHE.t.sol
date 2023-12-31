// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/FHE.sol";

contract FHETest is Test {
    FHE public fhe;

    bytes8 public constant frac64_1 = 0x3F_F0_00_00_00_00_00_00;
    bytes8 public constant frac64_4 = 0x40_10_00_00_00_00_00_00;
    bytes8 public constant frac64_5 = 0x40_14_00_00_00_00_00_00;

    bytes8 public constant frac64_9 = 0x40_22_00_00_00_00_00_00;
    bytes8 public constant frac64_20 = 0x40_34_00_00_00_00_00_00;

    function setUp() public {
        fhe = new FHE();
    }

    // Reverts (but, importantly, doesn't panic) because these are invalid
    // encodings
    function testFailAddCipherU256CipherU256() public view {
        uint256 p = 0;
        uint256 x = 1;
        uint256 y = 2;
        bytes memory ph = bytes.concat(keccak256(abi.encode(p)));
        bytes memory xh = bytes.concat(keccak256(abi.encode(x)));
        bytes memory yh = bytes.concat(keccak256(abi.encode(y)));

        fhe.addUint256EncEnc(ph, xh, yh);
    }

    // Test with pre-made ciphertext and encodings of a = 4, b = 5
    // Note that we can't actually test the result, of course. The
    // homomorphic addition will be randomized, so we won't actually get
    // back the same c_enc. This needs to be tested from _wallet_ code that
    // can actually create the sunscreen runtime and decode the result.

    // Still, good to have a test that valid encryptions and encodings make
    // it through without a revert.

    function testNetworkPublicKey() public {
        vm.pauseGasMetering();
        fhe.networkPublicKey();
        vm.resumeGasMetering();
    }

    /**
     *
     * uint256 operations
     *
     */

    function testAddUint256EncEnc() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = vm.readFileBinary("test/data/a_u256.bin");
        bytes memory b_enc = vm.readFileBinary("test/data/b_u256.bin");

        console.log("adding encrypted under other key");
        bytes memory c_enc = fhe.addUint256EncEnc(pubk, a_enc, b_enc);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        uint256 a_network = 5290240597;
        uint256 b_network = 478698;
        uint256 c_network = a_network + b_network;

        bytes memory a_enc_network = fhe.encryptUint256(a_network);
        console.log("encrypted a");
        bytes memory b_enc_network = fhe.encryptUint256(b_network);
        console.log("encrypted b");
        bytes memory c_enc_network = fhe.addUint256EncEnc(fhe.networkPublicKey(), a_enc_network, b_enc_network);
        console.log("encrypted c");

        uint256 c_network_decrypted = fhe.decryptUint256(c_enc_network);
        console.log("decrupted c");
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testAddUint256EncPlain() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = vm.readFileBinary("test/data/a_u256.bin");
        uint256 b = 4;

        bytes memory c_enc = fhe.addUint256EncPlain(pubk, a_enc, b);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        uint256 a_network = 5290240597;
        uint256 b_network = 478698;
        uint256 c_network = a_network + b_network;

        bytes memory a_enc_network = fhe.encryptUint256(a_network);
        bytes memory c_enc_network = fhe.addUint256EncPlain(fhe.networkPublicKey(), a_enc_network, b_network);

        uint256 c_network_decrypted = fhe.decryptUint256(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testAddUint256PlainEnc() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        uint256 a = 5;
        bytes memory b_enc = vm.readFileBinary("test/data/b_u256.bin");

        bytes memory c_enc = fhe.addUint256PlainEnc(pubk, a, b_enc);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        uint256 a_network = 5290240597;
        uint256 b_network = 478698;
        uint256 c_network = a_network + b_network;

        bytes memory b_enc_network = fhe.encryptUint256(b_network);
        bytes memory c_enc_network = fhe.addUint256PlainEnc(fhe.networkPublicKey(), a_network, b_enc_network);

        uint256 c_network_decrypted = fhe.decryptUint256(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testSubtractUint256EncEnc() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = vm.readFileBinary("test/data/a_u256.bin");
        bytes memory b_enc = vm.readFileBinary("test/data/b_u256.bin");

        bytes memory c_enc = fhe.subtractUint256EncEnc(pubk, a_enc, b_enc);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        uint256 a_network = 5290240597;
        uint256 b_network = 478698;
        uint256 c_network = a_network - b_network;

        bytes memory a_enc_network = fhe.encryptUint256(a_network);
        bytes memory b_enc_network = fhe.encryptUint256(b_network);
        bytes memory c_enc_network = fhe.subtractUint256EncEnc(fhe.networkPublicKey(), a_enc_network, b_enc_network);

        uint256 c_network_decrypted = fhe.decryptUint256(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testSubtractUint256EncPlain() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = vm.readFileBinary("test/data/a_u256.bin");
        uint256 b = 4;

        bytes memory c_enc = fhe.subtractUint256EncPlain(pubk, a_enc, b);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        uint256 a_network = 5290240597;
        uint256 b_network = 478698;
        uint256 c_network = a_network - b_network;

        bytes memory a_enc_network = fhe.encryptUint256(a_network);
        bytes memory c_enc_network = fhe.subtractUint256EncPlain(fhe.networkPublicKey(), a_enc_network, b_network);

        uint256 c_network_decrypted = fhe.decryptUint256(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testSubtractUint256PlainEnc() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        uint256 a = 5;
        bytes memory b_enc = vm.readFileBinary("test/data/b_u256.bin");

        bytes memory c_enc = fhe.subtractUint256PlainEnc(pubk, a, b_enc);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        uint256 a_network = 5290240597;
        uint256 b_network = 478698;
        uint256 c_network = a_network - b_network;

        bytes memory b_enc_network = fhe.encryptUint256(b_network);
        bytes memory c_enc_network = fhe.subtractUint256PlainEnc(fhe.networkPublicKey(), a_network, b_enc_network);

        uint256 c_network_decrypted = fhe.decryptUint256(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testMultiplyUint256EncEnc() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = vm.readFileBinary("test/data/a_u256.bin");
        bytes memory b_enc = vm.readFileBinary("test/data/b_u256.bin");

        bytes memory c_enc = fhe.multiplyUint256EncEnc(pubk, a_enc, b_enc);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        uint256 a_network = 5290240597;
        uint256 b_network = 478698;
        uint256 c_network = a_network * b_network;

        bytes memory a_enc_network = fhe.encryptUint256(a_network);
        bytes memory b_enc_network = fhe.encryptUint256(b_network);
        bytes memory c_enc_network = fhe.multiplyUint256EncEnc(fhe.networkPublicKey(), a_enc_network, b_enc_network);

        uint256 c_network_decrypted = fhe.decryptUint256(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testMultiplyUint256EncPlain() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = vm.readFileBinary("test/data/a_u256.bin");
        uint256 b = 4;

        bytes memory c_enc = fhe.multiplyUint256EncPlain(pubk, a_enc, b);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        uint256 a_network = 5290240597;
        uint256 b_network = 478698;
        uint256 c_network = a_network * b_network;

        bytes memory a_enc_network = fhe.encryptUint256(a_network);
        bytes memory c_enc_network = fhe.multiplyUint256EncPlain(fhe.networkPublicKey(), a_enc_network, b_network);

        uint256 c_network_decrypted = fhe.decryptUint256(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testMultiplyUint256PlainEnc() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        uint256 a = 5;
        bytes memory b_enc = vm.readFileBinary("test/data/b_u256.bin");

        bytes memory c_enc = fhe.multiplyUint256PlainEnc(pubk, a, b_enc);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        uint256 a_network = 5290240597;
        uint256 b_network = 478698;
        uint256 c_network = a_network * b_network;

        bytes memory b_enc_network = fhe.encryptUint256(b_network);
        bytes memory c_enc_network = fhe.multiplyUint256PlainEnc(fhe.networkPublicKey(), a_network, b_enc_network);

        uint256 c_network_decrypted = fhe.decryptUint256(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testEncryptUint256() public {
        vm.pauseGasMetering();
        bytes memory c_enc = fhe.encryptUint256(5);
        assert(c_enc.length > 0);
        vm.resumeGasMetering();
    }

    function testReencryptUint256() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = fhe.encryptUint256(5);

        bytes memory c_enc = fhe.reencryptUint256(pubk, a_enc);
        assert(c_enc.length > 0);
        vm.resumeGasMetering();
    }

    function testRefreshUint256() public {
        vm.pauseGasMetering();
        uint256 value = 6912345;
        bytes memory c_enc = fhe.encryptUint256(value);
        bytes memory c_enc_2 = fhe.refreshUint256(c_enc);

        uint256 c = fhe.decryptUint256(c_enc_2);

        assert(c_enc_2.length > 0);
        assertEq(c, value);

        vm.resumeGasMetering();
    }

    function testDecryptUint256() public {
        vm.pauseGasMetering();
        uint256 value = 745819;
        bytes memory c_enc = fhe.encryptUint256(value);
        uint256 c = fhe.decryptUint256(c_enc);

        assertEq(c, value);
        vm.resumeGasMetering();
    }

    /**
     *
     * uint64 operations
     *
     */

    function testAddUint64EncEnc() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = vm.readFileBinary("test/data/a_u64.bin");
        bytes memory b_enc = vm.readFileBinary("test/data/b_u64.bin");

        bytes memory c_enc = fhe.addUint64EncEnc(pubk, a_enc, b_enc);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        uint64 a_network = 5290240597;
        uint64 b_network = 478698;
        uint64 c_network = a_network + b_network;

        bytes memory a_enc_network = fhe.encryptUint64(a_network);
        bytes memory b_enc_network = fhe.encryptUint64(b_network);
        bytes memory c_enc_network = fhe.addUint64EncEnc(fhe.networkPublicKey(), a_enc_network, b_enc_network);

        uint64 c_network_decrypted = fhe.decryptUint64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testAddUint64EncPlain() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = vm.readFileBinary("test/data/a_u64.bin");
        uint64 b = 4;

        bytes memory c_enc = fhe.addUint64EncPlain(pubk, a_enc, b);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        uint64 a_network = 5290240597;
        uint64 b_network = 478698;
        uint64 c_network = a_network + b_network;

        bytes memory a_enc_network = fhe.encryptUint64(a_network);
        bytes memory c_enc_network = fhe.addUint64EncPlain(fhe.networkPublicKey(), a_enc_network, b_network);

        uint64 c_network_decrypted = fhe.decryptUint64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testAddUint64PlainEnc() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        uint64 a = 5;
        bytes memory b_enc = vm.readFileBinary("test/data/b_u64.bin");

        bytes memory c_enc = fhe.addUint64PlainEnc(pubk, a, b_enc);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        uint64 a_network = 5290240597;
        uint64 b_network = 478698;
        uint64 c_network = a_network + b_network;

        bytes memory b_enc_network = fhe.encryptUint64(b_network);
        bytes memory c_enc_network = fhe.addUint64PlainEnc(fhe.networkPublicKey(), a_network, b_enc_network);

        uint64 c_network_decrypted = fhe.decryptUint64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testSubtractUint64EncEnc() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = vm.readFileBinary("test/data/a_u64.bin");
        bytes memory b_enc = vm.readFileBinary("test/data/b_u64.bin");

        bytes memory c_enc = fhe.subtractUint64EncEnc(pubk, a_enc, b_enc);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        uint64 a_network = 5290240597;
        uint64 b_network = 478698;
        uint64 c_network = a_network - b_network;

        bytes memory a_enc_network = fhe.encryptUint64(a_network);
        bytes memory b_enc_network = fhe.encryptUint64(b_network);
        bytes memory c_enc_network = fhe.subtractUint64EncEnc(fhe.networkPublicKey(), a_enc_network, b_enc_network);

        uint64 c_network_decrypted = fhe.decryptUint64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testSubtractUint64EncPlain() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = vm.readFileBinary("test/data/a_u64.bin");
        uint64 b = 4;

        bytes memory c_enc = fhe.subtractUint64EncPlain(pubk, a_enc, b);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        uint64 a_network = 5290240597;
        uint64 b_network = 478698;
        uint64 c_network = a_network - b_network;

        bytes memory a_enc_network = fhe.encryptUint64(a_network);
        bytes memory c_enc_network = fhe.subtractUint64EncPlain(fhe.networkPublicKey(), a_enc_network, b_network);

        uint64 c_network_decrypted = fhe.decryptUint64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testSubtractUint64PlainEnc() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        uint64 a = 5;
        bytes memory b_enc = vm.readFileBinary("test/data/b_u64.bin");

        bytes memory c_enc = fhe.subtractUint64PlainEnc(pubk, a, b_enc);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        uint64 a_network = 5290240597;
        uint64 b_network = 478698;
        uint64 c_network = a_network - b_network;

        bytes memory b_enc_network = fhe.encryptUint64(b_network);
        bytes memory c_enc_network = fhe.subtractUint64PlainEnc(fhe.networkPublicKey(), a_network, b_enc_network);

        uint64 c_network_decrypted = fhe.decryptUint64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testMultiplyUint64EncEnc() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = vm.readFileBinary("test/data/a_u64.bin");
        bytes memory b_enc = vm.readFileBinary("test/data/b_u64.bin");

        bytes memory c_enc = fhe.multiplyUint64EncEnc(pubk, a_enc, b_enc);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        uint64 a_network = 5290240597;
        uint64 b_network = 478698;
        uint64 c_network = a_network * b_network;

        bytes memory a_enc_network = fhe.encryptUint64(a_network);
        bytes memory b_enc_network = fhe.encryptUint64(b_network);
        bytes memory c_enc_network = fhe.multiplyUint64EncEnc(fhe.networkPublicKey(), a_enc_network, b_enc_network);

        uint64 c_network_decrypted = fhe.decryptUint64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testMultiplyUint64EncPlain() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = vm.readFileBinary("test/data/a_u64.bin");
        uint64 b = 4;

        bytes memory c_enc = fhe.multiplyUint64EncPlain(pubk, a_enc, b);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        uint64 a_network = 5290240597;
        uint64 b_network = 478698;
        uint64 c_network = a_network * b_network;

        bytes memory a_enc_network = fhe.encryptUint64(a_network);
        bytes memory c_enc_network = fhe.multiplyUint64EncPlain(fhe.networkPublicKey(), a_enc_network, b_network);

        uint64 c_network_decrypted = fhe.decryptUint64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testMultiplyUint64PlainEnc() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        uint64 a = 5;
        bytes memory b_enc = vm.readFileBinary("test/data/b_u64.bin");

        bytes memory c_enc = fhe.multiplyUint64PlainEnc(pubk, a, b_enc);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        uint64 a_network = 5290240597;
        uint64 b_network = 478698;
        uint64 c_network = a_network * b_network;

        bytes memory b_enc_network = fhe.encryptUint64(b_network);
        bytes memory c_enc_network = fhe.multiplyUint64PlainEnc(fhe.networkPublicKey(), a_network, b_enc_network);

        uint64 c_network_decrypted = fhe.decryptUint64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testEncryptUint64() public {
        vm.pauseGasMetering();
        bytes memory c_enc = fhe.encryptUint64(5);
        assert(c_enc.length > 0);
        vm.resumeGasMetering();
    }

    function testReencryptUint64() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = fhe.encryptUint64(5);

        bytes memory c_enc = fhe.reencryptUint64(pubk, a_enc);
        assert(c_enc.length > 0);
        vm.resumeGasMetering();
    }

    function testRefreshUint64() public {
        vm.pauseGasMetering();
        uint64 value = 6912345;
        bytes memory c_enc = fhe.encryptUint64(value);
        bytes memory c_enc_2 = fhe.refreshUint64(c_enc);

        uint64 c = fhe.decryptUint64(c_enc_2);

        assert(c_enc_2.length > 0);
        assertEq(c, value);

        vm.resumeGasMetering();
    }

    function testDecryptUint64() public {
        vm.pauseGasMetering();
        uint64 value = 745819;
        bytes memory c_enc = fhe.encryptUint64(value);
        uint64 c = fhe.decryptUint64(c_enc);

        assertEq(c, value);
        vm.resumeGasMetering();
    }

    /**
     *
     * int64 operations
     *
     */

    function testAddInt64EncEnc() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = vm.readFileBinary("test/data/a_i64.bin");
        bytes memory b_enc = vm.readFileBinary("test/data/b_i64.bin");

        bytes memory c_enc = fhe.addInt64EncEnc(pubk, a_enc, b_enc);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        int64 a_network = -5290240597;
        int64 b_network = 478698;
        int64 c_network = a_network + b_network;

        bytes memory a_enc_network = fhe.encryptInt64(a_network);
        bytes memory b_enc_network = fhe.encryptInt64(b_network);
        bytes memory c_enc_network = fhe.addInt64EncEnc(fhe.networkPublicKey(), a_enc_network, b_enc_network);

        int64 c_network_decrypted = fhe.decryptInt64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testAddInt64EncPlain() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = vm.readFileBinary("test/data/a_i64.bin");
        int64 b = 4;

        bytes memory c_enc = fhe.addInt64EncPlain(pubk, a_enc, b);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        int64 a_network = -5290240597;
        int64 b_network = 478698;
        int64 c_network = a_network + b_network;

        bytes memory a_enc_network = fhe.encryptInt64(a_network);
        bytes memory c_enc_network = fhe.addInt64EncPlain(fhe.networkPublicKey(), a_enc_network, b_network);

        int64 c_network_decrypted = fhe.decryptInt64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testAddInt64PlainEnc() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        int64 a = 5;
        bytes memory b_enc = vm.readFileBinary("test/data/b_i64.bin");

        bytes memory c_enc = fhe.addInt64PlainEnc(pubk, a, b_enc);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        int64 a_network = -5290240597;
        int64 b_network = 478698;
        int64 c_network = a_network + b_network;

        bytes memory b_enc_network = fhe.encryptInt64(b_network);
        bytes memory c_enc_network = fhe.addInt64PlainEnc(fhe.networkPublicKey(), a_network, b_enc_network);

        int64 c_network_decrypted = fhe.decryptInt64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testSubtractInt64EncEnc() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = vm.readFileBinary("test/data/a_i64.bin");
        bytes memory b_enc = vm.readFileBinary("test/data/b_i64.bin");

        bytes memory c_enc = fhe.subtractInt64EncEnc(pubk, a_enc, b_enc);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        int64 a_network = -5290240597;
        int64 b_network = 478698;
        int64 c_network = a_network - b_network;

        bytes memory a_enc_network = fhe.encryptInt64(a_network);
        bytes memory b_enc_network = fhe.encryptInt64(b_network);
        bytes memory c_enc_network = fhe.subtractInt64EncEnc(fhe.networkPublicKey(), a_enc_network, b_enc_network);

        int64 c_network_decrypted = fhe.decryptInt64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testSubtractInt64EncPlain() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = vm.readFileBinary("test/data/a_i64.bin");
        int64 b = 4;

        bytes memory c_enc = fhe.subtractInt64EncPlain(pubk, a_enc, b);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        int64 a_network = -5290240597;
        int64 b_network = 478698;
        int64 c_network = a_network - b_network;

        bytes memory a_enc_network = fhe.encryptInt64(a_network);
        bytes memory c_enc_network = fhe.subtractInt64EncPlain(fhe.networkPublicKey(), a_enc_network, b_network);

        int64 c_network_decrypted = fhe.decryptInt64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testSubtractInt64PlainEnc() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        int64 a = 5;
        bytes memory b_enc = vm.readFileBinary("test/data/b_i64.bin");

        bytes memory c_enc = fhe.subtractInt64PlainEnc(pubk, a, b_enc);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        int64 a_network = -5290240597;
        int64 b_network = 478698;
        int64 c_network = a_network - b_network;

        bytes memory b_enc_network = fhe.encryptInt64(b_network);
        bytes memory c_enc_network = fhe.subtractInt64PlainEnc(fhe.networkPublicKey(), a_network, b_enc_network);

        int64 c_network_decrypted = fhe.decryptInt64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testMultiplyInt64EncEnc() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = vm.readFileBinary("test/data/a_i64.bin");
        bytes memory b_enc = vm.readFileBinary("test/data/b_i64.bin");

        bytes memory c_enc = fhe.multiplyInt64EncEnc(pubk, a_enc, b_enc);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        int64 a_network = -5290240597;
        int64 b_network = 478698;
        int64 c_network = a_network * b_network;

        bytes memory a_enc_network = fhe.encryptInt64(a_network);
        bytes memory b_enc_network = fhe.encryptInt64(b_network);
        bytes memory c_enc_network = fhe.multiplyInt64EncEnc(fhe.networkPublicKey(), a_enc_network, b_enc_network);

        int64 c_network_decrypted = fhe.decryptInt64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    // Currently cause an internal SEAL error
    function testMultiplyInt64EncPlain() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = vm.readFileBinary("test/data/a_i64.bin");
        int64 b = 4;

        bytes memory c_enc = fhe.multiplyInt64EncPlain(pubk, a_enc, b);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        int64 a_network = -5290240597;
        int64 b_network = 478698;
        int64 c_network = a_network * b_network;

        bytes memory a_enc_network = fhe.encryptInt64(a_network);
        bytes memory c_enc_network = fhe.multiplyInt64EncPlain(fhe.networkPublicKey(), a_enc_network, b_network);

        int64 c_network_decrypted = fhe.decryptInt64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testMultiplyInt64PlainEnc() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        int64 a = 5;
        bytes memory b_enc = vm.readFileBinary("test/data/b_i64.bin");

        bytes memory c_enc = fhe.multiplyInt64PlainEnc(pubk, a, b_enc);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        int64 a_network = -5290240597;
        int64 b_network = 478698;
        int64 c_network = a_network * b_network;

        bytes memory b_enc_network = fhe.encryptInt64(b_network);
        bytes memory c_enc_network = fhe.multiplyInt64PlainEnc(fhe.networkPublicKey(), a_network, b_enc_network);

        int64 c_network_decrypted = fhe.decryptInt64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testEncryptInt64() public {
        vm.pauseGasMetering();
        bytes memory c_enc = fhe.encryptInt64(5);
        assert(c_enc.length > 0);
        vm.resumeGasMetering();
    }

    function testReencryptInt64() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = fhe.encryptInt64(5);

        bytes memory c_enc = fhe.reencryptInt64(pubk, a_enc);
        assert(c_enc.length > 0);
        vm.resumeGasMetering();
    }

    function testRefreshInt64() public {
        vm.pauseGasMetering();
        int64 value = -6912345;
        bytes memory c_enc = fhe.encryptInt64(value);
        bytes memory c_enc_2 = fhe.refreshInt64(c_enc);

        int64 c = fhe.decryptInt64(c_enc_2);

        assert(c_enc_2.length > 0);
        assertEq(c, value);

        vm.resumeGasMetering();
    }

    function testDecryptInt64() public {
        vm.pauseGasMetering();
        int64 value = 745819;
        bytes memory c_enc = fhe.encryptInt64(value);
        int64 c = fhe.decryptInt64(c_enc);

        assertEq(c, value);
        vm.resumeGasMetering();
    }

    /**
     *
     * frac64 operations
     *
     */

    function testAddFrac64EncEnc() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = vm.readFileBinary("test/data/a_frac64.bin");
        bytes memory b_enc = vm.readFileBinary("test/data/b_frac64.bin");

        bytes memory c_enc = fhe.addFrac64EncEnc(pubk, a_enc, b_enc);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        bytes8 a_network = frac64_5;
        bytes8 b_network = frac64_4;
        bytes8 c_network = frac64_9;

        bytes memory a_enc_network = fhe.encryptFrac64(a_network);
        bytes memory b_enc_network = fhe.encryptFrac64(b_network);
        bytes memory c_enc_network = fhe.addFrac64EncEnc(fhe.networkPublicKey(), a_enc_network, b_enc_network);

        bytes8 c_network_decrypted = fhe.decryptFrac64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testAddFrac64EncPlain() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = vm.readFileBinary("test/data/a_frac64.bin");
        bytes8 b = frac64_4;

        bytes memory c_enc = fhe.addFrac64EncPlain(pubk, a_enc, b);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        bytes8 a_network = frac64_5;
        bytes8 b_network = frac64_4;
        bytes8 c_network = frac64_9;

        bytes memory a_enc_network = fhe.encryptFrac64(a_network);
        bytes memory c_enc_network = fhe.addFrac64EncPlain(fhe.networkPublicKey(), a_enc_network, b_network);

        bytes8 c_network_decrypted = fhe.decryptFrac64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testAddFrac64PlainEnc() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes8 a = frac64_5;
        bytes memory b_enc = vm.readFileBinary("test/data/b_frac64.bin");

        bytes memory c_enc = fhe.addFrac64PlainEnc(pubk, a, b_enc);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        bytes8 a_network = frac64_5;
        bytes8 b_network = frac64_4;
        bytes8 c_network = frac64_9;

        bytes memory b_enc_network = fhe.encryptFrac64(b_network);
        bytes memory c_enc_network = fhe.addFrac64PlainEnc(fhe.networkPublicKey(), a_network, b_enc_network);

        bytes8 c_network_decrypted = fhe.decryptFrac64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testSubtractFrac64EncEnc() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = vm.readFileBinary("test/data/a_frac64.bin");
        bytes memory b_enc = vm.readFileBinary("test/data/b_frac64.bin");

        bytes memory c_enc = fhe.subtractFrac64EncEnc(pubk, a_enc, b_enc);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        bytes8 a_network = frac64_5;
        bytes8 b_network = frac64_4;
        bytes8 c_network = frac64_1;

        bytes memory a_enc_network = fhe.encryptFrac64(a_network);
        bytes memory b_enc_network = fhe.encryptFrac64(b_network);
        bytes memory c_enc_network = fhe.subtractFrac64EncEnc(fhe.networkPublicKey(), a_enc_network, b_enc_network);

        bytes8 c_network_decrypted = fhe.decryptFrac64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testSubtractFrac64EncPlain() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = vm.readFileBinary("test/data/a_frac64.bin");
        bytes8 b = frac64_4;

        bytes memory c_enc = fhe.subtractFrac64EncPlain(pubk, a_enc, b);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        bytes8 a_network = frac64_5;
        bytes8 b_network = frac64_4;
        bytes8 c_network = frac64_1;

        bytes memory a_enc_network = fhe.encryptFrac64(a_network);
        bytes memory c_enc_network = fhe.subtractFrac64EncPlain(fhe.networkPublicKey(), a_enc_network, b_network);

        bytes8 c_network_decrypted = fhe.decryptFrac64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testSubtractFrac64PlainEnc() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes8 a = frac64_5;
        bytes memory b_enc = vm.readFileBinary("test/data/b_frac64.bin");

        bytes memory c_enc = fhe.subtractFrac64PlainEnc(pubk, a, b_enc);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        bytes8 a_network = frac64_5;
        bytes8 b_network = frac64_4;
        bytes8 c_network = frac64_1;

        bytes memory b_enc_network = fhe.encryptFrac64(b_network);
        bytes memory c_enc_network = fhe.subtractFrac64PlainEnc(fhe.networkPublicKey(), a_network, b_enc_network);

        bytes8 c_network_decrypted = fhe.decryptFrac64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testMultiplyFrac64EncEnc() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = vm.readFileBinary("test/data/a_frac64.bin");
        bytes memory b_enc = vm.readFileBinary("test/data/b_frac64.bin");

        bytes memory c_enc = fhe.multiplyFrac64EncEnc(pubk, a_enc, b_enc);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        bytes8 a_network = frac64_5;
        bytes8 b_network = frac64_4;
        bytes8 c_network = frac64_20;

        bytes memory a_enc_network = fhe.encryptFrac64(a_network);
        bytes memory b_enc_network = fhe.encryptFrac64(b_network);
        bytes memory c_enc_network = fhe.multiplyFrac64EncEnc(fhe.networkPublicKey(), a_enc_network, b_enc_network);

        bytes8 c_network_decrypted = fhe.decryptFrac64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testMultiplyFrac64EncPlain() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = vm.readFileBinary("test/data/a_frac64.bin");
        bytes8 b = frac64_4;

        bytes memory c_enc = fhe.multiplyFrac64EncPlain(pubk, a_enc, b);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        bytes8 a_network = frac64_5;
        bytes8 b_network = frac64_4;
        bytes8 c_network = frac64_20;

        bytes memory a_enc_network = fhe.encryptFrac64(a_network);
        bytes memory c_enc_network = fhe.multiplyFrac64EncPlain(fhe.networkPublicKey(), a_enc_network, b_network);

        bytes8 c_network_decrypted = fhe.decryptFrac64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testMultiplyFrac64PlainEnc() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes8 a = frac64_5;
        bytes memory b_enc = vm.readFileBinary("test/data/b_frac64.bin");

        bytes memory c_enc = fhe.multiplyFrac64PlainEnc(pubk, a, b_enc);
        assert(c_enc.length > 0);

        // Check that our operation returns the correct value.
        bytes8 a_network = frac64_5;
        bytes8 b_network = frac64_4;
        bytes8 c_network = frac64_20;

        bytes memory b_enc_network = fhe.encryptFrac64(b_network);
        bytes memory c_enc_network = fhe.multiplyFrac64PlainEnc(fhe.networkPublicKey(), a_network, b_enc_network);

        bytes8 c_network_decrypted = fhe.decryptFrac64(c_enc_network);
        assertEq(c_network, c_network_decrypted);

        vm.resumeGasMetering();
    }

    function testEncryptFrac64() public {
        vm.pauseGasMetering();
        bytes memory c_enc = fhe.encryptFrac64(frac64_5);
        assert(c_enc.length > 0);
        vm.resumeGasMetering();
    }

    function testReencryptFrac64() public {
        vm.pauseGasMetering();
        bytes memory pubk = vm.readFileBinary("test/data/public_key.pub");
        bytes memory a_enc = fhe.encryptFrac64(frac64_5);

        bytes memory c_enc = fhe.reencryptFrac64(pubk, a_enc);
        assert(c_enc.length > 0);
        vm.resumeGasMetering();
    }

    function testRefreshFrac64() public {
        vm.pauseGasMetering();
        bytes8 value = frac64_20;
        bytes memory c_enc = fhe.encryptFrac64(value);
        bytes memory c_enc_2 = fhe.refreshFrac64(c_enc);

        bytes8 c = fhe.decryptFrac64(c_enc_2);

        assert(c_enc_2.length > 0);
        assertEq(c, value);

        vm.resumeGasMetering();
    }

    function testDecryptFrac64() public {
        vm.pauseGasMetering();
        bytes8 value = frac64_5;
        bytes memory c_enc = fhe.encryptFrac64(value);
        bytes8 c = fhe.decryptFrac64(c_enc);

        assertEq(c, value);
        vm.resumeGasMetering();
    }
}
