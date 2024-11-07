// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "../src/Registry.sol";
import {BLS12381} from "../src/lib/BLS12381.sol";

contract RegistryTest is Test {
    using BLS12381 for *;
    
    Registry registry;
    address operator = address(0x1);
    
    function setUp() public {
        registry = new Registry();
        vm.deal(operator, 100 ether); // Give operator some ETH
    }

    function testVerifyBLS() public view {
        bytes memory message = bytes("Hello, World!");

        BLS12381.G2Point memory signature = BLS12381.G2Point({
            x: [
                0x000000000000000000000000000000000ba2ac80c977828320da976c87046248,
                0x2234a30c75cef3b37770091c356d20ab2ab6bd1db47e913f957767aaf632dcfc
            ],
            x_I: [
                0x000000000000000000000000000000000f047cc3afcb0a8e45a5289fae67dafc,
                0x5fcec5d836a2e949dd2ed209321fe2e1b71e4f41bb0394bd887b9b51ed1e1745
            ],
            y: [
                0x0000000000000000000000000000000016c9ab37c5e1ad264d468e569002b7a3,
                0x7ffac7c85bf398b7f5263304c141e4a452c04c8e390f6b1cd3c3ade058918117
            ],
            y_I: [
                0x000000000000000000000000000000001041d7c8cf215dbf695255d42537e099,
                0x0ac3c04c89a55c884636fb1d3aab81b4d731ab6b05f9228d1943e149c0a1d21e
            ]
        });

        BLS12381.G1Point memory pubkey = BLS12381.G1Point({
            x: [
                0x00000000000000000000000000000000101936a69d6fbd2feae29545220ad66e,
                0xb60c3171b8d15de582dd2c645f67cb32377de0c97666e4b4fc7fad8a1c9a81af
            ],
            y: [
                0x00000000000000000000000000000000056cde7adcc8f412efa58ee343569d76,
                0xa95176133a52fbf43979f46c0658010c573c093f3814a5d4dded92b52d197dff
            ]
        });
        bytes memory domainSeparator = hex"";

        require(registry.verifySignature(message, signature, pubkey, domainSeparator), "Signature verification failed");
    }
} 