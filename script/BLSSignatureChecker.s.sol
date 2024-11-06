// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {BLS12381} from "src/lib/BLS12381.sol";

contract BLSSignatureCheck is Script {
    // forge script script/BLSSignatureChecker.s.sol:BLSSignatureCheck --rpc-url $RPC_URL --broadcast
    function run() external {
        // Retrieve the private key from environment variable
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        // Start broadcasting transactions
        vm.startBroadcast(deployerPrivateKey);

        // Deploy the Registry contract
        BLSSignatureChecker blsSignatureChecker = new BLSSignatureChecker();

        // Log the deployed address
        console.log("Registry deployed to:", address(blsSignatureChecker));

        vm.stopBroadcast();
    }

    // forge script script/BLSSignatureChecker.s.sol:BLSSignatureChecker --func --rpc-url $RPC_URL --broadcast
    function verifySignature() external {
        // Retrieve the private key from environment variable
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        // Start broadcasting transactions
        // vm.startBroadcast(deployerPrivateKey);

        BLSSignatureChecker blsSignatureChecker = BLSSignatureChecker(
            0xbc3e245F5616304E6F4Ad06dD553FcFdDad55BA9
        );

        console2.log("blsSignatureChecker: ", address(blsSignatureChecker));

        bytes memory message = bytes("Hello, World!");

        // BLS12381.G1Point memory pubkey = BLS12381.G1Point({
        //     x: [
        //         0x00000000000000000000000000000000101936a69d6fbd2feae29545220ad66e,
        //         0xb60c3171b8d15de582dd2c645f67cb32377de0c97666e4b4fc7fad8a1c9a81af
        //     ],
        //     y: [
        //         0x0000000000000000000000000000000056cde7adcc8f412efa58ee343569d76a,
        //         0x095176133a52fbf43979f46c0658010c573c093f3814a5d4dded92b52d197dff
        //     ]
        // });

        // BLS12381.G2Point memory signature = BLS12381.G2Point({
        //     x: [
        //         0x0000000000000000000000000000000053551611fa07615a7c8928b6fd2bd6eb,
        //         0x0081937c6d89bd162874603223c735ce5ea86eb23569cce2147a9c7041966b96
        //     ],
        //     x_I: [
        //         0x0000000000000000000000000000000013fce717c9d6c37ffbd55e9097d6240b,
        //         0x2eeafd7f72cc5191e8642c9cff28c224bf25a24cdc06b65f01ac627eb2882420
        //     ],
        //     y: [
        //         0x0000000000000000000000000000000027846ac3f359dc4a47c6e677a9e17417,
        //         0x0e33e07c097be6b0403f47aa40ea6d46b62d163952d92db1580f17ed3c9c0a9b
        //     ],
        //     y_I: [
        //         0x0000000000000000000000000000000013949b290fc3c66d4741d48ec37b359e,
        //         0x781e7aff0ee1eddf15be1f73afafba6001689cb701ceda77b38d13a17b33c902
        //     ]
        // });
        BLS12381.G2Point memory signature = BLS12381.G2Point({
            x: [
                0x00000000000000000000000000000000075785f1ffe7faabd27259035731c4ff,
                0x881c38e87fc963a47425ce52f12f18c348370eaea53008bc683206d7770f5bdf
            ],
            x_I: [
                0x0000000000000000000000000000000002f8146bf138cbc35aeeccd4570d121c,
                0x8aec29661e8108e4094dc37b5a499272a6a680f015d0527c312a82457db8b979
            ],
            y: [
                0x000000000000000000000000000000000f5357626a9be51a0e689244b1a28d7b,
                0xe6132ad16f8d1852c2c75804fccf473902a5b8bbe6dd182d04643f34bb34fbe6
            ],
            y_I: [
                0x000000000000000000000000000000000544d2c2834eebb7cfbd5498cc0c328b,
                0x619d482161808b7e27dbb92941df85f704a6218ce9903af72eabdb3dbead70c7
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

        // bytes memory domainSeparator = bytes("");
        bytes memory domainSeparator = bytes("Taiko Based Rollup Preconfirmation v0.1.0");

        vm.assertEq(
            blsSignatureChecker.verifySignature(
                message,
                signature,
                pubkey,
                domainSeparator
            ),
            true
        );

        // vm.stopBroadcast();
    }
}

contract BLSSignatureChecker {
    using BLS12381 for *;
    /**
     * @notice Returns `true` if the BLS signature on the message matches against the public key
     * @param message The message bytes
     * @param sig The BLS signature
     * @param pubkey The BLS public key of the expected signer
     */
    function verifySignature(
        bytes memory message,
        BLS12381.G2Point memory sig,
        BLS12381.G1Point memory pubkey,
        bytes memory domainSeparator
    ) public view returns (bool) {
        // Hash the message bytes into a G2 point
        BLS12381.G2Point memory msgG2 = message.hashToCurveG2(domainSeparator);

        // Return the pairing check that denotes the correctness of the signature
        return BLS12381.pairing(pubkey, msgG2, BLS12381.negGeneratorG1(), sig);
    }
}
