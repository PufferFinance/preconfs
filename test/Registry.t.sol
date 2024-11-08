// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "../src/Registry.sol";
import {BLS} from "../src/lib/BLS.sol";

contract RegistryTest is Test {
    using BLS for *;

    Registry registry;
    address operator = address(0x1);

    // /// @notice The generator point in G1 (P1).
    // BLS.G1Point G1_GENERATOR =
    //     BLS.G1Point(
    //         BLS.Fp(
    //             31827880280837800241567138048534752271,
    //             88385725958748408079899006800036250932223001591707578097800747617502997169851
    //         ),
    //         BLS.Fp(
    //             11568204302792691131076548377920244452,
    //             114417265404584670498511149331300188430316142484413708742216858159411894806497
    //         )
    //     );

    // /// @notice The negated generator point in G1 (-P1).
    // BLS.G1Point NEGATED_G1_GENERATOR =
    //     BLS.G1Point(
    //         BLS.Fp(
    //             31827880280837800241567138048534752271,
    //             88385725958748408079899006800036250932223001591707578097800747617502997169851
    //         ),
    //         BLS.Fp(
    //             22997279242622214937712647648895181298,
    //             46816884707101390882112958134453447585552332943769894357249934112654335001290
    //         )
    //     );

    function setUp() public {
        registry = new Registry();
        vm.deal(operator, 100 ether); // Give operator some ETH
    }

    function testVerifyBLS() public {
        // Obtain the private key as a random scalar.
        uint256 privateKey = vm.randomUint();

        bytes memory message = bytes("Hello, World!");
        bytes memory domainSeparator = hex"";

        // Get the generator point
        (BLS.Fp memory x, BLS.Fp memory y) = registry.G1_GENERATOR();
        BLS.G1Point memory generator = BLS.G1Point(x, y);

        // Public key is the generator point multiplied by the private key.
        BLS.G1Point memory pubkey = BLS.G1Mul(generator, privateKey);

        // Hash the message bytes into a G2 point
        BLS.G2Point memory messagePoint = BLS.MapFp2ToG2(
            BLS.Fp2(BLS.Fp(0, 0), BLS.Fp(0, uint256(keccak256(message))))
        );

        // Obtain the signature by multiplying the message point by the private key.
        BLS.G2Point memory signature = BLS.G2Mul(messagePoint, privateKey);

        require(
            registry.verifySignature(
                message,
                signature,
                pubkey,
                domainSeparator
            ),
            "Signature verification failed"
        );
    }
}
