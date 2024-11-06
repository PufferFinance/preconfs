// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import {BLS12381} from "./lib/BLS12381.sol";
import {MerkleUtils} from "./lib/Merkelize.sol";

contract Registry {
    using BLS12381 for *;

    struct Registration {
        uint256[2] pubkey; // compressed bls pubkey
        uint256[8] signature; // flattened registration signature
    }

    struct Operator {
        bytes32 proxyKey; // compressed ecdsa key without prefix
        address operator; // msg.sender can be a multisig
        uint72 collateral;
        uint32 registeredAt;
        uint32 unregisteredAt;
    }

    struct Leaf {
        uint256[2] pubkey; // compressed pubkey
        bytes32 registrationCommitment; // sha256(signature || proxyKey)
    }

    mapping(bytes32 operatorCommitment => Operator) public commitments;

    // Constants
    uint256 constant MIN_COLLATERAL = 1 ether;
    uint256 constant TWO_EPOCHS = 64;

    // Errors
    error InsufficientCollateral();
    error WrongOperator();
    error AlreadyUnregistered();
    error NotUnregistered();
    error UnregistrationDelayNotMet();
    error NoCollateralToClaim();
    error FraudProofMerklePathInvalid();
    error FraudProofChallengeInvalid();
    // Events
    event OperatorRegistered(bytes32 operatorCommitment, uint32 registeredAt);
    event OperatorUnregistered(
        bytes32 operatorCommitment,
        uint32 unregisteredAt
    );
    event OperatorDeleted(bytes32 operatorCommitment, uint72 amountToReturn);

    function register(
        Registration[] calldata registrations,
        bytes32 proxyKey,
        uint256 height
    ) external payable {
        // check collateral
        if (msg.value < MIN_COLLATERAL) {
            revert InsufficientCollateral();
        }

        // operatorCommitment hash = merklize registrations
        bytes32 operatorCommitment = createCommitment(
            registrations,
            proxyKey,
            height
        );

        // add operatorCommitment to mapping
        commitments[operatorCommitment] = Operator({
            operator: msg.sender,
            proxyKey: proxyKey,
            collateral: uint72(msg.value),
            registeredAt: uint32(block.number),
            unregisteredAt: 0
        });

        // emit events
    }

    function createCommitment(
        Registration[] calldata registrations,
        bytes32 proxyKey,
        uint256 height
    ) internal view returns (bytes32 operatorCommitment) {
        uint256 batchSize = 1 << height; // guaranteed pow of 2
        require(
            registrations.length <= batchSize,
            "Batch size must be at least as big"
        );

        // Create leaves array with padding
        bytes32[] memory leaves = new bytes32[](batchSize);

        // Create leaf nodes
        for (uint256 i = 0; i < registrations.length; i++) {
            // Create registration commitment by hashing signature and metadata
            bytes32 registrationCommitment = sha256(
                abi.encodePacked(registrations[i].signature, proxyKey)
            );

            // Create leaf node by hashing pubkey and commitment
            leaves[i] = sha256(
                abi.encodePacked(
                    registrations[i].pubkey,
                    registrationCommitment
                )
            );

            // emit event
        }

        // Fill remaining leaves with empty hashes for padding
        for (uint256 i = registrations.length; i < batchSize; i++) {
            leaves[i] = bytes32(0);
        }

        operatorCommitment = MerkleUtils.merkleize(leaves);
        //emit final event
    }

    function slashRegistration(
        bytes32 operatorCommitment,
        BLS12381.G1Point calldata pubkey,
        BLS12381.G2Point calldata signature,
        bytes32 proxyKey,
        bytes32[] calldata proof,
        uint256 leafIndex
    ) external {
        Operator storage operator = commitments[operatorCommitment];

        uint256[2] memory pubkeyBytes = pubkey.compress(); // compressed bls pubkey
        uint256[8] memory signatureBytes = signature.flatten(); // flattened registration signature

        // reconstruct leaf
        bytes32 leaf = sha256(abi.encodePacked(
            pubkeyBytes,
            sha256(abi.encodePacked(signatureBytes, proxyKey))
        ));

        // verify proof against operatorCommitment
        if (MerkleUtils.verifyProof(proof, operatorCommitment, leaf, leafIndex)) {
            revert FraudProofMerklePathInvalid();
        }

        // reconstruct message todo
        bytes memory message = bytes("");

        // verify signature
        bytes memory domainSeparator = bytes("");
        if (verifySignature(message, signature, pubkey, domainSeparator)) {
            revert FraudProofChallengeInvalid();
        }
    }

    function unregister(bytes32 operatorCommitment) external {
        Operator storage operator = commitments[operatorCommitment];

        if (operator.operator != msg.sender) {
            revert WrongOperator();
        }

        // Check that they haven't already unregistered
        if (operator.unregisteredAt != 0) {
            revert AlreadyUnregistered();
        }

        // Set unregistration timestamp
        operator.unregisteredAt = uint32(block.number);

        emit OperatorUnregistered(operatorCommitment, operator.unregisteredAt);
    }

    function claimCollateral(bytes32 operatorCommitment) external {
        Operator storage operator = commitments[operatorCommitment];

        // Check that they've unregistered
        if (operator.unregisteredAt == 0) {
            revert NotUnregistered();
        }

        // Check that enough time has passed
        if (block.number < operator.unregisteredAt + TWO_EPOCHS) {
            revert UnregistrationDelayNotMet();
        }

        // Check there's collateral to claim
        if (operator.collateral == 0) {
            revert NoCollateralToClaim();
        }

        uint72 amountToReturn = operator.collateral;

        // TODO safe transfer for rentrancy
        (bool success, ) = msg.sender.call{value: amountToReturn}("");
        require(success, "Transfer failed");

        emit OperatorDeleted(operatorCommitment, amountToReturn);

        // Clear operator info
        delete commitments[operatorCommitment];
    }

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

// contract Registry2 {
//     struct Validator {
//         BLS12381.G1Point pubkey;
//         BLS12381.G2Point signature;
//         address operator;
//         uint64 registeredAt;
//     }

//     struct Registration {
//         BLS12381.G1Point pubkey;
//         BLS12381.G2Point signature;
//     }

//     // Pack operator info into a struct that fits in one storage slot
//     struct OperatorInfo {
//         uint64 validatorCount;
//         uint64 unregisteredAt; // 0 means not unregistered
//         uint128 collateral; // Using uint128 since 1 ether fits easily
//     }

//     mapping(address => OperatorInfo) public operatorInfo;
//     mapping(address => mapping(uint256 => Validator))
//         public operatorToValidator;

//     // Constants
//     uint256 constant MIN_COLLATERAL = 1 ether;
//     uint256 constant TWO_EPOCHS = 64;

//     // Errors
//     error InsufficientCollateral(uint256 sent);
//     error NotUnregistered();
//     error UnregistrationDelayNotMet();
//     error AlreadyUnregistered();
//     error NoCollateralToClaim();
//     error SignatureWasValid();
//     error WrongPubkey();
//     error WrongSignature();

//     // Events
//     event ValidatorRegistered(
//         address indexed operator,
//         BLS12381.G1Point pubkey,
//         BLS12381.G2Point signature,
//         uint64 activeAfter
//     );
//     event CollateralAdded(address indexed operator, uint256 amount);
//     event CollateralRemoved(address indexed operator, uint256 amount);
//     event OperatorUnregistered(address indexed operator, uint64 unregisteredAt);
//     event ValidatorRegistrationSlashed(
//         address indexed operator,
//         uint256 index,
//         BLS12381.G1Point pubkey
//     );

//     function register(Registration[] calldata validators) external payable {
//         OperatorInfo storage info = operatorInfo[msg.sender];

//         // Ensure operator isn't already unregistering
//         if (info.unregisteredAt != 0) {
//             // todo but should we allow re-registering?
//             revert AlreadyUnregistered();
//         }

//         uint256 newCollateral = info.collateral + msg.value;

//         // Check collateral requirement
//         if (newCollateral < MIN_COLLATERAL) {
//             revert InsufficientCollateral(newCollateral);
//         }

//         // Register each validator
//         uint64 timestamp = uint64(block.timestamp);
//         uint64 activeAfterTime = timestamp + 1 days;

//         for (uint256 i = 0; i < validators.length; i++) {
//             operatorToValidator[msg.sender][
//                 info.validatorCount + i
//             ] = Validator({
//                 pubkey: validators[i].pubkey,
//                 signatureHash: _hashSignature(validators[i].signature),
//                 registeredAt: timestamp,
//                 activeAfter: activeAfterTime
//             });

//             emit ValidatorRegistered(
//                 msg.sender,
//                 validators[i].pubkey,
//                 validators[i].signature,
//                 activeAfterTime
//             );
//         }

//         // Update operator info
//         info.validatorCount += uint64(validators.length);
//         info.collateral = uint128(newCollateral);

//         emit CollateralAdded(msg.sender, msg.value);
//     }

//     function unregister() external {
//         OperatorInfo storage info = operatorInfo[msg.sender];

//         // Check that they haven't already unregistered
//         if (info.unregisteredAt != 0) {
//             revert AlreadyUnregistered();
//         }

//         // Set unregistration timestamp
//         info.unregisteredAt = uint64(block.number);

//         emit OperatorUnregistered(msg.sender, info.unregisteredAt);
//     }

//     function claimCollateral() external {
//         OperatorInfo storage info = operatorInfo[msg.sender];

//         // Check that they've unregistered
//         if (info.unregisteredAt == 0) {
//             revert NotUnregistered();
//         }

//         // Check that enough time has passed
//         if (block.number < info.unregisteredAt + TWO_EPOCHS) {
//             revert UnregistrationDelayNotMet();
//         }

//         // Check there's collateral to claim
//         if (info.collateral == 0) {
//             revert NoCollateralToClaim();
//         }

//         // Store amount to return
//         uint256 amountToReturn = info.collateral;

//         // Clear operator info
//         delete operatorInfo[msg.sender];

//         // TODO safe transfer for rentrancy
//         (bool success, ) = msg.sender.call{value: amountToReturn}("");
//         require(success, "Transfer failed");

//         emit CollateralRemoved(msg.sender, amountToReturn);
//     }

//     function slashRegistration(
//         address operator,
//         uint256 index,
//         BLS12381.G1Point calldata pubkey,
//         BLS12381.G2Point calldata signature
//     ) external {
//         Validator memory validator = operatorToValidator[msg.sender][index];

//         // Verify the supplied calldata matches what has been committed
//         if (_hashBLSPubKey(validator.pubkey) != _hashBLSPubKey(pubkey)) {
//             revert WrongPubkey();
//         }

//         if (validator.signatureHash != _hashSignature(signature)) {
//             revert WrongSignature();
//         }

//         // Verify the signature
//         bytes memory message = abi.encodePacked(operator);
//         if (_verifySignature(message, signature, pubkey)) {
//             revert SignatureWasValid();
//         }

//         // todo slash the validator collateral
//         // todo do we pay the msg.sender?

//         emit ValidatorRegistrationSlashed(operator, index, pubkey);
//     }

//     /**
//      * @notice Returns `true` if the BLS signature on the message matches against the public key
//      * @param message The message bytes
//      * @param sig The BLS signature
//      * @param pubkey The BLS public key of the expected signer
//      */
//     function _verifySignature(
//         bytes memory message,
//         BLS12381.G2Point memory sig,
//         BLS12381.G1Point memory pubkey
//     ) internal view returns (bool) {
//         bytes memory domainSeparator = bytes("Proposer Commitment Registry");
//         // Hash the message bytes into a G2 point
//         BLS12381.G2Point memory msgG2 = message.hashToCurveG2(domainSeparator);

//         // Return the pairing check that denotes the correctness of the signature
//         return BLS12381.pairing(pubkey, msgG2, BLS12381.negGeneratorG1(), sig);
//     }

//     function _hashBLSPubKey(
//         BLS12381.G1Point memory pubkey
//     ) internal pure returns (bytes32) {
//         uint256[2] memory compressedPubKey = pubkey.compress();
//         return keccak256(abi.encodePacked(compressedPubKey));
//     }

//     function _hashSignature(
//         BLS12381.G2Point memory signature
//     ) internal pure returns (bytes32) {
//         uint256[8] memory flattenedSignature = signature.flatten();
//         return keccak256(abi.encodePacked(flattenedSignature));
//     }
// }
