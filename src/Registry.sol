// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import {BLS12381} from "./lib/BLS12381.sol";
import {MerkleUtils} from "./lib/Merkelize.sol";

contract Registry {
    using BLS12381 for *;

    struct Registration {
        uint256[2] pubkey; // compressed bls pubkey
        uint256[8] signature; // flattened Registration signature
    }

    struct Operator {
        bytes32 commitmentKey; // compressed ecdsa key without prefix
        address operator; // msg.sender can be a multisig
        uint72 collateral; // todo save as GWEI
        uint32 registeredAt;
        uint32 unregisteredAt;
        uint32 unregistrationDelay;
        // anything else?
    }

    struct Leaf {
        uint256[2] pubkey; // compressed pubkey
        bytes32 registrationCommitment; // sha256(signature || commitmentKey)
    }

    mapping(bytes32 operatorCommitment => Operator) public commitments;

    // Constants
    uint256 constant MIN_COLLATERAL = 0.1 ether;
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
    error UnregistrationDelayTooShort();

    // Events
    event OperatorRegistered(bytes32 operatorCommitment, uint32 registeredAt);
    event OperatorUnregistered(
        bytes32 operatorCommitment,
        uint32 unregisteredAt
    );
    event OperatorDeleted(bytes32 operatorCommitment, uint72 amountToReturn);

    function register(
        Registration[] calldata registrations,
        bytes32 commitmentKey,
        uint32 unregistrationDelay,
        uint256 height
    ) external payable {
        // check collateral
        if (msg.value < MIN_COLLATERAL) {
            revert InsufficientCollateral();
        }

        if (unregistrationDelay < TWO_EPOCHS) {
            revert UnregistrationDelayTooShort();
        }

        // operatorCommitment hash = merklize registrations
        bytes32 operatorCommitment = createCommitment(
            registrations,
            commitmentKey,
            height
        );

        // add operatorCommitment to mapping
        commitments[operatorCommitment] = Operator({
            operator: msg.sender,
            commitmentKey: commitmentKey,
            collateral: uint72(msg.value), // todo save as GWEI
            registeredAt: uint32(block.number),
            unregistrationDelay: unregistrationDelay,
            unregisteredAt: 0
        });

        // emit events
    }

    function createCommitment(
        Registration[] calldata registrations,
        bytes32 commitmentKey,
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
                abi.encodePacked(registrations[i].signature, commitmentKey)
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
        bytes32 commitmentKey,
        bytes32[] calldata proof,
        uint256 leafIndex
    ) external {
        Operator storage operator = commitments[operatorCommitment];

        uint256[2] memory pubkeyBytes = pubkey.compress(); // compressed bls pubkey
        uint256[8] memory signatureBytes = signature.flatten(); // flattened registration signature

        // reconstruct leaf
        bytes32 leaf = sha256(abi.encodePacked(
            pubkeyBytes,
            sha256(abi.encodePacked(signatureBytes, commitmentKey))
        ));

        // verify proof against operatorCommitment
        if (MerkleUtils.verifyProof(proof, operatorCommitment, leaf, leafIndex)) {
            revert FraudProofMerklePathInvalid();
        }

        // reconstruct message 
        // todo what exactly are they signing?
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
        if (block.number < operator.unregisteredAt + operator.unregistrationDelay) {
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