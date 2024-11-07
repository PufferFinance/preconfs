# preconfs

## TODOs

[Registry.sol](src/Registry.sol)
- [x] Reduce `MIN_COLLATERAL` to 0.1 ETH. It needs to be non-zero to incentivize people to slash bad registrations.
- [ ] Optimistically accept an `OperatorCommitment` hash. It can be proven as fraudulent by generating the merkle tree in the fraud proof.
- [ ] Make the unregistration delay parameterizable by the proposer but requires it to be at least `TWO_EPOCHS`.
- [ ] Spec out the `Registration` message signed by a Validator BLS key. 
- [ ] Make sure no one can overwrite an `OperatorCommitment`
- [ ] Save the `Operator.collateral` as GWEI.
- [ ] Diagram the registration process
- [ ] Add field to `Operator` struct to signal if they are a gateway (open for discussion). 


[BytecodeSlasher.sol](src/BytecodeSlasher.sol)
- [ ] Update the `BytecodeSlasher` interface to include the slashing evidence, signed bytecode, operator commitment, proxy key, and function selector.
- [ ] Any additional modifiers needed? 
- [ ] Verify the `Delegation` signature inside the `BytecodeSlasher` 
- [ ] If we want to support 'stateful' slashing contracts we should consider signing `slasherAddress || functionSelector` and invoking that instead of deploying and executing bytecode.


## Schemas
```
struct RegistrationMessage {
    // compressed ECDSA key without prefix used to sign `Delegation` messages
    bytes32 proxyKey; 

    // the address that can unregister and claim collateral
    address operator; 

    // the number of blocks to wait before the operator can unregister
    uint16 unregistrationDelay; 
}
```

```
class Delegation(Container):
    validator_pubkey: BLSPubkey
    delegatee_pubkey: BLSPubkey
    bytecode_hash: Bytes
    metadata: Bytes
struct RegistrationMessage {
    // Validator's compressed BLS public key
    bytes validatorPubkey; 

    // Key used to sign this container
    bytes32 proxyKey; 

    // Hash of the slashing bytecode to be executed
    bytes32 bytecodeHash;

    // Arbitrary metadata to be included in the delegation (we should include the OperatorCommitment)
    bytes metadata; 
}
```