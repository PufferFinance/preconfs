# preconfs

## TODOs

[Registry.sol](src/Registry.sol)
- [x] Reduce `MIN_COLLATERAL` to 0.1 ETH. It needs to be non-zero to incentivize people to slash bad registrations.
- [ ] Save the `Operator.collateral` as GWEI.
- [ ] Optimistically accept an `OperatorCommitment` hash. It can be proven as fraudulent by generating the merkle tree in the fraud proof.
- [ ] Make the unregistration delay parameterizable by the proposer but requires it to be at least `TWO_EPOCHS`.
- [ ] Spec out the `Registration` message signed by a Validator BLS key. 
- [ ] Make sure no one can overwrite an `OperatorCommitment`
- [ ] Diagram the registration process
- [ ] Add field to `Operator` struct to signal if they are a gateway (open for discussion). 


[BytecodeSlasher.sol](src/BytecodeSlasher.sol)
- [ ] Update the `BytecodeSlasher` interface to include the slashing evidence
- [ ] Any additional modifiers needed? 
- [ ] Verify the `Delegation` signature inside the `BytecodeSlasher` 
