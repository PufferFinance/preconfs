// SPDX-License-Identifier: MIT
// Credit https://github.com/NethermindEth/Taiko-Preconf-AVS/blob/master/SmartContracts/src/libraries/MerkleUtils.sol

pragma solidity >=0.8.0 <0.9.0;

library MerkleUtils {

    function hash(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(a, b));
    }

    function merkleize(bytes32[] memory chunks) internal pure returns (bytes32) {
        uint256 length = chunks.length;
        bytes32[] memory tmp = new bytes32[](length);

        for (uint256 i; i < chunks.length; ++i) {
            merge(tmp, i, chunks[i]);
        }

        return tmp[length - 1];
    }

    function merge(bytes32[] memory tmp, uint256 index, bytes32 chunk) internal pure {
        bytes32 h = chunk;
        uint256 j = 0;
        while (true) {
            if (index & 1 << j == 0) {
                break;
            } else {
                h = hash(tmp[j], h);
            }
            j += 1;
        }
        tmp[j] = h;
    }

    function verifyProof(bytes32[] memory proof, bytes32 root, bytes32 leaf, uint256 leafIndex)
        internal
        pure
        returns (bool)
    {
        bytes32 h = leaf;
        uint256 index = leafIndex;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];

            if (index % 2 == 0) {
                h = sha256(bytes.concat(h, proofElement));
            } else {
                h = sha256(bytes.concat(proofElement, h));
            }

            index = index / 2;
        }

        return h == root;
    }

    function toLittleEndian(uint256 n) internal pure returns (bytes32) {
        uint256 v = n;
        v = ((v & 0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >> 8)
            | ((v & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) << 8);
        v = ((v & 0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >> 16)
            | ((v & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) << 16);
        v = ((v & 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >> 32)
            | ((v & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) << 32);
        v = ((v & 0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >> 64)
            | ((v & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) << 64);
        v = (v >> 128) | (v << 128);
        return bytes32(v);
    }
}