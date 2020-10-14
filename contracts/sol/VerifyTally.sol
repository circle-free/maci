// SPDX-License-Identifier: MIT

pragma solidity <= 0.7.3;
pragma experimental ABIEncoderV2;

import "./Hasher.sol";

contract VerifyTally is Hasher {

    uint8 internal constant TALLY_LEAVES_PER_NODE = 5;

    function computeMerkleRootFromPath(
        uint8 _depth,
        uint256 _index,
        uint256 _leaf,
        uint256[][] memory _pathElements
    ) public pure returns (uint256) {
        uint256 pos = _index % TALLY_LEAVES_PER_NODE;
        uint256 current = _leaf;
        uint8 k;

        uint256[] memory level = new uint256[](TALLY_LEAVES_PER_NODE);

        for (uint8 i = 0; i < _depth; i ++) {
            for (uint8 j = 0; j < TALLY_LEAVES_PER_NODE; j ++) {
                if (j == pos) {
                    level[j] = current;
                } else {
                    if (j > pos) {
                        k = j - 1;
                    } else {
                        k = j;
                    }
                    level[j] = _pathElements[i][k];
                }
            }

            _index /= TALLY_LEAVES_PER_NODE;
            pos = _index % TALLY_LEAVES_PER_NODE;
            current = hash5(level);
        }

        return current;
    }
}
