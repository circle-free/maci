// SPDX-License-Identifier: MIT

pragma solidity <= 0.7.3;
pragma experimental ABIEncoderV2;

contract MACISharedObjs {
    uint8 constant MESSAGE_DATA_LENGTH = 10;
    struct Message {
        uint256 iv;
        uint256[MESSAGE_DATA_LENGTH] data;
    }

    struct PubKey {
        uint256 x;
        uint256 y;
    }
}
