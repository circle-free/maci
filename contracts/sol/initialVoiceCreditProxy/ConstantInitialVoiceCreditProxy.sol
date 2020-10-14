// SPDX-License-Identifier: MIT

pragma solidity ^0.7.3;

import './InitialVoiceCreditProxy.sol';

contract ConstantInitialVoiceCreditProxy is InitialVoiceCreditProxy {

    uint256 internal balance;

    constructor(uint256 _balance) { 
        balance = _balance;
    }

    function getVoiceCredits(address, bytes memory) public view override returns (uint256) {
        return balance;
    }
}
