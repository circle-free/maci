// SPDX-License-Identifier: MIT

pragma solidity ^0.7.3;

abstract contract InitialVoiceCreditProxy {
    function getVoiceCredits(address _user, bytes memory _data) public view virtual returns (uint256);
}
