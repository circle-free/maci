// SPDX-License-Identifier: MIT

pragma solidity ^0.7.3;

import './SignUpGatekeeper.sol';

abstract contract POAPGatekeeper is SignUpGatekeeper {

    //function isAllowed(address _user, bytes memory _data) public returns (bool) {
        //return true;
        //// Decode _data as the token ID

        //uint256 tokenId;
        //address signUpTokenAddress;
        //(tokenId, signUpTokenAddress) = abi.decode(_data, (uint256, address));
        //bool isOwner = SignUpToken(signUpTokenAddress).ownerOf(tokenId) == _user;

        //return isOwner;
    //}
}
