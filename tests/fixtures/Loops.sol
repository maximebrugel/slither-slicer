// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

// A loop that pays out an array of recipients: the external call sits inside the
// loop, and the loop bound / index influence it. Slicing must terminate and pull
// the loop guard.
contract Loops {
    mapping(address => uint256) public owed;

    function payAll(address[] calldata users) external {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 amount = owed[users[i]];
            owed[users[i]] = 0;
            (bool ok, ) = users[i].call{value: amount}("");
            require(ok, "pay failed");
        }
    }
}
