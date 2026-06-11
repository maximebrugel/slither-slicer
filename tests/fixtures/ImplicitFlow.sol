// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Regression fixture for forward slicing: taint reaches a branch condition
// through an assignment, and the statements the branch guards (implicit flow)
// must be in the slice.

contract ImplicitFlow {
    bool public won;

    function play() external payable {
        uint256 v = msg.value;
        if (v > 1 ether) {
            won = true;
        }
    }
}
