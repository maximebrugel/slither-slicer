// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

// Checks-effects-interactions done correctly: state is written BEFORE the
// external call, so there is no state write reachable after it.
contract CEISafe {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");
        balances[msg.sender] = 0; // effect first
        (bool ok, ) = msg.sender.call{value: amount}(""); // interaction last
        require(ok, "failed");
    }
}
