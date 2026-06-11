// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

// The call target is attacker-controlled (a function parameter), so this forwards
// arbitrary calls with the contract's authority. Signal: sink:arbitrary_call.
contract Forwarder {
    function forward(address target, bytes calldata data) external {
        (bool ok, ) = target.call(data);
        require(ok, "call failed");
    }
}
