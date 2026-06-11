// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

// delegatecall into an attacker-controlled target runs arbitrary code in this
// contract's storage context — full takeover. Signal: a delegatecall sink in an
// unguarded function whose target is a parameter.
contract Proxy {
    address public implementation;

    function execute(address target, bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }
}
