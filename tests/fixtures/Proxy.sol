// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Regression fixture for node_id drill-in: a delegatecall sink is a whole-node
// criterion (no variable), reachable only via its catalog `criterion_node_id`.

contract Proxy {
    address public impl;

    function setImpl(address a) external {
        impl = a;
    }

    function exec(bytes calldata data) external {
        (bool ok, ) = impl.delegatecall(data);
        require(ok, "delegatecall failed");
    }

    // staticcall is read-only — must not register as an external-call sink
    function peek(address target) external view returns (bool ok) {
        (ok, ) = target.staticcall("");
    }
}
