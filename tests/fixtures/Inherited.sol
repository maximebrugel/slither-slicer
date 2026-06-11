// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Regression fixture: code declared in a base contract is live code of the
// derived contract — sinks there must be cataloged, and ascent must climb
// into base-declared callers.

contract Base {
    uint256 public stored;

    // sink declared in the BASE contract (inherited by Vault, never overridden)
    function sweep(address payable to) external {
        to.transfer(address(this).balance);
    }

    // base-declared caller of _store — ascent from _store must find it
    function baseEntry(uint256 v) external {
        _store(v);
    }

    function _store(uint256 amt) internal {
        stored = amt;
    }

    // two-level call chain for the --depth knob: two -> one -> _store
    function two(uint256 v) external {
        one(v);
    }

    function one(uint256 v) public {
        _store(v);
    }
}

contract Vault is Base {
    function deposit() external payable {
        _store(msg.value);
    }
}
