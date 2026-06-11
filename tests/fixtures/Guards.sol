// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Regression fixture for `guarded`: only modifiers that actually check caller
// identity count. nonReentrant restricts nothing about who may call.

contract Guards {
    address public owner;
    uint256 public value;
    bool private locked;
    mapping(address => bool) public allowed;
    mapping(address => uint256) public balances;

    modifier nonReentrant() {
        require(!locked, "reentrant");
        locked = true;
        _;
        locked = false;
    }

    // OZ-style: the modifier delegates the caller check to an internal function
    modifier onlyOwnerIndirect() {
        _checkOwner();
        _;
    }

    function _checkOwner() internal view {
        require(msg.sender == owner, "not owner");
    }

    // nonReentrant only — anyone may call: NOT guarded
    function poke() external nonReentrant {
        value = 1;
    }

    // guarded via the indirect modifier
    function adminIndirect(uint256 v) external onlyOwnerIndirect {
        value = v;
    }

    // guarded via an in-body caller check
    function adminInline(uint256 v) external {
        require(msg.sender == owner, "not owner");
        value = v;
    }

    // solvency check: reads msg.sender but anyone with a balance passes — NOT guarded
    function spend(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
    }

    // boolean allowlist lookup IS access control
    function gated(uint256 v) external {
        require(allowed[msg.sender], "not allowed");
        value = v;
    }
}
