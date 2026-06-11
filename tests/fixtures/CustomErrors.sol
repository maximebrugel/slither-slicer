// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

error Unauthorized(address caller);
error TooSmall(uint256 given, uint256 min);

// Modern Solidity guards: `if (cond) revert CustomError()` carries no require, so
// guard detection and control dependence must recognise the conditional revert.
contract CustomErrors {
    address public owner;
    uint256 public value;

    function setGuarded(uint256 v) external {
        if (msg.sender != owner) revert Unauthorized(msg.sender);
        value = v;
    }

    function setChecked(uint256 v) external {
        if (v < 10) revert TooSmall(v, 10);
        value = v;
    }
}
