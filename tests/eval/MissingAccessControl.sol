// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

// A privileged setter with no caller restriction: anyone can change the fee and
// the withdrawal address. Signal: an unguarded privileged state write.
contract Config {
    address public owner;
    uint256 public fee;
    address public treasury;

    constructor() {
        owner = msg.sender;
    }

    // Correctly guarded for contrast.
    function setOwner(address o) external {
        require(msg.sender == owner, "not owner");
        owner = o;
    }

    // BUG: no access control.
    function setFee(uint256 f) external {
        fee = f;
    }

    // BUG: no access control on a fund-routing change.
    function setTreasury(address t) external {
        treasury = t;
    }
}
