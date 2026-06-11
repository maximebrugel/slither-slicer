// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

// receive() and fallback() are entry points too — value can arrive through them
// and their state writes must be cataloged as sinks.
contract FallbackReceive {
    uint256 public received;
    address public lastSender;

    receive() external payable {
        received += msg.value;
    }

    fallback() external payable {
        lastSender = msg.sender;
    }
}
