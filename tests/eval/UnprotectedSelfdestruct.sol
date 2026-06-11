// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

// Parity-wallet-style: an unprotected function that destroys the contract.
// Anyone can call kill(). Signal: a selfdestruct sink in an unguarded function.
contract Wallet {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function kill() external {
        selfdestruct(payable(msg.sender));
    }
}
