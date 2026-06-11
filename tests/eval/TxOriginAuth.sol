// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

// tx.origin authentication is phishable: a malicious contract the owner calls can
// forward into withdraw and pass the check. Signal: the guard depends on
// tx.origin (not msg.sender).
contract Phishable {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function withdraw(address payable to) external {
        require(tx.origin == owner, "not owner");
        to.transfer(address(this).balance);
    }
}
