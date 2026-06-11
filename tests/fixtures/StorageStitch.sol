// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

// Storage stitching target: `balances` is read in withdraw() but written in two
// other functions — an unguarded deposit() and an owner-only slash() that has
// its own require. A backward slice from withdraw's transfer with storage_depth
// must pull both writers; `owner` is written only in the constructor.
contract StorageStitch {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function slash(address user, uint256 amount) external onlyOwner {
        require(amount <= balances[user], "too much");
        balances[user] -= amount;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "failed");
    }
}
