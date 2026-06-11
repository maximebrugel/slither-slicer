// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

library LibMath {
    // A validating transformer: reverts on zero, returns a derived value.
    function checkedDouble(uint256 x) internal pure returns (uint256) {
        require(x > 0, "zero");
        return x * 2;
    }
}

contract Library {
    using LibMath for uint256;

    address public owner;
    uint256 public total;

    event Stored(uint256 value);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // Guarded; value flows through a library call (data + control dependence).
    function store(uint256 amount) external onlyOwner {
        uint256 doubled = amount.checkedDouble();
        total = doubled;
        emit Stored(doubled);
    }

    // Unguarded external call whose TARGET is an attacker-controlled parameter.
    function forward(address target, bytes calldata data) external {
        (bool ok, ) = target.call(data);
        require(ok, "call failed");
    }
}
