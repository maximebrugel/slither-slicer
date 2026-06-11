// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

// Three-level inheritance A -> B -> C. A guard declared in the base must protect
// a privileged write in the most-derived contract, and ascent must climb through
// both levels.
contract Base {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }
}

contract Middle is Base {
    uint256 public config;

    function _apply(uint256 v) internal {
        config = v;
    }
}

contract Top is Middle {
    function setConfig(uint256 v) external onlyOwner {
        _apply(v);
    }
}
