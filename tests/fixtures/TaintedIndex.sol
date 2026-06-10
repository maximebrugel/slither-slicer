// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract TaintedIndex {
    mapping(uint256 => uint256) public slots;

    function set(uint256 key, uint256 val) external {
        uint256 idx = key + 1;
        slots[idx] = val;
    }
}
