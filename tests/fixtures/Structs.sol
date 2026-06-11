// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

// Struct field access through a storage mapping: slicing must resolve the base
// (positions) and flag the non-constant key as imprecise.
contract Structs {
    struct Position {
        uint256 size;
        address owner;
    }

    mapping(uint256 => Position) public positions;

    function open(uint256 id, uint256 size) external {
        positions[id].size = size;
        positions[id].owner = msg.sender;
    }

    function sizeOf(uint256 id) external view returns (uint256) {
        return positions[id].size;
    }
}
