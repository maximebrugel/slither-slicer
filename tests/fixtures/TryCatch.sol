// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IFeed {
    function read() external returns (uint256);
}

contract TryCatch {
    uint256 public last;
    bool public failed;

    function update(IFeed feed) external {
        try feed.read() returns (uint256 v) {
            last = v; // success path: external return flows to state
        } catch {
            failed = true; // catch path: state write under the failure branch
        }
    }
}
