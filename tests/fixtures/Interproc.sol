// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Interproc {
    mapping(address => uint256) public balances;

    function _transfer(address to, uint256 value) internal {
        balances[to] = balances[to] - value;
        (bool ok, ) = to.call{value: value}("");
        require(ok, "failed");
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        _transfer(msg.sender, amount);
    }
}
