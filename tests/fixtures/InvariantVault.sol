// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixtures for check_state_invariant. InvariantVault has a planted relational
// divergence (totalSupply vs sum(balances)); AssemblyVault exercises the
// completeness caveat (an inline-assembly sstore Slither does not attribute).

contract InvariantVault {
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public debts; // same-type sibling of `balances`
    uint256 public constant CAP = 1_000_000 ether; // never written -> no-writers
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // holds: bumps both sides of totalSupply == sum(balances)
    function mint(address to, uint256 amt) external {
        balances[to] += amt;
        totalSupply += amt;
    }

    // violates: attacker-reachable, bumps totalSupply WITHOUT balances
    function badMint(address to, uint256 amt) external {
        totalSupply += amt;
    }

    // underconstrained-setter: breaks the invariant but admin-only
    function setTotalSupply(uint256 v) external {
        require(msg.sender == owner, "not owner");
        totalSupply = v;
    }
}

contract AssemblyVault {
    uint256 public total;

    function plainWrite(uint256 v) external {
        total = v; // attributed by Slither
    }

    function rawBump(uint256 v) external {
        // sstore is NOT attributed to `total` by Slither -> completeness caveat
        assembly {
            sstore(total.slot, add(sload(total.slot), v))
        }
    }
}
