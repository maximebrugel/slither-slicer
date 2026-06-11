// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

// Concrete callee in the same compilation unit: Vault.pull resolves to exactly
// one Token, so a cross-contract descent can peer into Token.transfer.
contract Token {
    mapping(address => uint256) public bal;

    function transfer(address to, uint256 amount) external {
        bal[to] += amount;
    }

    function balanceOf(address a) external view returns (uint256) {
        return bal[a];
    }
}

interface IOracle {
    function price() external view returns (uint256);
}

// Single implementer of IOracle in the unit -> resolvable via the interface.
contract Oracle is IOracle {
    uint256 public p;

    function price() external view returns (uint256) {
        return p;
    }
}

// Two implementers of IPriced -> a call through IPriced is ambiguous.
interface IPriced {
    function quote() external view returns (uint256);
}

contract PricedA is IPriced {
    function quote() external pure returns (uint256) {
        return 1;
    }
}

contract PricedB is IPriced {
    function quote() external pure returns (uint256) {
        return 2;
    }
}

contract Vault {
    Token public token;
    IOracle public oracle;
    IPriced public priced;

    // Concrete cross-contract call: token is a Token.
    function pull(address to, uint256 amount) external {
        token.transfer(to, amount);
    }

    // Interface call with a single implementer (Oracle).
    function readPrice() external view returns (uint256) {
        return oracle.price();
    }

    // Interface call with two implementers -> ambiguous, stays opaque.
    function readQuote() external view returns (uint256) {
        return priced.quote();
    }
}
