// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

// Minimal SafeERC20-style wrapper: a library call we descend into. The token
// movement must still be cataloged as a sink at the calling contract.
library SafeERC20 {
    function safeTransfer(IERC20 token, address to, uint256 amount) internal {
        require(token.transfer(to, amount), "safeTransfer failed");
    }
}

contract Vault {
    using SafeERC20 for IERC20;

    IERC20 public token;
    mapping(address => uint256) public shares;

    // Raw external token transfer -> sink:token_transfer.
    function pay(address to, uint256 amount) external {
        token.transfer(to, amount);
    }

    // Pull via transferFrom -> sink:token_transfer.
    function pull(address from, uint256 amount) external {
        token.transferFrom(from, address(this), amount);
    }

    // Approval -> sink:token_approval.
    function allow(address spender, uint256 amount) external {
        token.approve(spender, amount);
    }

    // SafeERC20 library wrapper -> still sink:token_transfer (caught on the
    // library call), and the library body is descended into.
    function safePay(address to, uint256 amount) external {
        token.safeTransfer(to, amount);
    }
}
