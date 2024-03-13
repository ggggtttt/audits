# Smart Contract Security Assessment

Client: edgelessNetwork </br>
Timeline: 23.02.2024 - 24.02.2024</br>
Repository: https://github.com/edgelessNetwork/contracts</br>
Commit ID: 85b6ab5a665bfdf3efbc1c8470849a0061c214b4</br>
Remediation Commit ID: n/a</br>
Size: 213 nSLOC</br>

## Solution

The yield generating contracts on Ethereum for Edgeless Network. The vision of Edgeless is to lower or remove the transaction fees that dApps currently charge and monetize via bridged TVL. Edgeless is able to pool together the revenue that is generated across the ecosystem and redistribute it to app developers based on the value they bring to the ecosystem.

## Scope

- src/EdgelessDeposit.sol
- src/StakingManager.sol
- src/WrappedToken.sol
- src/Constants.sol
- src/strategies/EthStrategy.sol

## Out of scope

- src/interfaces/*
- Centralization concerns.

## Limitations

- Staking of DAI was not implemented within the timeline of the security assessment.

# Disclaimer

The vulnerabilities identified in the report are based on the tests conducted during the limited period with information provided by the client in advance, whereas a cybercriminal is not limited to such restrictions. Therefore, despite the fact of taking reasonable care to perform the security assessment, this report may not cover all weaknesses existing within the solution.

# Risk rate methodology

Within the security assessment the qualitative severity raking was used with labels: Critical, High, Medium, Low and Information. The severity assigned to each finding was assessed based on the auditor's experience and in accordance with the leading security practices.

# Findings

## [L01] The withdrawEth() function may transfer ether to not existing address

The `withdrawEth()` function accepts `address to` as input parameter. If user supplied data are incorrect, the low level call function will transfer ether and return positive value in `success` output parameter. Thus, a user may transfer ether to the non-existing address.

```solidity
function withdrawEth(address to, uint256 amount) external {
    wrappedEth.burn(msg.sender, amount);
    stakingManager.withdraw(amount);
    (bool success, bytes memory data) = to.call{ value: amount }("");
    if (!success) revert TransferFailed(data);
    emit WithdrawEth(msg.sender, to, amount, amount);
}
```

Severity: Low</br>
Recommendation: It is recommended to allow withdrawal only to `msg.sender`. Alternatively, it is recommended to implement two separate functions for withdrawals to mitigate this vulnerability.

## [I01] StakingManager, EthStrategy, EdgelessDeposit contracts lack _disableInitializers()

It was identified that none of the upgradable contracts within the solution calls the `_disableInitializers()` to disable implementations. However, no possibility to attack the implementation itself was identified.

Severity: Information</br>
Recommendation: It is recommended to disable implementations for each upgradable contract within the solution.

## [I02] The _withdrawEth() function emits Withdraw with `amount`

It was identified that the `_withdrawEth()` function emits `Withdraw` event with `amount` as input parameter. Thus, it may issue incorrect information within the event, as it actually transfers the `withdrawnAmount` amount instead.

```solidity
function _withdrawEth(uint256 amount) internal {
    IStakingStrategy strategy = getActiveStrategy(ETH_ADDRESS);
    uint256 withdrawnAmount;
    if (address(strategy) != address(0)) {
        withdrawnAmount = strategy.withdraw(amount);
    } else {
        withdrawnAmount = amount > address(this).balance ? address(this).balance : amount;
    }
    (bool success, bytes memory data) = staker.call{ value: withdrawnAmount }("");
    if (!success) revert TransferFailed(data);
    emit Withdraw(ETH_ADDRESS, amount);
}
```

Severity: Information</br>
Recommendation: It is recommended to emit `Withdraw` event with `withdrawnAmount` as input parameter.

## [I03] The removeStrategy() emits RemoveStrategy with potentially overestimated `withdrawnAmount`

The EthStrategy `withdraw()` only its current balance, where `underlyingAssetAmount()` returns the sum of balance and LIDO's balance. If LIDO's balance remains positive, the `removeStrategy()` can emit incorrect, overestimated information.

```solidity
function removeStrategy(address asset, uint256 index) external onlyOwner {
      IStakingStrategy strategy = strategies[asset][index];
      uint256 withdrawnAmount = strategy.withdraw(strategy.underlyingAssetAmount()); //@audit
      ...
      emit RemoveStrategy(asset, strategy, withdrawnAmount);
  }
```

```solidity
function underlyingAssetAmount() external view returns (uint256) {
      return address(this).balance + LIDO.balanceOf(address(this));
  }
```

```solidity
function withdraw(uint256 amount) external onlyStakingManager returns (uint256 withdrawnAmount) {
    uint256 balance = address(this).balance;
    if (amount > balance) {
        withdrawnAmount = balance;
    } else {
        withdrawnAmount = amount;
    }
    (bool success, bytes memory data) = stakingManager.call{ value: withdrawnAmount }("");
    if (!success) revert TransferFailed(data);
    emit EthWithdrawn(withdrawnAmount);
    return withdrawnAmount;
}
```

Severity: Information</br>
Recommendation: It is recommended to review the implementation and decide what value should be emitted within the `RemoveStrategy` event.


## [I04] The requestLidoWithdrawal() lacks input validation

The `requestLidoWithdrawal()` function attempts to request wihdrawals within the LIDO solution. However, it does not check whether the amounts provided are between the range of MIN_STETH_WITHDRAWAL_AMOUNT and MAX_STETH_WITHDRAWAL_AMOUNT values defined within the LIDO. As a result, this function may revert in later processing consuming additional amount of gas.

```solidity
function requestLidoWithdrawal(uint256[] calldata amounts)
        external
        onlyOwner
        returns (uint256[] memory requestIds)
{
    uint256 total;
    for (uint256 i; i < amounts.length; ++i) {
        total += amounts[i];
    }
    LIDO.approve(address(LIDO_WITHDRAWAL_ERC721), total);
    requestIds = LIDO_WITHDRAWAL_ERC721.requestWithdrawals(amounts, address(this));
    emit RequestedLidoWithdrawals(requestIds, amounts);
}
```

Severity: Information</br>
Recommendation: It is recommended to consider implementation of aforementioned input validation to save some gas.

## [I05] The mintEthBasedOnStakedAmount() may revert due to integer underflow

The LIDO solution is rebalancing token, thus its value may increase or decrease over the time. Assuming there are no owner deposits, in the rare event of LIDO's validators slashing, the LIDO balance may decrease during rebalance. Thus, the number of issued `wrappedTokens` can be higher than value returned by the `getAssetTotal()` function. In such case, the `mintEthBasedOnStakedAmount()` function may revert for short period.

```solidity
function mintEthBasedOnStakedAmount(address to, uint256 amount) external onlyOwner {
    uint256 maxMint = stakingManager.getAssetTotal(stakingManager.ETH_ADDRESS()) - wrappedEth.totalSupply();
    if (maxMint < amount) revert MaxMintExceeded();
    wrappedEth.mint(to, amount);
    emit MintWrappedEth(to, amount);
}
```

```solidity
function getAssetTotal(address asset) external view returns (uint256 total) {
    for (uint256 i = 0; i < strategies[asset].length; i++) {
        IStakingStrategy strategy = strategies[asset][i];
        total += strategy.underlyingAssetAmount();
    }
}

```solidity
function underlyingAssetAmount() external view returns (uint256) {
      return address(this).balance + LIDO.balanceOf(address(this));
  }
```

Severity: Information</br>
Recommendation: It is recommended to add validation check whether the function can process minting of the accrued revenue.

## [I06] The mintEthBasedOnStakedAmount() can be manipulated to mint additional tokens

The `mintEthBasedOnStakedAmount()` function is minting new wrappedTokens for ether rewards accrued overtime. However, the limitation can be bypassed by adding the same strategy twice via `addStrategy()` function. Then, in such event the amount returned by the `getAssetTotal()` is doubled. Still, it must be noted that Owner can do manipulation by other means, e.g. via the `setStaker()` function.

Severity: Information</br>
Recommendation: It is recommended to consider adding validation check that prevents adding the same strategy twice.
