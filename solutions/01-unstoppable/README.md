# Smart Contract Security Audit Report

---

## [H-01] Denial of Service (DoS) in UnstoppableVault via Direct Token Transfer (Strict Accounting Invariant Bypass)

### Severity
* **Classification:** High
* **Impact:** High (Permanent freezing of the core flash loan utility and monitoring system, resulting in complete failure of the protocol's primary function).
* **Likelihood:** High (Extremely simple to execute by any external actor with no special privileges or large capital requirements).

---

### Executive Summary
The `UnstoppableVault` contract provides zero-fee flash loans utilizing an ERC-4626 tokenized vault structure. However, the contract relies on a strict mathematical assertion to validate that its internal accounting matches its actual token balances. 

Because standard ERC-20 tokens allow direct transfers that bypass the contract's vault deposit interface (`deposit()` or `mint()`), an attacker can force-feed the vault with standard tokens. This desynchronizes the vault's physical assets from its share registry, permanently bricking the `flashLoan` mechanism and causing an irreversible Denial of Service.

---

### Vulnerability Detail (Root Cause Analysis)

#### 1. ELI5 (Explain Like I'm 5)
Imagine a magical piggy bank (the Vault). When you put coins into the piggy bank using the front slot (Legitimate Deposit), it gives you paper receipts (Shares) so you can prove how much you put in. The piggy bank keeps two notebooks:
* **Notebook A (Internal Registry):** Calculates how many coins should be inside based on the total paper receipts given out (`convertToShares(totalSupply)`).
* **Notebook B (Reality Check):** Peeks inside the box and counts every physical coin (`totalAssets()`, which reads the raw token balance).

Whenever someone wants to borrow coins for a split second (Flash Loan), the piggy bank checks both notebooks and says: "Before I let you borrow, Notebook A must match Notebook B EXACTLY."

But there's a back door. Someone can slide a tiny coin (1 wei) through the back door directly into the piggy bank without getting a paper receipt. 

Now:
* Notebook B (physical coin count) goes up by 1 coin.
* Notebook A (receipt registry) stays exactly the same.

Because the two notebooks no longer match, the piggy bank gets confused, assumes there is an accounting error, and refuses to open its doors to anyone trying to take a flash loan ever again.

#### 2. Advanced Technical Explanation
Under the hood, `UnstoppableVault` inherits from `ERC4626`. It overrides the `totalAssets()` function to return the raw ERC-20 balance of the contract.

```solidity
function totalAssets() public view override returns (uint256) {
    return asset.balanceOf(address(this));
}
```

During the execution of the flashLoan function, the contract enforces a strict accounting invariant check before executing the transfer of assets to the borrower.

uint256 balanceBefore = totalAssets();
if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance();

The `convertToShares` method follows the standard ERC-4626 mathematical formula:

$$
shares = \frac{assets \times totalSupply}{totalAssets()}
$$

In a healthy state where the vault only receives tokens via `deposit()` or `mint()`, the asset-to-share ratio is 1:1, meaning `totalAssets()` perfectly equals `totalSupply`. Thus, `convertToShares(totalSupply)` yields an identical value to `balanceBefore`.

If an attacker executes a direct transfer of **1 wei** using the raw ERC-20 `transfer()` function:
1. `totalAssets()` (and therefore `balanceBefore`) increases by 1.
2. `totalSupply` remains unchanged because no new shares were minted.
3. When `convertToShares(totalSupply)` is calculated, the formula uses the new, inflated `totalAssets()` in its denominator:

$$
shares = \frac{totalSupply \times totalSupply}{totalAssets() + 1}
$$

Because the denominator is now larger, the result of the division changes due to Solidity's integer division floor truncation. Consequently, the calculated shares will never equal `balanceBefore` again. Since there is no administrative recovery or sync function to re-align state variables, the flash loan utility is permanently bricked.

---

### Proof of Concept (PoC)

Based on the automated **Foundry/Forge** execution traces, the exploit execution succeeds through the following concrete phase transitions:

#### 1. Invariant Desynchronization
The attacker (`player`) completely bypasses the vault's entry interfaces and executes a direct `transfer` of **1 wei** of the underlying asset directly to the `UnstoppableVault` address.

* **Prior State of Vault:**
  * `totalAssets()` = `1000000000000000000000000` ($10^6$ tokens)
  * `totalSupply()` = `1000000000000000000000000`
* **Current State of Vault (Post-Exploit):**
  * `totalAssets()` = `1000000000000000000000001` ($10^6$ tokens + 1 wei)
  * `totalSupply()` = `1000000000000000000000000`

#### 2. Complete Denial of Service (DoS)
When any subsequent actor or the monitoring circuit (`UnstoppableMonitor`) triggers `checkFlashLoan()`, the call jumps into `UnstoppableVault::flashLoan()`. The EVM processes the balance queries via `[staticcall]`, encounters the desynchronized strict equality check, and triggers a state rollback, executing:

```text
[← Revert] InvalidBalance()
```

#### 3. Circuit Breaker Activation
Upon catching the unexpected flash loan failure, the `UnstoppableMonitor` contract triggers its emergency defensive routines:
1. It calls `UnstoppableVault::setPause(true)` to freeze the contract's operations.
2. It calls `UnstoppableVault::transferOwnership(deployer)` to offload administrative control back to the original deployer for forensic analysis.

To run the automated validation test locally, execute the following command:

```bash
forge test --match-test test_unstoppable -vvvv
``` 
---

### Recommended Mitigation

#### Architectural Critique of Accumulator-Based State Tracking
Implementing a global state variable (e.g., `uint256 public poolBalance`) that increments on token ingestion is a common design pattern intended to isolate internal ledger metrics from live external balance queries.

However, standard ERC-20 implementations **do not feature push-notification hooks or call triggers** upon executing standard `transfer()` actions. When an external actor invokes `transfer(address(vault), amount)` on the token ledger, the execution context remains isolated inside the ERC-20 storage layout. The `UnstoppableVault` receives no execution signal, meaning a manual state update like `poolBalance += amount` cannot run automatically during a direct transfer bypass. An attacker could still force-feed the raw token balance, leaving your internal `poolBalance` completely desynchronized from actual holdings and breaking any logic requiring absolute alignment between them.

#### The Definitive Production-Grade Solution (Industry Standard)
To permanently resolve this vulnerability, you must remove the strict equality invariant and transition flash loan validation to a **non-strict local balance delta** model.

##### 1. Deprecate Strict Invariant Constraints
Allow raw token surpluses to sit inside the vault without throwing execution errors. Any tokens pushed to the vault via direct transfer will simply behave as un-tracked donations, naturally increasing the underlying asset value per share for standard users without affecting execution stability.

##### 2. Implement Local Snapshot Verification
Store contract balance thresholds within transient stack variables immediately prior to routing execution to the borrower, then validate that the post-execution balance satisfies the initial debt plus fees.

Refactor the inner logic of `flashLoan` to match the following robust, non-strict design pattern:

```solidity
function flashLoan(
    IERC3156FlashBorrower borrower,
    address token,
    uint256 amount,
    bytes calldata data
) public override returns (bool) {
    // ... [Parameter validation checks] ...

    // 1. Capture exact contract asset baseline prior to token distribution
    uint256 balanceBefore = totalAssets();
    uint256 fee = flashFee(token, amount);

    // 2. Route the requested flash capital to the borrower destination
    asset.safeTransfer(address(borrower), amount);

    // 3. Shift execution context control to the external receiver contract
    require(
        borrower.onFlashLoan(msg.sender, token, amount, fee, data) == keccak256("IERC3156FlashBorrower.onFlashLoan"),
        "FlashLoanReceiverRejected"
    );

    // 4. Assert non-strict recovery criteria on final asset balances
    uint256 balanceAfter = totalAssets();
    if (balanceAfter < balanceBefore + fee) {
        revert FeeNotPaid();
    }

    return true;
}
```
`
##### Operational Benefits
* **Immunity to Force-Feeding:** Pushing excess tokens to the contract simply inflates `balanceBefore`. The contract will safely evaluate if `balanceAfter` meets or exceeds that new baseline plus the fee, neutralising the desynchronization attack vector.
* **Gas Efficiency Optimization:** This layout eliminates complex internal calculations (`convertToShares`) from the active transaction path, lowering overall runtime gas consumption.
