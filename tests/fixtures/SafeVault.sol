pragma solidity ^0.8.19;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract SafeVault is ReentrancyGuard {
    mapping(address => uint) public balances;
    function deposit() public payable { balances[msg.sender]+=msg.value; }
    function withdraw() public nonReentrant {
        uint bal = balances[msg.sender];
        require(bal > 0);
        balances[msg.sender]=0;
        (bool sent,)=msg.sender.call{value: bal}("");
        require(sent);
    }
}
