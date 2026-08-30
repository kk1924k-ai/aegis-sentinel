pragma solidity ^0.7.0;
contract VulnerableBank {
    mapping(address => uint) public balances;
    function deposit() public payable { balances[msg.sender]+=msg.value; }
    function withdraw() public {
        uint bal = balances[msg.sender];
        require(bal > 0, "no funds");
        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed");
        balances[msg.sender] = 0;
    }
    function setFee(uint x) public { fee=x; } uint public fee;
}
