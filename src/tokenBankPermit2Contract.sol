// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// 导入 Permit2 的签名转移接口
import "permit2/src/interfaces/ISignatureTransfer.sol";

contract TokenBank {
    IERC20 public token;
    ISignatureTransfer public permit2;

    mapping(address => uint256) public balances;

    modifier AccountVerification(address account) {
        require(account != address(0), "Invalid address");
        _;
    }

    modifier AmountVerification(uint256 amount) {
        require(amount > 0, "Amount must be greater than zero");
        _;
    }

    constructor(address _tokenAddress, address _permit2Address) AccountVerification(_tokenAddress) {
        token = IERC20(_tokenAddress);
        permit2 = ISignatureTransfer(_permit2Address);
    }

    function deposit(uint256 amount) public AmountVerification(amount) {
        require(token.transferFrom(msg.sender, address(this), amount), "TransferFrom failed");
        balances[msg.sender] += amount;
    }

    function depositWithPermit2(
        ISignatureTransfer.PermitTransferFrom calldata permit,
        ISignatureTransfer.SignatureTransferDetails calldata transferDetails,
        bytes calldata signature
    ) external {
        permit2.permitTransferFrom(permit, transferDetails, msg.sender, signature);

        balances[msg.sender] += transferDetails.requestedAmount;
    }

    function withdraw(uint256 amount) public AmountVerification(amount) {
        require(balances[msg.sender] >= amount, "Insufficient balance in TokenBank");
        balances[msg.sender] -= amount;
        require(token.transfer(msg.sender, amount), "Transfer failed");
    }

    function balanceOf(address account) public view AccountVerification(account) returns (uint256) {
        return balances[account];
    }
}