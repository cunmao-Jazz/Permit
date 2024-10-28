// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import "forge-std/console.sol"; // 确保导入 console.sol
import "../src/tokenBankPermit2Contract.sol";
import "permit2/src/Permit2.sol";
import "../src/ERC20.sol";

contract TokenBankTest is Test {
    TokenBank public tokenBank;
    Permit2 public permit2;
    BaseERC20 public token;

    uint256 whitelistPrivateKey = 0xA11CE;

    address public user = vm.addr(whitelistPrivateKey);

    // 定义常量
    bytes32 constant PERMIT_TRANSFER_FROM_TYPEHASH = keccak256(
        "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"
    );

    bytes32 constant TOKEN_PERMISSIONS_TYPEHASH = keccak256(
        "TokenPermissions(address token,uint256 amount)"
    );


    function setUp() public {
        // 部署 ERC20 代币
        token = new BaseERC20();

        // 给用户分配一些代币
        token.transfer(user, 1000 * 1e18);

        // 部署 Permit2 合约
        permit2 = new Permit2();

        // 部署 TokenBank 合约
        tokenBank = new TokenBank(address(token), address(permit2));

        // 用户批准 Permit2 合约花费其代币（如果需要）
        vm.prank(user);
        token.approve(address(permit2), type(uint256).max);
    }

    function testDepositWithPermit2() public {
        uint256 amount = 100 * 1e18;
        uint256 nonce = 0;
        uint256 deadline = block.timestamp + 1 hours;

        // 构造 PermitTransferFrom 结构
        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({
                token: address(token),
                amount: amount
            }),
            nonce: nonce,
            deadline: deadline
        });

        // 构造 SignatureTransferDetails 结构
        ISignatureTransfer.SignatureTransferDetails memory transferDetails = ISignatureTransfer.SignatureTransferDetails({
            to: address(tokenBank),
            requestedAmount: amount
        });


        bytes32 tokenPermissionsHash = keccak256(
            abi.encode(
                TOKEN_PERMISSIONS_TYPEHASH,
                permit.permitted.token,
                permit.permitted.amount
            )
        );

        bytes32 structHash = keccak256(
            abi.encode(
                PERMIT_TRANSFER_FROM_TYPEHASH,
                tokenPermissionsHash,
                address(tokenBank), 
                permit.nonce,
                permit.deadline
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", permit2.DOMAIN_SEPARATOR(), structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(whitelistPrivateKey, digest);

        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        tokenBank.depositWithPermit2(permit, transferDetails, signature);

        // 验证余额更新
        uint256 bankBalance = tokenBank.balanceOf(user);
        assertEq(bankBalance, amount);

        // 验证 TokenBank 合约持有的代币数量
        uint256 bankTokenBalance = token.balanceOf(address(tokenBank));
        assertEq(bankTokenBalance, amount);

        // 验证用户代币余额减少
        uint256 userTokenBalance = token.balanceOf(user);
        assertEq(userTokenBalance, 900 * 1e18);
    }
}