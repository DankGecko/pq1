function withdrawETH(address, uint256 amount, address to) external override {
  IAToken aWETH = IAToken(POOL.getReserveAToken(address(WETH)));
  uint256 userBalance = aWETH.balanceOf(msg.sender);
  uint256 amountToWithdraw = amount;

  // if amount is equal to type(uint256).max, the user wants to redeem everything
  if (amount == type(uint256).max) {
    amountToWithdraw = userBalance;
  }
  // aWETH is trusted, disabling warning
  // forge-lint: disable-next-line(erc20-unchecked-transfer)
  aWETH.transferFrom(msg.sender, address(this), amountToWithdraw);
  POOL.withdraw(address(WETH), amountToWithdraw, address(this));
  WETH.withdraw(amountToWithdraw);
  _safeTransferETH(to, amountToWithdraw);
}

function withdrawETHWithPermit(
  address,
  uint256 amount,
  address to,
  uint256 deadline,
  uint8 permitV,
  bytes32 permitR,
  bytes32 permitS
) external override {
  IAToken aWETH = IAToken(POOL.getReserveAToken(address(WETH)));
  uint256 userBalance = aWETH.balanceOf(msg.sender);
  uint256 amountToWithdraw = amount;

  // if amount is equal to type(uint256).max, the user wants to redeem everything
  if (amount == type(uint256).max) {
    amountToWithdraw = userBalance;
  }
  // permit `amount` rather than `amountToWithdraw` to make it easier for front-ends and integrators
  try
    aWETH.permit(msg.sender, address(this), amount, deadline, permitV, permitR, permitS)
  {} catch {}
  // aWETH is trusted, disabling warning
  // forge-lint: disable-next-line(erc20-unchecked-transfer)
  aWETH.transferFrom(msg.sender, address(this), amountToWithdraw);
  POOL.withdraw(address(WETH), amountToWithdraw, address(this));
  WETH.withdraw(amountToWithdraw);
  _safeTransferETH(to, amountToWithdraw);
}
