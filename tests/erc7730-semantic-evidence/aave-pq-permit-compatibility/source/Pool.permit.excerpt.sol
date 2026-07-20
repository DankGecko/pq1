function supply(
  address asset,
  uint256 amount,
  address onBehalfOf,
  uint16 referralCode
) public virtual override {
  SupplyLogic.executeSupply(
    _reserves,
    _eModeCategories,
    _usersConfig[onBehalfOf],
    DataTypes.ExecuteSupplyParams({
      user: _msgSender(),
      asset: asset,
      interestRateStrategyAddress: RESERVE_INTEREST_RATE_STRATEGY,
      amount: amount,
      onBehalfOf: onBehalfOf,
      referralCode: referralCode,
      supplierEModeCategory: _usersEModeCategory[onBehalfOf]
    })
  );
}

function supplyWithPermit(
  address asset,
  uint256 amount,
  address onBehalfOf,
  uint16 referralCode,
  uint256 deadline,
  uint8 permitV,
  bytes32 permitR,
  bytes32 permitS
) public virtual override {
  try
    IERC20WithPermit(asset).permit(
      _msgSender(),
      address(this),
      amount,
      deadline,
      permitV,
      permitR,
      permitS
    )
  {} catch {}
  SupplyLogic.executeSupply(
    _reserves,
    _eModeCategories,
    _usersConfig[onBehalfOf],
    DataTypes.ExecuteSupplyParams({
      user: _msgSender(),
      asset: asset,
      interestRateStrategyAddress: RESERVE_INTEREST_RATE_STRATEGY,
      amount: amount,
      onBehalfOf: onBehalfOf,
      referralCode: referralCode,
      supplierEModeCategory: _usersEModeCategory[onBehalfOf]
    })
  );
}

function repay(
  address asset,
  uint256 amount,
  uint256 interestRateMode,
  address onBehalfOf
) public virtual override returns (uint256) {
  return
    BorrowLogic.executeRepay(
      _reserves,
      _reservesList,
      _eModeCategories,
      _usersConfig[onBehalfOf],
      DataTypes.ExecuteRepayParams({
        asset: asset,
        user: _msgSender(),
        interestRateStrategyAddress: RESERVE_INTEREST_RATE_STRATEGY,
        amount: amount,
        interestRateMode: DataTypes.InterestRateMode(interestRateMode),
        onBehalfOf: onBehalfOf,
        useATokens: false,
        oracle: ADDRESSES_PROVIDER.getPriceOracle(),
        userEModeCategory: _usersEModeCategory[onBehalfOf]
      })
    );
}

function repayWithPermit(
  address asset,
  uint256 amount,
  uint256 interestRateMode,
  address onBehalfOf,
  uint256 deadline,
  uint8 permitV,
  bytes32 permitR,
  bytes32 permitS
) public virtual override returns (uint256) {
  try
    IERC20WithPermit(asset).permit(
      _msgSender(),
      address(this),
      amount,
      deadline,
      permitV,
      permitR,
      permitS
    )
  {} catch {}

  {
    DataTypes.ExecuteRepayParams memory params = DataTypes.ExecuteRepayParams({
      asset: asset,
      user: _msgSender(),
      interestRateStrategyAddress: RESERVE_INTEREST_RATE_STRATEGY,
      amount: amount,
      interestRateMode: DataTypes.InterestRateMode(interestRateMode),
      onBehalfOf: onBehalfOf,
      useATokens: false,
      oracle: ADDRESSES_PROVIDER.getPriceOracle(),
      userEModeCategory: _usersEModeCategory[onBehalfOf]
    });
    return
      BorrowLogic.executeRepay(
        _reserves,
        _reservesList,
        _eModeCategories,
        _usersConfig[onBehalfOf],
        params
      );
  }
}
