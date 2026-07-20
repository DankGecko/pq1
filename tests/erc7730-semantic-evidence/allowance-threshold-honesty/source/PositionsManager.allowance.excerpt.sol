/*
 * Normalized-LF, non-contiguous excerpts from the verified FlyingTulip
 * PositionsManager source. This is an evidence excerpt, not a compilable unit.
 */

contract PositionsManager is
    IPMViews,
    IPositionsManager,
    Initializable,
    ReentrancyGuardTransientUpgradeable,
    UUPSUpgradeable
{

    function _consumeEngineDebitAllowance(address user, address asset, uint256 amt) internal {
        uint256 allowance = engineDebitAllowance[user][msg.sender][asset];
        if (allowance == type(uint256).max) return;
        if (allowance < amt) revert ftPositionManagerInsufficientEngineDebitAllowance();
        unchecked {
            engineDebitAllowance[user][msg.sender][asset] = allowance - amt;
        }
    }

    function _approveBorrow(
        address user,
        address delegate,
        address asset,
        uint256 borrowAllowance_
    )
        internal
    {
        borrowAllowance[user][delegate][asset] = borrowAllowance_;
        emit BorrowDelegateApprovalSet(user, delegate, asset, borrowAllowance_);
    }

    function approveBorrow(address delegate, address asset, uint256 borrowAllowance_) external {
        approveBorrow(msg.sender, delegate, asset, borrowAllowance_);
    }

    function _approveEngine(
        address user,
        address engine,
        address asset,
        uint256 debitAllowance
    )
        internal
    {
        engineDebitAllowance[user][engine][asset] = debitAllowance;
        emit EngineApprovalSet(user, engine, asset, debitAllowance);
    }

    function approveEngine(address engine, address asset, uint256 debitAllowance) external {
        approveEngine(msg.sender, engine, asset, debitAllowance);
    }

        uint256 allowance = borrowAllowance[user][msg.sender][borrowAsset];
        if (allowance < borrowAmount) revert ftPositionManagerInsufficientBorrowAllowance();
        unchecked {
            borrowAllowance[user][msg.sender][borrowAsset] = allowance - borrowAmount;
        }
