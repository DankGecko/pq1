// SPDX-License-Identifier: UNLICENSED
// Copyright (c) 2025 Flying Tulip Inc. All rights reserved.
pragma solidity 0.8.30;

import {Initializable} from "openzeppelin-contracts/contracts/proxy/utils/Initializable.sol";
import {
    Ownable2StepUpgradeable
} from "openzeppelin-contracts-upgradeable/contracts/access/Ownable2StepUpgradeable.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {
    IERC20Metadata
} from "openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {
    IERC20Permit
} from "openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {
    PausableUpgradeable
} from "openzeppelin-contracts-upgradeable/contracts/utils/PausableUpgradeable.sol";
import {
    ReentrancyGuardTransient
} from "openzeppelin-contracts/contracts/utils/ReentrancyGuardTransient.sol";
import {
    UUPSUpgradeable
} from "openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";
import {Math} from "openzeppelin-contracts/contracts/utils/math/Math.sol";
import {
    EIP712Upgradeable
} from "openzeppelin-contracts-upgradeable/contracts/utils/cryptography/EIP712Upgradeable.sol";

import {IftYieldWrapperV2} from "./interfaces/IftYieldWrapperV2.sol";
import {IFtUSDCore} from "./interfaces/IFtUSDCore.sol";
import {IFtUSD} from "./interfaces/IFtUSD.sol";
import {ISessionManager} from "./interfaces/ISessionManager.sol";
import {IOracleUSD} from "@ft-common/interfaces/IOracleUSD.sol";
import {IRelayerAuth} from "./interfaces/IRelayerAuth.sol";
import {IMintPayoutRouter} from "./interfaces/IMintPayoutRouter.sol";

/// @title MintAndRedeem
/// @notice Oracle-priced minting and redemption engine for ftUSD against supported collateral tokens.
/// @dev
/// - `ftUSD` is treated as USD with 6 decimals.
/// - Collateral is deposited as principal into a per-collateral `ftYieldWrapper` (single-asset wrapper).
/// - Mint/redeem amounts are computed using `oracle.priceUSD(collateral)` (assumed non-stale or revert).
/// - Exposes mint/redeem plus session-key (delegated) flows for integrators.
contract MintAndRedeem is
    Initializable,
    PausableUpgradeable,
    Ownable2StepUpgradeable,
    UUPSUpgradeable,
    EIP712Upgradeable,
    ReentrancyGuardTransient
{
    using SafeERC20 for IERC20;

    uint256 internal constant FTUSD_SCALE = 1e6;
    uint256 internal constant USD_WAD = 1e18;
    uint256 internal constant BPS = 10_000;

    IRelayerAuth public relayerAuth;

    /// @notice Payout router for rate-limited ftUSD distribution
    IMintPayoutRouter public payoutRouter;
    bytes32 internal constant _SESSION_MINT_DATAHASH_TYPEHASH = keccak256(
        "SessionMint(address collateralToken,uint256 collateralAmount,bytes32 ref,uint256 txDeadline,uint256 minFtUSDOut)"
    );
    bytes32 internal constant _SESSION_REDEEM_DATAHASH_TYPEHASH = keccak256(
        "SessionRedeem(address collateralToken,uint256 ftUSDAmount,bytes32 ref,uint256 txDeadline,uint256 minCollateralOut)"
    );
    bytes32 internal constant _SESSION_MINT_EXACT_DATAHASH_TYPEHASH = keccak256(
        "SessionMintExact(address collateralToken,uint256 ftUSDAmountOut,bytes32 ref,uint256 txDeadline,uint256 maxCollateralIn)"
    );
    bytes32 internal constant _SESSION_REDEEM_EXACT_DATAHASH_TYPEHASH = keccak256(
        "SessionRedeemExact(address collateralToken,uint256 collateralAmountOut,bytes32 ref,uint256 txDeadline,uint256 maxFtUSDIn)"
    );

    IFtUSD internal immutable ftUSD;
    IOracleUSD internal immutable oracle;
    IFtUSDCore internal immutable core;

    address public pauser;

    struct CollateralInfo {
        IftYieldWrapperV2 yieldWrapper;
        uint8 decimals;
        bool enabled;
        uint16 mintFeeBps;
        uint16 redeemFeeBps;
        uint256 maxValueFtUSD;
        uint256 mintPriceHardcapWad;
        uint256 totalIn;
        uint256 totalOut;
        uint256 totalFtUSDBurned;
        uint256 totalFtUSDMinted;
    }

    struct MintExactWithSessionParams {
        address collateralToken;
        uint256 ftUSDAmountOut;
        bytes32 ref;
        uint256 txDeadline;
        uint256 maxCollateralIn;
    }

    struct RedeemExecutionParams {
        address collateralToken;
        address payer;
        address recipient;
        uint256 ftUSDAmount;
        uint256 burnFtUSDAmount;
        uint256 feeFtUSDAmount;
        uint256 collateralAmount;
        bytes32 ref;
        address executor;
        uint256 relayerFeeCollateralAmount;
    }

    mapping(address collateral => CollateralInfo) internal _collaterals;
    address[] internal _collateralList;

    // yield wrappers are non-recoverable (they represent principal shares)
    mapping(address wrapper => bool) internal isYieldWrapper;

    uint256 internal totalFtUSDMinted;
    uint256 internal totalFtUSDBurned;
    uint256 internal claimableFeeAmount;

    ISessionManager internal sessionManager;

    /// @notice Parameters for EIP-2612 permit signatures.
    /// @dev Used to optionally set token allowance in a single transaction.
    ///      If deadline is 0, the permit is skipped (assumes allowance already exists).
    struct PermitParams {
        uint256 value;
        uint256 deadline;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    // ===== Events =====
    event PauserChanged(address indexed newPauser);
    event SessionManagerUpdated(address indexed newSessionManager);

    event CollateralAdded(
        address indexed collateralToken, address indexed yieldWrapper, uint8 collateralDecimals
    );
    event CollateralStatusChanged(address indexed collateralToken, bool enabled);
    event CollateralCapUpdated(address indexed collateralToken, uint256 capValueFtUSD);
    event FeeBpsUpdated(address indexed collateralToken, uint16 feeBps, bool isMintFee);
    event FeesSwept(address indexed to, uint256 amount);
    event MintPriceHardcapUpdated(address indexed collateralToken, uint256 hardcapPriceWad);

    event Minted(
        address caller,
        address indexed from,
        address indexed to,
        bytes32 ref,
        address indexed collateralToken,
        uint256 collateralAmount,
        uint256 ftUSDAmount,
        uint256 feeFtUSDAmount,
        uint256 wrapperPrincipalAfter
    );

    event Redeemed(
        address caller,
        address indexed from,
        address indexed to,
        bytes32 ref,
        address indexed collateralToken,
        uint256 ftUSDAmount,
        uint256 feeFtUSDAmount,
        uint256 collateralAmount,
        uint256 wrapperPrincipalAfter
    );

    event ExcessCollateralSwept(
        address indexed caller,
        address indexed to,
        address indexed collateralToken,
        uint256 collateralAmount,
        uint256 wrapperPrincipalAfter,
        uint256 outstandingUSDAfter
    );

    event Recovered(address indexed token, address indexed to, uint256 amount);
    event RelayerFeePaid(
        address indexed payer,
        address indexed executor,
        address indexed token,
        uint256 amount,
        bytes32 ref
    );
    event RelayerAuthUpdated(address indexed newRelayerAuth);
    event MintQueued(address indexed recipient, uint256 ftUSDAmount, uint256 queueId);
    event PayoutRouterUpdated(address indexed newRouter);

    // ===== Errors =====
    error ZeroAddress();
    error NotContract(address account);
    error ZeroAmount();
    error RecipientMustBeSender(address sender, address recipient);
    error NotPauser(address caller);
    error AmountTooSmall();
    error TokenNotRecoverable();
    error UnsupportedCollateral(address collateral);
    error NotRelayer(address sender);
    error CollateralAlreadyAdded(address collateral);
    error CollateralConfigRequired();
    error InvalidYieldWrapper(address wrapper);
    error InvalidFeeBps(uint256 feeBps);
    error InsufficientExcessUSD();
    error InsufficientSweepableCollateral();
    error CollateralCapExceeded(address collateralToken);
    error InvalidCollateralDecimals();
    error TransactionExpired();
    error SlippageExceeded(uint256 amountOut, uint256 minAmountOut);
    error InsufficientClaimableFees();
    error SessionManagerNotSet();
    error SessionDataHashMismatch(bytes32 expected, bytes32 provided);
    error RelayerFeeTooHigh(uint256 feeAmount, uint256 maxFeeAmount);

    modifier onlyPauser() {
        _onlyPauser();
        _;
    }

    function _onlyPauser() internal view {
        if (msg.sender != pauser) revert NotPauser(msg.sender);
    }

    constructor(address core_, address ftUSD_, address oracle_) {
        if (core_ == address(0) || ftUSD_ == address(0) || oracle_ == address(0)) {
            revert ZeroAddress();
        }
        core = IFtUSDCore(core_);
        ftUSD = IFtUSD(ftUSD_);
        oracle = IOracleUSD(oracle_);
        _disableInitializers();
    }

    /// @notice Initializes the MintAndRedeem contract.
    /// @dev Sets up pausable, ownable, and EIP712 functionality. Grants max approval to core for ftUSD burns.
    /// @param initialOwner The address that will own this contract (can manage collaterals, fees, etc.).
    /// @param initialPauser The address authorized to pause/unpause minting and redemption.
    function initialize(address initialOwner, address initialPauser) public initializer {
        if (initialOwner == address(0) || initialPauser == address(0)) revert ZeroAddress();

        __Pausable_init();
        __Ownable_init(initialOwner);
        __Ownable2Step_init();
        __EIP712_init("MintAndRedeem", "1");

        pauser = initialPauser;

        // Allow the core to pull ftUSD from this engine for burns (used on redemption).
        IERC20(address(ftUSD)).forceApprove(address(core), type(uint256).max);

        emit PauserChanged(initialPauser);
    }

    // ===== Admin =====

    /// @notice Registers a new collateral token by associating it with a yield wrapper and initial config.
    /// @dev The collateral token is derived from the wrapper's `token()` method. Reverts if wrapper
    ///      is already registered or if the collateral decimals exceed 18.
    ///      To avoid a newly-added collateral being immediately usable with all-zero defaults (0 fees,
    ///      no cap, no hardcap), this function requires at least one non-zero config value.
    /// @param yieldWrapper_ The ftYieldWrapper contract address for the collateral.
    /// @param mintFeeBps_ Mint fee in bps (< 10,000).
    /// @param redeemFeeBps_ Redeem fee in bps (< 10,000).
    /// @param capValueFtUSD_ Collateral cap in ftUSD units (6 decimals). Use 0 for unlimited.
    /// @param hardcapPriceWad_ Mint price hardcap in USD WAD (1e18). Use 0 to disable.
    function addCollateral(
        address yieldWrapper_,
        uint16 mintFeeBps_,
        uint16 redeemFeeBps_,
        uint256 capValueFtUSD_,
        uint256 hardcapPriceWad_
    )
        external
        onlyOwner
    {
        if (yieldWrapper_ == address(0)) revert ZeroAddress();
        if (isYieldWrapper[yieldWrapper_]) revert InvalidYieldWrapper(yieldWrapper_);
        if (mintFeeBps_ >= BPS) revert InvalidFeeBps(mintFeeBps_);
        if (redeemFeeBps_ >= BPS) revert InvalidFeeBps(redeemFeeBps_);
        if (mintFeeBps_ == 0 && redeemFeeBps_ == 0 && capValueFtUSD_ == 0 && hardcapPriceWad_ == 0)
        {
            revert CollateralConfigRequired();
        }

        IftYieldWrapperV2 wrapper = IftYieldWrapperV2(yieldWrapper_);
        address collateralToken = wrapper.token();
        if (collateralToken == address(0)) revert InvalidYieldWrapper(yieldWrapper_);

        CollateralInfo storage existing = _collaterals[collateralToken];
        if (address(existing.yieldWrapper) != address(0)) {
            revert CollateralAlreadyAdded(collateralToken);
        }

        uint8 decimals = IERC20Metadata(collateralToken).decimals();
        if (decimals > 18) revert InvalidCollateralDecimals();
        _collaterals[collateralToken] = CollateralInfo({
            yieldWrapper: wrapper,
            decimals: decimals,
            enabled: true,
            mintFeeBps: mintFeeBps_,
            redeemFeeBps: redeemFeeBps_,
            maxValueFtUSD: capValueFtUSD_,
            mintPriceHardcapWad: hardcapPriceWad_,
            totalIn: 0,
            totalOut: 0,
            totalFtUSDBurned: 0,
            totalFtUSDMinted: 0
        });
        IERC20(address(collateralToken)).forceApprove(address(yieldWrapper_), type(uint256).max);
        _collateralList.push(collateralToken);
        isYieldWrapper[yieldWrapper_] = true;

        emit CollateralAdded(collateralToken, yieldWrapper_, decimals);
        emit FeeBpsUpdated(collateralToken, mintFeeBps_, true);
        emit FeeBpsUpdated(collateralToken, redeemFeeBps_, false);
        emit CollateralCapUpdated(collateralToken, capValueFtUSD_);
        emit MintPriceHardcapUpdated(collateralToken, hardcapPriceWad_);
    }

    /// @notice Enables or disables a collateral token for minting and redemption.
    /// @param collateralToken The collateral token address to update.
    /// @param enabled Whether the collateral should be enabled (true) or disabled (false).
    function setCollateralEnabled(address collateralToken, bool enabled) external onlyOwner {
        CollateralInfo storage cinfo = _getCollateral(collateralToken);
        cinfo.enabled = enabled;
        emit CollateralStatusChanged(collateralToken, enabled);
    }

    /// @notice Sets the mint fee for a specific collateral token.
    /// @dev Fee is charged in ftUSD and deducted from the gross mint output.
    /// @param collateralToken The collateral token address to configure.
    /// @param feeBps The fee in basis points (must be < 10000).
    function setMintFee(address collateralToken, uint16 feeBps) external onlyOwner {
        if (feeBps >= BPS) revert InvalidFeeBps(feeBps);
        CollateralInfo storage cinfo = _getCollateral(collateralToken);
        cinfo.mintFeeBps = feeBps;
        emit FeeBpsUpdated(collateralToken, feeBps, true);
    }

    /// @notice Sets the redeem fee for a specific collateral token.
    /// @dev Fee is charged in ftUSD and deducted from the input before conversion to collateral.
    /// @param collateralToken The collateral token address to configure.
    /// @param feeBps The fee in basis points (must be < 10000).
    function setRedeemFee(address collateralToken, uint16 feeBps) external onlyOwner {
        if (feeBps >= BPS) revert InvalidFeeBps(feeBps);
        CollateralInfo storage cinfo = _getCollateral(collateralToken);
        cinfo.redeemFeeBps = feeBps;
        emit FeeBpsUpdated(collateralToken, feeBps, false);
    }

    /// @notice Sets a per-collateral hardcap on the oracle USD price used for minting conversions.
    /// @dev Useful for stablecoin collateral: setting to `1e18` ensures the engine never mints using
    ///      a price above $1 (e.g. when a stable trades at a premium or oracle spikes upward).
    ///      Set to 0 to disable the hardcap and use the raw oracle price.
    /// @param collateralToken The collateral token address to configure.
    /// @param hardcapPriceWad The hardcap price in USD WAD (1e18). Use 0 to disable.
    function setMintPriceHardcapWad(
        address collateralToken,
        uint256 hardcapPriceWad
    )
        external
        onlyOwner
    {
        CollateralInfo storage cinfo = _getCollateral(collateralToken);
        cinfo.mintPriceHardcapWad = hardcapPriceWad;
        emit MintPriceHardcapUpdated(collateralToken, hardcapPriceWad);
    }

    /// @notice Sets the maximum USD value (in ftUSD units) of a collateral that can be held.
    /// @dev A cap of 0 means no limit. Cap is enforced on mint operations using spot oracle pricing.
    ///      Temporary oracle drawdowns can therefore admit more token units under a fixed ftUSD cap.
    /// @param collateralToken The collateral token address to configure.
    /// @param capValueFtUSD The maximum value in ftUSD units (6 decimals). Use 0 for unlimited.
    function setCollateralCapFtUSD(
        address collateralToken,
        uint256 capValueFtUSD
    )
        external
        onlyOwner
    {
        CollateralInfo storage cinfo = _getCollateral(collateralToken);
        cinfo.maxValueFtUSD = capValueFtUSD;
        emit CollateralCapUpdated(collateralToken, capValueFtUSD);
    }

    /// @notice Updates the address authorized to pause and unpause the contract.
    /// @param newPauser The new pauser address. Cannot be the zero address.
    function updatePauser(address newPauser) external onlyOwner {
        if (newPauser == address(0)) revert ZeroAddress();
        pauser = newPauser;
        emit PauserChanged(newPauser);
    }

    function setSessionManager(address newSessionManager) external onlyOwner {
        if (newSessionManager == address(0)) revert ZeroAddress();
        sessionManager = ISessionManager(newSessionManager);
        emit SessionManagerUpdated(newSessionManager);
    }

    function setRelayerAuth(address newRelayerAuth) external onlyOwner {
        if (newRelayerAuth == address(0)) revert ZeroAddress();
        relayerAuth = IRelayerAuth(newRelayerAuth);
        emit RelayerAuthUpdated(newRelayerAuth);
    }

    /// @notice Sets the payout router for rate-limited ftUSD distribution
    /// @param router The payout router address (use address(0) to disable rate limiting)
    function setPayoutRouter(address router) external onlyOwner {
        if (router != address(0) && router.code.length == 0) revert NotContract(router);
        payoutRouter = IMintPayoutRouter(router);
        emit PayoutRouterUpdated(router);
    }

    modifier isRelayer() {
        _isRelayer();
        _;
    }

    function _isRelayer() internal view {
        if (!relayerAuth.isRelayer(msg.sender)) revert NotRelayer(msg.sender);
    }

    /// @notice Pauses all minting and redemption operations.
    /// @dev Only callable by the pauser address.
    function pause() external onlyPauser {
        _pause();
    }

    /// @notice Unpauses minting and redemption operations.
    /// @dev Only callable by the pauser address.
    function unpause() external onlyPauser {
        _unpause();
    }

    // ===== Views =====

    /// @notice Get protocol accounting info
    function getAccountingInfo() external view returns (uint256, uint256, uint256) {
        return (totalFtUSDMinted, totalFtUSDBurned, claimableFeeAmount);
    }

    /// @notice Returns the number of registered collateral tokens.
    /// @return The count of collateral tokens added to this engine.
    function collateralCount() external view returns (uint256) {
        return _collateralList.length;
    }

    /// @notice Returns the collateral token address at a specific index.
    /// @param index The index in the collateral list (0-based).
    /// @return The collateral token address at the given index.
    function collateralAt(uint256 index) external view returns (address) {
        return _collateralList[index];
    }

    /// @notice Returns the configuration for a registered collateral token.
    /// @param collateralToken The collateral token address to query.
    /// @return The CollateralInfo struct containing wrapper, decimals, fees, cap, and flow totals.
    function collateralInfo(address collateralToken) external view returns (CollateralInfo memory) {
        CollateralInfo storage cinfo = _getCollateral(collateralToken);
        return cinfo;
    }

    /// @notice Previews the ftUSD amount that would be received for a given collateral deposit.
    /// @dev Accounts for the current mint fee. Reverts if collateral is disabled or amount is zero.
    /// @param collateralToken The collateral token to deposit.
    /// @param collateralAmount The amount of collateral tokens to deposit.
    /// @return ftUSDAmount The net ftUSD amount after fees that would be minted.
    function previewMint(
        address collateralToken,
        uint256 collateralAmount
    )
        external
        view
        returns (uint256 ftUSDAmount)
    {
        if (collateralAmount == 0) revert ZeroAmount();
        CollateralInfo storage cinfo = _getCollateralEnabled(collateralToken);
        (ftUSDAmount,) = _collateralToFtUSDWithFee(
            collateralToken, collateralAmount, cinfo.decimals, cinfo.mintFeeBps
        );
    }

    /// @notice Previews the collateral amount that would be received for a given ftUSD redemption.
    /// @dev Accounts for the current redeem fee. Reverts if collateral is disabled or amount is zero.
    /// @param collateralToken The collateral token to receive.
    /// @param ftUSDAmount The amount of ftUSD to redeem.
    /// @return collateralAmount The collateral amount that would be returned after fees.
    function previewRedeem(
        address collateralToken,
        uint256 ftUSDAmount
    )
        external
        view
        returns (uint256 collateralAmount)
    {
        if (ftUSDAmount == 0) revert ZeroAmount();
        CollateralInfo storage cinfo = _getCollateralEnabled(collateralToken);
        (,, collateralAmount) = _ftUSDToCollateralWithFee(
            collateralToken,
            ftUSDAmount,
            cinfo.decimals,
            cinfo.redeemFeeBps,
            cinfo.totalIn,
            cinfo.totalOut,
            cinfo.totalFtUSDBurned,
            cinfo.totalFtUSDMinted
        );
    }

    function previewMintExact(
        address collateralToken,
        uint256 ftUSDAmount
    )
        external
        view
        returns (uint256 collateralAmount)
    {
        if (ftUSDAmount == 0) revert ZeroAmount();
        CollateralInfo storage cinfo = _getCollateralEnabled(collateralToken);
        (,, collateralAmount) = _calculateMintExactAmounts(
            collateralToken, ftUSDAmount, cinfo.decimals, cinfo.mintFeeBps
        );
    }

    function previewRedeemExact(
        address collateralToken,
        uint256 collateralAmount
    )
        external
        view
        returns (uint256 ftUSDAmount)
    {
        if (collateralAmount == 0) revert ZeroAmount();
        CollateralInfo storage cinfo = _getCollateralEnabled(collateralToken);
        (, ftUSDAmount,) = _calculateRedeemExactAmounts(
            collateralToken,
            collateralAmount,
            cinfo.decimals,
            cinfo.redeemFeeBps,
            cinfo.totalIn,
            cinfo.totalOut,
            cinfo.totalFtUSDBurned,
            cinfo.totalFtUSDMinted
        );
    }

    /// @notice Returns the total collateral held for a specific token (wrapper shares + idle balance).
    /// @param collateralToken The collateral token address to query.
    /// @return The total collateral amount held by this engine.
    function collateralAssets(address collateralToken) external view returns (uint256) {
        CollateralInfo storage cinfo = _getCollateral(collateralToken);
        return cinfo.yieldWrapper.balanceOf(address(this))
            + IERC20(collateralToken).balanceOf(address(this));
    }

    /// @notice Returns the total system assets valued in ftUSD units (6 decimals).
    /// @dev Only includes enabled collaterals. Uses mint pricing (oracle capped by `mintPriceHardcapWad`)
    ///      and floor rounding for conservative reserve/sweep accounting.
    /// @return totalFtUSDValue The aggregate USD value of all collateral held by this engine.
    function assetsUSD() public view returns (uint256 totalFtUSDValue) {
        uint256 len = _collateralList.length;
        for (uint256 i = 0; i < len; i++) {
            address collateralToken = _collateralList[i];
            CollateralInfo storage cinfo = _collaterals[collateralToken];
            if (!cinfo.enabled) continue;

            uint256 assets = cinfo.yieldWrapper.balanceOf(address(this))
                + IERC20(collateralToken).balanceOf(address(this));

            if (assets == 0) continue;

            totalFtUSDValue += _collateralToFtUSDMint(
                collateralToken, assets, cinfo.decimals, Math.Rounding.Floor
            );
        }
    }

    // ===== Minting (exact input) =====

    /// @notice Mints ftUSD by depositing collateral, sending to the caller.
    /// @dev Convenience wrapper around `mintTo` with `to` set to `msg.sender` and no ref.
    /// @param collateralToken The collateral token to deposit.
    /// @param collateralAmount The amount of collateral to deposit.
    /// @param txDeadline Unix timestamp after which the transaction reverts. Use 0 for no deadline.
    /// @param minFtUSDOut Minimum ftUSD to receive (slippage protection).
    /// @return ftUSDAmount The net ftUSD amount minted to the caller after fees.
    function mint(
        address collateralToken,
        uint256 collateralAmount,
        uint256 txDeadline,
        uint256 minFtUSDOut
    )
        external
        returns (uint256 ftUSDAmount)
    {
        return
            mintTo(
                collateralToken, msg.sender, collateralAmount, bytes32(0), txDeadline, minFtUSDOut
            );
    }

    /// @notice Mints ftUSD by depositing collateral, sending to a specified recipient.
    /// @dev Collateral is deposited into the yield wrapper. Fee-on-transfer tokens are not supported.
    /// @param collateralToken The collateral token to deposit.
    /// @param to The recipient address for the minted ftUSD.
    /// @param collateralAmount The amount of collateral to deposit.
    /// @param ref An optional reference identifier for tracking/integrations.
    /// @param txDeadline Unix timestamp after which the transaction reverts. Use 0 for no deadline.
    /// @param minFtUSDOut Minimum ftUSD to receive (slippage protection).
    /// @return ftUSDAmount The net ftUSD amount minted to the recipient after fees.
    function mintTo(
        address collateralToken,
        address to,
        uint256 collateralAmount,
        bytes32 ref,
        uint256 txDeadline,
        uint256 minFtUSDOut
    )
        public
        nonReentrant
        whenNotPaused
        returns (uint256 ftUSDAmount)
    {
        _enforceDeadline(txDeadline);
        if (to == address(0)) revert ZeroAddress();
        if (collateralAmount == 0) revert ZeroAmount();

        CollateralInfo storage cinfo = _getCollateralEnabled(collateralToken);

        uint256 feeFtUSDAmount;
        (ftUSDAmount, feeFtUSDAmount) = _collateralToFtUSDWithFee(
            collateralToken, collateralAmount, cinfo.decimals, cinfo.mintFeeBps
        );
        if (ftUSDAmount < minFtUSDOut) revert SlippageExceeded(ftUSDAmount, minFtUSDOut);
        uint256 grossFtUSDAmount = ftUSDAmount + feeFtUSDAmount;

        _executeMintWithRelayerFee(
            collateralToken,
            cinfo,
            msg.sender,
            to,
            collateralAmount,
            grossFtUSDAmount,
            feeFtUSDAmount,
            ref,
            msg.sender,
            0
        );
    }

    // ===== Session-key minting (exact input) =====

    /// @notice Mints ftUSD using a delegated session key and an optional EIP-2612 permit for collateral.
    /// @dev Pays the relayer fee (if any) out of the minted ftUSD output.
    /// @dev If `permit.deadline != 0`, applies the permit for `collateralToken` from the session owner to this engine.
    /// @param collateralToken The collateral token to deposit.
    /// @param collateralAmount Amount of collateral to deposit.
    /// @param ref Optional reference identifier.
    /// @param txDeadline Unix timestamp after which the transaction reverts. Use 0 for no deadline.
    /// @param minFtUSDOut Minimum ftUSD to receive (net of protocol + relayer fees).
    /// @param sessionCall Delegate-signed session call intent.
    /// @param delegateSignature Signature from the delegated session key over `sessionCall`.
    function mintWithSessionAndPermit(
        address collateralToken,
        uint256 collateralAmount,
        bytes32 ref,
        uint256 txDeadline,
        uint256 minFtUSDOut,
        PermitParams calldata permit,
        ISessionManager.SessionCall calldata sessionCall,
        bytes calldata delegateSignature
    )
        external
        nonReentrant
        isRelayer
        whenNotPaused
        returns (uint256 ftUSDAmountOut)
    {
        _enforceDeadline(txDeadline);
        if (collateralAmount == 0) revert ZeroAmount();

        bytes32 expectedHash = keccak256(
            abi.encode(
                _SESSION_MINT_DATAHASH_TYPEHASH,
                collateralToken,
                collateralAmount,
                ref,
                txDeadline,
                minFtUSDOut
            )
        );
        (address payer, uint16 maxFeeBps) = _validateSessionCall(
            expectedHash, collateralToken, collateralAmount, sessionCall, delegateSignature
        );

        _applyPermitIfProvided(collateralToken, payer, permit);

        CollateralInfo storage cinfo = _getCollateralEnabled(collateralToken);

        uint256 protocolFeeFtUSDAmount;
        uint256 protocolNetFtUSDAmount;
        (protocolNetFtUSDAmount, protocolFeeFtUSDAmount) = _collateralToFtUSDWithFee(
            collateralToken, collateralAmount, cinfo.decimals, cinfo.mintFeeBps
        );

        _enforceRelayerFee(protocolNetFtUSDAmount, maxFeeBps, sessionCall.feeAmount);

        ftUSDAmountOut = protocolNetFtUSDAmount - sessionCall.feeAmount;
        if (ftUSDAmountOut < minFtUSDOut) revert SlippageExceeded(ftUSDAmountOut, minFtUSDOut);

        uint256 grossFtUSDAmount = protocolNetFtUSDAmount + protocolFeeFtUSDAmount;
        _executeMintWithRelayerFee(
            collateralToken,
            cinfo,
            payer,
            payer,
            collateralAmount,
            grossFtUSDAmount,
            protocolFeeFtUSDAmount,
            ref,
            sessionCall.executor,
            sessionCall.feeAmount
        );
    }

    // ===== Session-key minting (exact output) =====

    /// @notice Mints an exact ftUSD amount (net to the owner) using a delegated session key.
    /// @dev Pays the relayer fee (if any) out of the minted ftUSD output.
    ///      The signed session call binds `ftUSDAmountOut` and `maxCollateralIn`, allowing price movement
    ///      within the slippage tolerance.
    function mintExactWithSessionAndPermit(
        address collateralToken,
        uint256 ftUSDAmountOut,
        bytes32 ref,
        uint256 txDeadline,
        uint256 maxCollateralIn,
        PermitParams calldata permit,
        ISessionManager.SessionCall calldata sessionCall,
        bytes calldata delegateSignature
    )
        external
        nonReentrant
        isRelayer
        whenNotPaused
        returns (uint256 collateralAmountIn)
    {
        MintExactWithSessionParams memory p = MintExactWithSessionParams({
            collateralToken: collateralToken,
            ftUSDAmountOut: ftUSDAmountOut,
            ref: ref,
            txDeadline: txDeadline,
            maxCollateralIn: maxCollateralIn
        });

        return _mintExactWithSessionAndPermit(p, permit, sessionCall, delegateSignature);
    }

    function _mintExactWithSessionAndPermit(
        MintExactWithSessionParams memory p,
        PermitParams calldata permit,
        ISessionManager.SessionCall calldata sessionCall,
        bytes calldata delegateSignature
    )
        internal
        returns (uint256 collateralAmountIn)
    {
        _enforceDeadline(p.txDeadline);
        if (p.ftUSDAmountOut == 0) revert ZeroAmount();

        bytes32 expectedHash = keccak256(
            abi.encode(
                _SESSION_MINT_EXACT_DATAHASH_TYPEHASH,
                p.collateralToken,
                p.ftUSDAmountOut,
                p.ref,
                p.txDeadline,
                p.maxCollateralIn
            )
        );
        CollateralInfo storage cinfo = _getCollateralEnabled(p.collateralToken);

        uint256 protocolNetFtUSDAmount = p.ftUSDAmountOut + sessionCall.feeAmount;
        uint256 grossFtUSDAmount;
        uint256 protocolFeeFtUSDAmount;
        (grossFtUSDAmount, protocolFeeFtUSDAmount, collateralAmountIn) = _calculateMintExactAmounts(
            p.collateralToken, protocolNetFtUSDAmount, cinfo.decimals, cinfo.mintFeeBps
        );
        _enforceMaxSlippage(collateralAmountIn, p.maxCollateralIn);

        (address payer, uint16 maxFeeBps) = _validateSessionCall(
            expectedHash, p.collateralToken, collateralAmountIn, sessionCall, delegateSignature
        );

        _applyPermitIfProvided(p.collateralToken, payer, permit);

        _enforceRelayerFee(protocolNetFtUSDAmount, maxFeeBps, sessionCall.feeAmount);

        _executeMintWithRelayerFee(
            p.collateralToken,
            cinfo,
            payer,
            payer,
            collateralAmountIn,
            grossFtUSDAmount,
            protocolFeeFtUSDAmount,
            p.ref,
            sessionCall.executor,
            sessionCall.feeAmount
        );
    }

    function mintExact(
        address collateralToken,
        uint256 ftUSDAmount,
        bytes32 ref,
        uint256 txDeadline,
        uint256 maxCollateralIn
    )
        external
        returns (uint256 collateralAmount)
    {
        return
            mintExactTo(collateralToken, msg.sender, ftUSDAmount, ref, txDeadline, maxCollateralIn);
    }

    /// @notice Mints an exact ftUSD amount by depositing collateral, sending ftUSD to a recipient.
    /// @dev Exact-output version of `mintTo`. Calculates and pulls the required collateral amount.
    /// @param collateralToken The collateral token to deposit.
    /// @param to The recipient address for the minted ftUSD.
    /// @param ftUSDAmount The exact net ftUSD amount to mint to `to` (after protocol fees).
    /// @param ref An optional reference identifier for tracking/integrations.
    /// @param txDeadline Unix timestamp after which the transaction reverts. Use 0 for no deadline.
    /// @param maxCollateralIn Maximum collateral allowed to be pulled (slippage protection). Use 0 for no limit.
    /// @return collateralAmount The collateral amount pulled from the caller.
    function mintExactTo(
        address collateralToken,
        address to,
        uint256 ftUSDAmount,
        bytes32 ref,
        uint256 txDeadline,
        uint256 maxCollateralIn
    )
        public
        nonReentrant
        whenNotPaused
        returns (uint256 collateralAmount)
    {
        _enforceDeadline(txDeadline);
        if (to == address(0)) revert ZeroAddress();
        if (ftUSDAmount == 0) revert ZeroAmount();

        CollateralInfo storage cinfo = _getCollateralEnabled(collateralToken);

        uint256 grossFtUSDAmount;
        uint256 feeFtUSDAmount;
        (grossFtUSDAmount, feeFtUSDAmount, collateralAmount) = _calculateMintExactAmounts(
            collateralToken, ftUSDAmount, cinfo.decimals, cinfo.mintFeeBps
        );
        _enforceMaxSlippage(collateralAmount, maxCollateralIn);

        _executeMintWithRelayerFee(
            collateralToken,
            cinfo,
            msg.sender,
            to,
            collateralAmount,
            grossFtUSDAmount,
            feeFtUSDAmount,
            ref,
            msg.sender,
            0
        );
    }

    // ===== Redemption (exact input) =====
    // NOTE: Redemptions are blocked when paused. This is intentional because redemptions interact with
    // external yield wrappers/strategies and pausing may be necessary to prevent further damage during
    // an exploit or wrapper malfunction. (Other modules may choose different emergency-exit policies.)

    /// @notice Redeems ftUSD for collateral, sending to the caller.
    /// @dev Convenience wrapper around `redeemTo` with `to` set to `msg.sender` and no ref.
    /// @param collateralToken The collateral token to receive.
    /// @param ftUSDAmount The amount of ftUSD to redeem.
    /// @param txDeadline Unix timestamp after which the transaction reverts. Use 0 for no deadline.
    /// @param minCollateralOut Minimum collateral to receive (slippage protection).
    /// @return collateralAmount The collateral amount sent to the caller after fees.
    function redeem(
        address collateralToken,
        uint256 ftUSDAmount,
        uint256 txDeadline,
        uint256 minCollateralOut
    )
        external
        returns (uint256 collateralAmount, uint256 queueId)
    {
        return redeemTo(
            collateralToken, msg.sender, ftUSDAmount, bytes32(0), txDeadline, minCollateralOut
        );
    }

    /// @notice Redeems ftUSD for collateral, sending to a specified recipient.
    /// @dev Collateral is withdrawn from the yield wrapper. Fee-on-transfer tokens are not supported.
    /// @param collateralToken The collateral token to receive.
    /// @param to The recipient address for the collateral.
    /// @param ftUSDAmount The amount of ftUSD to redeem.
    /// @param ref An optional reference identifier for tracking/integrations.
    /// @param txDeadline Unix timestamp after which the transaction reverts. Use 0 for no deadline.
    /// @param minCollateralOut Minimum collateral to receive (slippage protection).
    /// @return collateralAmount The collateral amount sent to the recipient after fees.
    function redeemTo(
        address collateralToken,
        address to,
        uint256 ftUSDAmount,
        bytes32 ref,
        uint256 txDeadline,
        uint256 minCollateralOut
    )
        public
        nonReentrant
        whenNotPaused
        returns (uint256 collateralAmount, uint256 queueId)
    {
        _enforceDeadline(txDeadline);
        if (to == address(0)) revert ZeroAddress();
        if (ftUSDAmount == 0) revert ZeroAmount();

        CollateralInfo storage cinfo = _getCollateralEnabled(collateralToken);

        uint256 feeFtUSDAmount;
        uint256 burnFtUSDAmount;
        (feeFtUSDAmount, burnFtUSDAmount, collateralAmount) = _ftUSDToCollateralWithFee(
            collateralToken,
            ftUSDAmount,
            cinfo.decimals,
            cinfo.redeemFeeBps,
            cinfo.totalIn,
            cinfo.totalOut,
            cinfo.totalFtUSDBurned,
            cinfo.totalFtUSDMinted
        );
        if (collateralAmount < minCollateralOut) {
            revert SlippageExceeded(collateralAmount, minCollateralOut);
        }

        uint256 feeQueueId;
        (collateralAmount, queueId, feeQueueId) = _executeRedeemWithRelayerFee(
            cinfo,
            RedeemExecutionParams({
                collateralToken: collateralToken,
                payer: msg.sender,
                recipient: to,
                ftUSDAmount: ftUSDAmount,
                burnFtUSDAmount: burnFtUSDAmount,
                feeFtUSDAmount: feeFtUSDAmount,
                collateralAmount: collateralAmount,
                ref: ref,
                executor: msg.sender,
                relayerFeeCollateralAmount: 0
            })
        );
        // Sanity: no relayer fee in this call, so there should not be a fee queue id.
        assert(feeQueueId == 0);
    }

    // ===== Session-key redemption (exact input) =====

    /// @notice Redeems ftUSD using a delegated session key and an optional EIP-2612 permit for ftUSD.
    /// @dev If `permit.deadline != 0`, applies the permit for `ftUSD` from the session owner to this engine.
    /// @dev Pays the relayer fee (if any) out of the collateral output.
    /// @param collateralToken The collateral token to receive.
    /// @param ftUSDAmount Amount of ftUSD to redeem.
    /// @param ref Optional reference identifier.
    /// @param txDeadline Unix timestamp after which the transaction reverts. Use 0 for no deadline.
    /// @param minCollateralOut Minimum collateral to receive (net of relayer fee).
    /// @param sessionCall Delegate-signed session call intent.
    /// @param delegateSignature Signature from the delegated session key over `sessionCall`.
    function redeemWithSessionAndPermit(
        address collateralToken,
        uint256 ftUSDAmount,
        bytes32 ref,
        uint256 txDeadline,
        uint256 minCollateralOut,
        PermitParams calldata permit,
        ISessionManager.SessionCall calldata sessionCall,
        bytes calldata delegateSignature
    )
        external
        nonReentrant
        isRelayer
        whenNotPaused
        returns (uint256 collateralAmountOut, uint256 queueIdTo, uint256 queueIdFee)
    {
        _enforceDeadline(txDeadline);
        if (ftUSDAmount == 0) revert ZeroAmount();

        bytes32 expectedHash = keccak256(
            abi.encode(
                _SESSION_REDEEM_DATAHASH_TYPEHASH,
                collateralToken,
                ftUSDAmount,
                ref,
                txDeadline,
                minCollateralOut
            )
        );
        (address payer, uint16 maxFeeBps) = _validateSessionCall(
            expectedHash, address(ftUSD), ftUSDAmount, sessionCall, delegateSignature
        );

        _applyPermitIfProvided(address(ftUSD), payer, permit);

        CollateralInfo storage cinfo = _getCollateralEnabled(collateralToken);

        uint256 protocolFeeFtUSDAmount;
        uint256 burnFtUSDAmount;
        uint256 collateralAmount;
        (protocolFeeFtUSDAmount, burnFtUSDAmount, collateralAmount) = _ftUSDToCollateralWithFee(
            collateralToken,
            ftUSDAmount,
            cinfo.decimals,
            cinfo.redeemFeeBps,
            cinfo.totalIn,
            cinfo.totalOut,
            cinfo.totalFtUSDBurned,
            cinfo.totalFtUSDMinted
        );

        _enforceRelayerFee(collateralAmount, maxFeeBps, sessionCall.feeAmount);

        collateralAmountOut = collateralAmount - sessionCall.feeAmount;
        if (collateralAmountOut < minCollateralOut) {
            revert SlippageExceeded(collateralAmountOut, minCollateralOut);
        }

        (collateralAmountOut, queueIdTo, queueIdFee) = _executeRedeemWithRelayerFee(
            cinfo,
            RedeemExecutionParams({
                collateralToken: collateralToken,
                payer: payer,
                recipient: payer,
                ftUSDAmount: ftUSDAmount,
                burnFtUSDAmount: burnFtUSDAmount,
                feeFtUSDAmount: protocolFeeFtUSDAmount,
                collateralAmount: collateralAmount,
                ref: ref,
                executor: sessionCall.executor,
                relayerFeeCollateralAmount: sessionCall.feeAmount
            })
        );
    }

    // ===== Redemption (exact output) =====

    function redeemExact(
        address collateralToken,
        uint256 collateralAmount,
        uint256 txDeadline,
        uint256 maxFtUSDIn
    )
        external
        returns (uint256 ftUSDAmount, uint256 queueId)
    {
        return redeemExactTo(
            collateralToken, msg.sender, collateralAmount, bytes32(0), txDeadline, maxFtUSDIn
        );
    }

    /// @notice Redeems an exact collateral amount by burning ftUSD, sending collateral to a recipient.
    /// @dev Exact-output version of `redeemTo`. Calculates and burns the required ftUSD amount.
    /// @param collateralToken The collateral token to receive.
    /// @param to The recipient address for the collateral.
    /// @param collateralAmount The exact collateral amount to send to `to` (after protocol fees).
    /// @param ref An optional reference identifier for tracking/integrations.
    /// @param txDeadline Unix timestamp after which the transaction reverts. Use 0 for no deadline.
    /// @param maxFtUSDIn Maximum ftUSD allowed to be pulled (slippage protection). Use 0 for no limit.
    /// @return ftUSDAmount The ftUSD amount pulled from the caller.
    function redeemExactTo(
        address collateralToken,
        address to,
        uint256 collateralAmount,
        bytes32 ref,
        uint256 txDeadline,
        uint256 maxFtUSDIn
    )
        public
        nonReentrant
        whenNotPaused
        returns (uint256 ftUSDAmount, uint256 queueId)
    {
        _enforceDeadline(txDeadline);
        if (to == address(0)) revert ZeroAddress();
        if (collateralAmount == 0) revert ZeroAmount();

        CollateralInfo storage cinfo = _getCollateralEnabled(collateralToken);

        uint256 burnFtUSDAmount;
        uint256 feeFtUSDAmount;
        (burnFtUSDAmount, ftUSDAmount, feeFtUSDAmount) = _calculateRedeemExactAmounts(
            collateralToken,
            collateralAmount,
            cinfo.decimals,
            cinfo.redeemFeeBps,
            cinfo.totalIn,
            cinfo.totalOut,
            cinfo.totalFtUSDBurned,
            cinfo.totalFtUSDMinted
        );
        _enforceMaxSlippage(ftUSDAmount, maxFtUSDIn);

        uint256 collateralToRecipient;
        uint256 feeQueueId;
        (collateralToRecipient, queueId, feeQueueId) = _executeRedeemWithRelayerFee(
            cinfo,
            RedeemExecutionParams({
                collateralToken: collateralToken,
                payer: msg.sender,
                recipient: to,
                ftUSDAmount: ftUSDAmount,
                burnFtUSDAmount: burnFtUSDAmount,
                feeFtUSDAmount: feeFtUSDAmount,
                collateralAmount: collateralAmount,
                ref: ref,
                executor: msg.sender,
                relayerFeeCollateralAmount: 0
            })
        );
        // Sanity: no relayer fee in this call, so there should not be a fee queue id.
        assert(feeQueueId == 0);
        // Sanity: exact-output redeem without relayer fee delivers the full amount.
        assert(collateralToRecipient == collateralAmount);
    }

    // ===== Session-key redemption (exact output) =====

    /// @notice Redeems an exact collateral amount (net to the owner) using a delegated session key.
    /// @dev Pays the relayer fee (if any) out of the collateral output.
    ///      The signed session call binds `collateralAmountOut` and `maxFtUSDIn`, allowing price movement
    ///      within the slippage tolerance.
    function redeemExactWithSessionAndPermit(
        address collateralToken,
        uint256 collateralAmountOut,
        bytes32 ref,
        uint256 txDeadline,
        uint256 maxFtUSDIn,
        PermitParams calldata permit,
        ISessionManager.SessionCall calldata sessionCall,
        bytes calldata delegateSignature
    )
        external
        nonReentrant
        isRelayer
        whenNotPaused
        returns (uint256 ftUSDAmountIn, uint256 queueIdTo, uint256 queueIdFee)
    {
        _enforceDeadline(txDeadline);
        if (collateralAmountOut == 0) revert ZeroAmount();

        bytes32 expectedHash = keccak256(
            abi.encode(
                _SESSION_REDEEM_EXACT_DATAHASH_TYPEHASH,
                collateralToken,
                collateralAmountOut,
                ref,
                txDeadline,
                maxFtUSDIn
            )
        );
        CollateralInfo storage cinfo = _getCollateralEnabled(collateralToken);

        uint256 collateralAmount = collateralAmountOut + sessionCall.feeAmount;

        uint256 burnFtUSDAmount;
        uint256 feeFtUSDAmount;
        (burnFtUSDAmount, ftUSDAmountIn, feeFtUSDAmount) = _calculateRedeemExactAmounts(
            collateralToken,
            collateralAmount,
            cinfo.decimals,
            cinfo.redeemFeeBps,
            cinfo.totalIn,
            cinfo.totalOut,
            cinfo.totalFtUSDBurned,
            cinfo.totalFtUSDMinted
        );
        _enforceMaxSlippage(ftUSDAmountIn, maxFtUSDIn);

        (address payer, uint16 maxFeeBps) = _validateSessionCall(
            expectedHash, address(ftUSD), ftUSDAmountIn, sessionCall, delegateSignature
        );

        _applyPermitIfProvided(address(ftUSD), payer, permit);

        _enforceRelayerFee(collateralAmount, maxFeeBps, sessionCall.feeAmount);

        uint256 actualCollateralOut;
        (actualCollateralOut, queueIdTo, queueIdFee) = _executeRedeemWithRelayerFee(
            cinfo,
            RedeemExecutionParams({
                collateralToken: collateralToken,
                payer: payer,
                recipient: payer,
                ftUSDAmount: ftUSDAmountIn,
                burnFtUSDAmount: burnFtUSDAmount,
                feeFtUSDAmount: feeFtUSDAmount,
                collateralAmount: collateralAmount,
                ref: ref,
                executor: sessionCall.executor,
                relayerFeeCollateralAmount: sessionCall.feeAmount
            })
        );
        // Sanity: exact-output redeem computes the net collateral out deterministically.
        assert(actualCollateralOut == collateralAmountOut);
    }

    // ===== Rescue =====

    /// @notice Sweeps collected ftUSD fees (held by this contract) to a destination address.
    /// @dev Only fees accounted for via `claimableFeeAmount` can be swept. Any ftUSD sent
    ///      to this contract accidentally (outside of mint/redeem flows) cannot be recovered
    ///      through this function and is effectively locked.
    /// @param to The recipient address for the swept fees.
    /// @param amount The amount of ftUSD fees to sweep.
    function sweepFees(address to, uint256 amount) external nonReentrant onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();

        uint256 available = claimableFeeAmount;
        if (amount > available) {
            revert InsufficientClaimableFees();
        }

        claimableFeeAmount = available - amount;
        IERC20(address(ftUSD)).safeTransfer(to, amount);
        emit FeesSwept(to, amount);
    }

    /// @notice Sweeps excess collateral above the reserve requirement to a destination address.
    /// @dev Only collateral value exceeding this engine's net issuance can be swept. Withdraws
    ///      from the yield wrapper if idle collateral is insufficient.
    /// @param collateralToken The collateral token to sweep.
    /// @param to The recipient address for the swept collateral.
    /// @param collateralAmount The amount of collateral to sweep.
    function sweepExcess(
        address collateralToken,
        address to,
        uint256 collateralAmount
    )
        external
        nonReentrant
        onlyOwner
    {
        if (to == address(0)) revert ZeroAddress();
        if (collateralAmount == 0) revert ZeroAmount();

        CollateralInfo storage cinfo = _getCollateral(collateralToken);

        IERC20 collateral = IERC20(collateralToken);
        IftYieldWrapperV2 wrapper = cinfo.yieldWrapper;
        uint256 idleCollateralAmount = collateral.balanceOf(address(this));
        uint256 wrapperBalance = wrapper.balanceOf(address(this));
        uint256 totalCollateralAmount = idleCollateralAmount + wrapperBalance;
        if (collateralAmount > totalCollateralAmount) {
            revert InsufficientSweepableCollateral();
        }

        uint256 outstandingUSD =
            totalFtUSDMinted > totalFtUSDBurned ? totalFtUSDMinted - totalFtUSDBurned : 0;

        if (cinfo.enabled) {
            uint256 requestedFtUSDAmount = _collateralToFtUSDMint(
                collateralToken, collateralAmount, cinfo.decimals, Math.Rounding.Ceil
            );

            if (requestedFtUSDAmount == 0) revert AmountTooSmall();

            uint256 assets = assetsUSD();
            uint256 required = outstandingUSD;

            uint256 excessUSDAmount = assets > required ? assets - required : 0;
            if (requestedFtUSDAmount > excessUSDAmount) {
                revert InsufficientExcessUSD();
            }
        }

        if (idleCollateralAmount < collateralAmount) {
            uint256 withdrawAmount = collateralAmount - idleCollateralAmount;
            wrapper.withdraw(withdrawAmount, address(this));
        }

        // Only book sweep outflow against protocol-accounted inventory. Collateral present
        // beyond accounted net inventory (e.g. direct donations) should not increase totalOut.
        uint256 accountedNetCollateral =
            cinfo.totalIn > cinfo.totalOut ? cinfo.totalIn - cinfo.totalOut : 0;
        uint256 untrackedSurplus = totalCollateralAmount > accountedNetCollateral
            ? totalCollateralAmount - accountedNetCollateral
            : 0;
        uint256 accountedSweepAmount =
            collateralAmount > untrackedSurplus ? collateralAmount - untrackedSurplus : 0;

        collateral.safeTransfer(to, collateralAmount);

        unchecked {
            cinfo.totalOut += accountedSweepAmount;
        }
        emit ExcessCollateralSwept(
            msg.sender,
            to,
            collateralToken,
            collateralAmount,
            wrapper.balanceOf(address(this)),
            outstandingUSD
        );
    }

    /// @notice Recovers accidentally sent ERC20 tokens that are not ftUSD, collateral, or wrapper shares.
    /// @dev Cannot recover ftUSD (use `sweepFees`), registered collateral tokens, or yield wrapper shares.
    /// @param token The ERC20 token address to recover.
    /// @param to The recipient address for the recovered tokens.
    /// @param amount The amount of tokens to recover.
    function recoverERC20(
        address token,
        address to,
        uint256 amount
    )
        external
        nonReentrant
        onlyOwner
    {
        if (token == address(0) || to == address(0)) revert ZeroAddress();

        // ftUSD held by this contract (fees) must be swept via `sweepFees`.
        if (token == address(ftUSD)) revert TokenNotRecoverable();

        // Disallow recovering collateral tokens and wrapper share tokens.
        CollateralInfo storage cinfo = _collaterals[token];
        if (address(cinfo.yieldWrapper) != address(0)) revert TokenNotRecoverable();
        if (isYieldWrapper[token]) revert TokenNotRecoverable();

        IERC20(token).safeTransfer(to, amount);
        emit Recovered(token, to, amount);
    }

    // ===== Internal config helpers =====

    function _getCollateralEnabled(address collateralToken)
        internal
        view
        returns (CollateralInfo storage cinfo)
    {
        cinfo = _collaterals[collateralToken];
        if (address(cinfo.yieldWrapper) == address(0) || !cinfo.enabled) {
            revert UnsupportedCollateral(collateralToken);
        }
    }

    function _getCollateral(address collateralToken)
        internal
        view
        returns (CollateralInfo storage cinfo)
    {
        cinfo = _collaterals[collateralToken];
        if (address(cinfo.yieldWrapper) == address(0)) {
            revert UnsupportedCollateral(collateralToken);
        }
    }

    // ===== Internals =====

    /// @dev Calculates amounts for exact-output mint (user specifies ftUSD amount to receive).
    function _calculateMintExactAmounts(
        address collateralToken,
        uint256 ftUSDAmount,
        uint8 decimals,
        uint16 mintFeeBps
    )
        internal
        view
        returns (uint256 grossFtUSDAmount, uint256 feeFtUSDAmount, uint256 collateralAmount)
    {
        grossFtUSDAmount = Math.mulDiv(ftUSDAmount, BPS, BPS - mintFeeBps, Math.Rounding.Ceil);
        feeFtUSDAmount = grossFtUSDAmount - ftUSDAmount;
        collateralAmount =
            _ftUSDToCollateralMint(collateralToken, grossFtUSDAmount, decimals, Math.Rounding.Ceil);
        if (collateralAmount == 0) revert AmountTooSmall();
    }

    /// @dev Calculates amounts for exact-output redeem (user specifies collateral amount to receive).
    function _calculateRedeemExactAmounts(
        address collateralToken,
        uint256 collateralAmount,
        uint8 decimals,
        uint16 redeemFeeBps,
        uint256 collateralIn,
        uint256 collateralOut,
        uint256 ftUSDBurned,
        uint256 ftUSDMinted
    )
        internal
        view
        returns (uint256 burnFtUSDAmount, uint256 ftUSDAmount, uint256 feeFtUSDAmount)
    {
        burnFtUSDAmount =
            _collateralToFtUSD(collateralToken, collateralAmount, decimals, Math.Rounding.Ceil);
        if (ftUSDMinted != 0 && collateralIn != 0) {
            // Always apply at least the average mint price (buy-side). If the collateral has a
            // net-positive position, also apply the net inventory NAV price (buy/sell) and take
            // the most conservative (highest burn).
            uint256 minBurnFtUSD =
                Math.mulDiv(collateralAmount, ftUSDMinted, collateralIn, Math.Rounding.Ceil);
            if (ftUSDMinted > ftUSDBurned && collateralIn > collateralOut) {
                uint256 netCollateralIn = collateralIn - collateralOut;
                uint256 netFtUSD = ftUSDMinted - ftUSDBurned;
                uint256 navBurnFtUSD =
                    Math.mulDiv(collateralAmount, netFtUSD, netCollateralIn, Math.Rounding.Ceil);
                if (navBurnFtUSD > minBurnFtUSD) minBurnFtUSD = navBurnFtUSD;
            }
            if (minBurnFtUSD > burnFtUSDAmount) burnFtUSDAmount = minBurnFtUSD;
        }
        if (burnFtUSDAmount == 0) revert AmountTooSmall();
        ftUSDAmount = Math.mulDiv(burnFtUSDAmount, BPS, BPS - redeemFeeBps, Math.Rounding.Ceil);
        feeFtUSDAmount = ftUSDAmount - burnFtUSDAmount;
    }

    /// @dev Applies EIP-2612 permit if provided (deadline != 0).
    function _applyPermitIfProvided(
        address token,
        address owner,
        PermitParams calldata permit
    )
        internal
    {
        if (permit.deadline != 0) {
            try IERC20Permit(token)
                .permit(
                    owner,
                    address(this),
                    permit.value,
                    permit.deadline,
                    permit.v,
                    permit.r,
                    permit.s
                ) {}
                catch {}
        }
    }

    /// @dev Enforces max slippage for exact-output operations. Reverts if actual > max and max != 0.
    function _enforceMaxSlippage(uint256 actual, uint256 max) internal pure {
        if (max != 0 && actual > max) revert SlippageExceeded(actual, max);
    }

    function _enforceRelayerFee(uint256 amount, uint16 maxFeeBps, uint256 feeAmount) internal pure {
        uint256 maxRelayerFee = maxFeeBps == 0 ? 0 : Math.mulDiv(amount, maxFeeBps, BPS);
        if (feeAmount > maxRelayerFee) revert RelayerFeeTooHigh(feeAmount, maxRelayerFee);
    }

    /// @dev Core mint logic that pays a relayer fee out of the minted ftUSD output.
    function _executeMintWithRelayerFee(
        address collateralToken,
        CollateralInfo storage cinfo,
        address payer,
        address recipient,
        uint256 collateralAmount,
        uint256 grossFtUSDAmount,
        uint256 feeFtUSDAmount,
        bytes32 ref,
        address executor,
        uint256 relayerFeeFtUSDAmount
    )
        internal
        returns (uint256 netToRecipient)
    {
        IftYieldWrapperV2 wrapper = cinfo.yieldWrapper;
        IERC20 collateral = IERC20(collateralToken);
        uint256 idleCollateralAmount = collateral.balanceOf(address(this));
        uint256 wrapperPrincipal = wrapper.balanceOf(address(this));

        _enforceCollateralCap(
            collateralToken, cinfo, wrapperPrincipal + idleCollateralAmount, collateralAmount
        );

        collateral.safeTransferFrom(payer, address(this), collateralAmount);
        wrapper.deposit(collateralAmount);

        core.mint(address(this), grossFtUSDAmount);

        uint256 netFtUSDAmount = grossFtUSDAmount - feeFtUSDAmount;
        if (relayerFeeFtUSDAmount > netFtUSDAmount) {
            revert RelayerFeeTooHigh(relayerFeeFtUSDAmount, netFtUSDAmount);
        }

        unchecked {
            netToRecipient = netFtUSDAmount - relayerFeeFtUSDAmount;
        }

        // Distribute minted ftUSD via payout router (rate-limited) or directly
        IMintPayoutRouter router = payoutRouter;
        if (address(router) != address(0)) {
            // Router handles rate-limited distribution (TVL computed post-mint)
            IERC20(address(ftUSD)).safeTransfer(address(router), netFtUSDAmount);
            router.payout(recipient, netToRecipient, executor, relayerFeeFtUSDAmount);
        } else {
            // No router - transfer directly
            IERC20(address(ftUSD)).safeTransfer(recipient, netToRecipient);
            if (relayerFeeFtUSDAmount != 0) {
                IERC20(address(ftUSD)).safeTransfer(executor, relayerFeeFtUSDAmount);
            }
        }

        if (relayerFeeFtUSDAmount != 0) {
            emit RelayerFeePaid(payer, executor, address(ftUSD), relayerFeeFtUSDAmount, ref);
        }

        unchecked {
            cinfo.totalIn += collateralAmount;
            cinfo.totalFtUSDMinted += grossFtUSDAmount;
            totalFtUSDMinted += grossFtUSDAmount;
            claimableFeeAmount += feeFtUSDAmount;
        }
        emit Minted(
            msg.sender,
            payer,
            recipient,
            ref,
            collateralToken,
            collateralAmount,
            netToRecipient,
            feeFtUSDAmount,
            wrapper.balanceOf(address(this))
        );
    }

    /// @dev Core redeem logic that pays a relayer fee out of the collateral output.
    function _executeRedeemWithRelayerFee(
        CollateralInfo storage cinfo,
        RedeemExecutionParams memory p
    )
        internal
        returns (uint256 collateralToRecipient, uint256 queueIdTo, uint256 queueIdFee)
    {
        IERC20(address(ftUSD)).safeTransferFrom(p.payer, address(this), p.ftUSDAmount);
        core.burn(p.burnFtUSDAmount);

        if (p.relayerFeeCollateralAmount > p.collateralAmount) {
            revert RelayerFeeTooHigh(p.relayerFeeCollateralAmount, p.collateralAmount);
        }

        unchecked {
            collateralToRecipient = p.collateralAmount - p.relayerFeeCollateralAmount;
        }

        // Wrapper is already a ProtectedContract - it handles rate limiting of collateral outflows
        IftYieldWrapperV2 wrapper = cinfo.yieldWrapper;

        queueIdTo = wrapper.withdraw(collateralToRecipient, p.recipient);
        if (p.relayerFeeCollateralAmount != 0) {
            queueIdFee = wrapper.withdraw(p.relayerFeeCollateralAmount, p.executor);
            emit RelayerFeePaid(
                p.payer, p.executor, p.collateralToken, p.relayerFeeCollateralAmount, p.ref
            );
        }

        unchecked {
            cinfo.totalOut += p.collateralAmount;
            cinfo.totalFtUSDBurned += p.burnFtUSDAmount;
            totalFtUSDBurned += p.burnFtUSDAmount;
            claimableFeeAmount += p.feeFtUSDAmount;
        }
        emit Redeemed(
            msg.sender,
            p.payer,
            p.recipient,
            p.ref,
            p.collateralToken,
            p.ftUSDAmount,
            p.feeFtUSDAmount,
            collateralToRecipient,
            wrapper.balanceOf(address(this))
        );
    }

    function _enforceDeadline(uint256 txDeadline) internal view {
        if (txDeadline == 0) return;
        if (block.timestamp > txDeadline) revert TransactionExpired();
    }

    function _validateSessionCall(
        bytes32 expectedHash,
        address spendToken,
        uint256 spendAmount,
        ISessionManager.SessionCall calldata sessionCall,
        bytes calldata delegateSignature
    )
        internal
        returns (address payer, uint16 maxFeeBps)
    {
        if (address(sessionManager) == address(0)) revert SessionManagerNotSet();
        if (sessionCall.dataHash != expectedHash) {
            revert SessionDataHashMismatch(expectedHash, sessionCall.dataHash);
        }
        (payer,, maxFeeBps) = sessionManager.validateAndConsume(
            spendToken, spendAmount, sessionCall, delegateSignature, msg.sender
        );
    }

    function _calculateFee(uint256 amount, uint16 feeBps) internal pure returns (uint256) {
        if (feeBps == 0) return 0;
        return Math.mulDiv(amount, feeBps, BPS, Math.Rounding.Ceil);
    }

    function _enforceCollateralCap(
        address collateralToken,
        CollateralInfo storage cinfo,
        uint256 existingCollateralAmount,
        uint256 addedCollateralAmount
    )
        internal
        view
    {
        uint256 cap = cinfo.maxValueFtUSD;
        if (cap == 0) return;

        uint256 newCollateralAmount = existingCollateralAmount + addedCollateralAmount;
        uint256 collateralValue = _collateralToFtUSD(
            collateralToken, newCollateralAmount, cinfo.decimals, Math.Rounding.Ceil
        );
        if (collateralValue == 0) return;

        if (collateralValue > cap) {
            revert CollateralCapExceeded(collateralToken);
        }
    }

    function _collateralToFtUSD(
        address collateralToken,
        uint256 collateralAmount,
        uint8 decimals,
        Math.Rounding rounding
    )
        internal
        view
        returns (uint256)
    {
        uint256 priceWad = oracle.priceUSD(collateralToken);
        uint256 assetUnit = 10 ** uint256(decimals);
        return Math.mulDiv(collateralAmount, priceWad * FTUSD_SCALE, assetUnit * USD_WAD, rounding);
    }

    function _priceUSDForMint(address collateralToken) internal view returns (uint256 priceWad) {
        priceWad = oracle.priceUSD(collateralToken);
        uint256 hardcapPriceWad = _collaterals[collateralToken].mintPriceHardcapWad;
        if (hardcapPriceWad != 0 && priceWad > hardcapPriceWad) {
            priceWad = hardcapPriceWad;
        }
    }

    function _collateralToFtUSDMint(
        address collateralToken,
        uint256 collateralAmount,
        uint8 decimals,
        Math.Rounding rounding
    )
        internal
        view
        returns (uint256)
    {
        uint256 priceWad = _priceUSDForMint(collateralToken);
        uint256 assetUnit = 10 ** uint256(decimals);
        return Math.mulDiv(collateralAmount, priceWad * FTUSD_SCALE, assetUnit * USD_WAD, rounding);
    }

    /// @dev Quote ftUSD out and fee for collateral in (mint flow).
    /// Fee is charged in ftUSD, computed from the gross ftUSD output.
    function _collateralToFtUSDWithFee(
        address collateralToken,
        uint256 collateralAmount,
        uint8 decimals,
        uint16 mintFeeBps
    )
        internal
        view
        returns (uint256 ftUSDAmount, uint256 feeAmount)
    {
        uint256 grossFtUSDAmount = _collateralToFtUSDMint(
            collateralToken, collateralAmount, decimals, Math.Rounding.Floor
        );
        if (grossFtUSDAmount == 0) revert AmountTooSmall();

        feeAmount = _calculateFee(grossFtUSDAmount, mintFeeBps);
        ftUSDAmount = grossFtUSDAmount - feeAmount;
        if (ftUSDAmount == 0) revert AmountTooSmall();
    }

    function _ftUSDToCollateral(
        address collateralToken,
        uint256 ftUSDAmount,
        uint8 decimals,
        Math.Rounding rounding
    )
        internal
        view
        returns (uint256)
    {
        uint256 priceWad = oracle.priceUSD(collateralToken);
        uint256 assetUnit = 10 ** uint256(decimals);
        return Math.mulDiv(ftUSDAmount, assetUnit * USD_WAD, FTUSD_SCALE * priceWad, rounding);
    }

    function _ftUSDToCollateralMint(
        address collateralToken,
        uint256 ftUSDAmount,
        uint8 decimals,
        Math.Rounding rounding
    )
        internal
        view
        returns (uint256)
    {
        uint256 priceWad = _priceUSDForMint(collateralToken);
        uint256 assetUnit = 10 ** uint256(decimals);
        return Math.mulDiv(ftUSDAmount, assetUnit * USD_WAD, FTUSD_SCALE * priceWad, rounding);
    }

    /// @dev Quote collateral out and fee for ftUSD in (redeem flow).
    /// Fee is charged in ftUSD, computed from the input ftUSD amount; only net is converted to collateral.
    function _ftUSDToCollateralWithFee(
        address collateralToken,
        uint256 ftUSDAmount,
        uint8 decimals,
        uint16 redeemFeeBps,
        uint256 collateralIn,
        uint256 collateralOut,
        uint256 ftUSDBurned,
        uint256 ftUSDMinted
    )
        internal
        view
        returns (uint256 feeAmount, uint256 netFtUSDAmount, uint256 collateralAmount)
    {
        feeAmount = _calculateFee(ftUSDAmount, redeemFeeBps);
        netFtUSDAmount = ftUSDAmount - feeAmount;
        if (netFtUSDAmount == 0) revert AmountTooSmall();

        collateralAmount =
            _ftUSDToCollateral(collateralToken, netFtUSDAmount, decimals, Math.Rounding.Floor);

        if (ftUSDMinted != 0 && collateralIn != 0) {
            // Always apply at most the average mint rate (buy-side). If the collateral has a
            // net-positive position, also apply the net inventory NAV rate (buy/sell) and take
            // the most conservative (lowest max out).
            uint256 maxCollateralOut =
                Math.mulDiv(netFtUSDAmount, collateralIn, ftUSDMinted, Math.Rounding.Floor);
            if (ftUSDMinted > ftUSDBurned && collateralIn > collateralOut) {
                uint256 netCollateralIn = collateralIn - collateralOut;
                uint256 netFtUSD = ftUSDMinted - ftUSDBurned;
                uint256 navMaxCollateralOut =
                    Math.mulDiv(netFtUSDAmount, netCollateralIn, netFtUSD, Math.Rounding.Floor);
                if (navMaxCollateralOut < maxCollateralOut) maxCollateralOut = navMaxCollateralOut;
            }
            if (collateralAmount > maxCollateralOut) collateralAmount = maxCollateralOut;
        }
        if (collateralAmount == 0) revert AmountTooSmall();
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
