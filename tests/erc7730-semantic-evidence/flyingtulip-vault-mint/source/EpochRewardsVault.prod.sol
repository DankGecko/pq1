// SPDX-License-Identifier: UNLICENSED
// Copyright (c) 2025 Flying Tulip Inc. All rights reserved.
pragma solidity 0.8.30;

import {Initializable} from "openzeppelin-contracts/contracts/proxy/utils/Initializable.sol";
import {
    ERC20Upgradeable
} from "openzeppelin-contracts-upgradeable/contracts/token/ERC20/ERC20Upgradeable.sol";
import {
    ERC4626Upgradeable
} from "openzeppelin-contracts-upgradeable/contracts/token/ERC20/extensions/ERC4626Upgradeable.sol";
import {
    ERC20PermitUpgradeable
} from "openzeppelin-contracts-upgradeable/contracts/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {
    Ownable2StepUpgradeable
} from "openzeppelin-contracts-upgradeable/contracts/access/Ownable2StepUpgradeable.sol";
import {
    PausableUpgradeable
} from "openzeppelin-contracts-upgradeable/contracts/utils/PausableUpgradeable.sol";
import {
    UUPSUpgradeable
} from "openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";
import {
    ReentrancyGuardTransient
} from "openzeppelin-contracts/contracts/utils/ReentrancyGuardTransient.sol";
import {Math} from "openzeppelin-contracts/contracts/utils/math/Math.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {
    SignatureChecker
} from "openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol";
import {
    IERC20Permit
} from "openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {ISessionManager} from "./interfaces/ISessionManager.sol";
import {IftYieldWrapperV2} from "./interfaces/IftYieldWrapperV2.sol";
import {IRelayerAuth} from "./interfaces/IRelayerAuth.sol";

interface IFtUSDCompliance {
    function isBlacklisted(address account) external view returns (bool);
    function paused() external view returns (bool);
}
/// @title Staking vault distributing FT rewards per epoch (stake-time weighted, O(1) catch-up)
/// @notice Users stake asset. Admin periodically closes an epoch and funds FT rewards.
///         FT is allocated pro-rata by stake-seconds within that epoch.
/// @dev O(1) per user action and per epoch settlement (no loops over epochs).
contract EpochRewardsVault is
    Initializable,
    ERC4626Upgradeable,
    ERC20PermitUpgradeable,
    Ownable2StepUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardTransient
{
    using SafeERC20 for IERC20;

    uint256 internal constant RAY = 1e27;
    uint256 internal constant BPS = 10_000;

    IRelayerAuth public relayerAuth;

    IERC20 public immutable ASSET;
    IERC20 public immutable FT;
    IftYieldWrapperV2 public immutable yieldWrapper;

    /// @notice Current total staked ASSET (smallest units) == totalSupply().
    /// @notice Cumulative integral S(t) = ∫ totalSupply() dt (units: ASSET * seconds).
    uint256 public totalStakeTime;
    /// @notice Last timestamp we synced totalStakeTime.
    uint40 public lastStakeTimeUpdate;

    // -----------------------------
    // Epoch settlement state
    // -----------------------------
    /// @notice Latest settled epoch id. Open epoch is always (epoch+1) and not stored yet.
    uint32 public epoch;

    struct EpochData {
        uint40 t_end; // epoch end timestamp
        uint256 S_end; // totalStakeTime at epoch end
        uint256 rateRay; // FT*RAY / (ASSET*sec)
        uint256 X_end; // X_end = Σ (Δt * rateRay) up to this epoch, units FT*RAY/ASSET
        uint256 rewardAmount; // actual FT received for this epoch
        uint256 stakeTime; // total stake-time for this epoch (ASSET*sec)
    }

    mapping(uint32 => EpochData) public epochs;

    // -----------------------------
    // User state
    // -----------------------------
    struct User {
        uint40 lastT; // timestamp checkpoint within the currently-open epoch
        uint32 lastSettledEpoch;
        uint256 openStakeTime; // banked stake-time within open epoch due to stake changes (ASSET*sec)
        uint256 ftAccrued; // claimable FT from settled epochs
    }

    mapping(address => User) public users;

    /// @notice Parameters for EIP-2612 permit signatures (optional when `deadline == 0`).
    struct PermitParams {
        uint256 value;
        uint256 deadline;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    ISessionManager public sessionManager;
    address public epochSettler;

    bytes32 internal constant _PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    bytes32 internal constant _SESSION_DEPOSIT_DATAHASH_TYPEHASH =
        keccak256("SessionDeposit(uint256 assets)");
    bytes32 internal constant _SESSION_WITHDRAW_DATAHASH_TYPEHASH =
        keccak256("SessionWithdraw(uint256 assets)");
    bytes32 internal constant _SESSION_CLAIM_DATAHASH_TYPEHASH = keccak256("SessionClaim()");

    // -----------------------------
    // Errors
    // -----------------------------
    error ZeroAmount();
    error ZeroAddress();
    error NoStakeTime();
    error NotEnoughRewards();
    error NotBlacklisted(address account);
    error NothingToWipe(address account);
    error TokenNotRecoverable();
    error NotRelayer(address sender);
    error AccountBlacklisted(address account);
    error SessionManagerNotSet();
    error SessionDataHashMismatch(bytes32 expected, bytes32 provided);
    error RelayerFeeTooHigh(uint256 feeAmount, uint256 maxFeeAmount);
    error ReceiverMustBeOwner(address owner, address receiver);
    error NotOwnerOrEpochSettler(address caller);

    event SessionManagerUpdated(address indexed newSessionManager);
    event EpochSettlerUpdated(address indexed newEpochSettler);
    event RelayerAuthUpdated(address indexed newRelayerAuth);
    event RelayerFeePaid(
        address indexed user, address indexed executor, address token, uint256 amount
    );
    event EpochSettled(
        uint32 indexed epochId, uint256 rewardAmount, uint256 stakeTime, uint256 rateRay
    );
    event Claimed(address indexed user, address indexed to, uint256 paid, uint256 remaining);
    event Recovered(address indexed token, address indexed to, uint256 amount);
    event BlacklistedAddressWiped(
        address indexed account, address indexed owner, uint256 assetsSeized, uint256 rewardsSeized
    );

    constructor(address _yieldWrapper, address _ft) {
        FT = IERC20(_ft);
        yieldWrapper = IftYieldWrapperV2(_yieldWrapper);
        ASSET = IERC20(yieldWrapper.token());
        _disableInitializers();
    }

    function initialize(address admin) external initializer {
        if (admin == address(0)) revert ZeroAddress();

        __ERC20_init("Staked Flying Tulip USD", "sftUSD");
        __ERC4626_init(IERC20(ASSET));
        __ERC20Permit_init("Staked Flying Tulip USD");
        __Pausable_init();
        __Ownable_init(admin);
        __Ownable2Step_init();

        uint40 nowTs = uint40(block.timestamp);

        // Genesis epoch 0
        epochs[0] = EpochData({
            t_end: nowTs, S_end: 0, rateRay: 0, X_end: 0, rewardAmount: 0, stakeTime: 0
        });

        // epoch = 0; this is the default. no need to force 0.
        lastStakeTimeUpdate = nowTs;
        ASSET.forceApprove(address(yieldWrapper), type(uint256).max);

        emit EpochSettled(0, 0, 0, 0);
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
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

    function setEpochSettler(address newEpochSettler) external onlyOwner {
        epochSettler = newEpochSettler;
        emit EpochSettlerUpdated(newEpochSettler);
    }

    modifier isRelayer() {
        _isRelayer();
        _;
    }

    modifier onlyOwnerOrEpochSettler() {
        _onlyOwnerOrEpochSettler();
        _;
    }

    function _isRelayer() internal view {
        if (!relayerAuth.isRelayer(msg.sender)) revert NotRelayer(msg.sender);
    }

    function _onlyOwnerOrEpochSettler() internal view {
        if (msg.sender != owner() && msg.sender != epochSettler) {
            revert NotOwnerOrEpochSettler(msg.sender);
        }
    }

    // -----------------------------
    // ERC4626 (tokenized deposits)
    // -----------------------------

    function _deposit(
        address from,
        address to,
        uint256 assets,
        uint256 shares,
        address executor,
        uint256 fee
    )
        internal
    {
        ASSET.safeTransferFrom(from, address(this), assets + fee);
        if (fee != 0) {
            ASSET.safeTransfer(executor, fee);
            emit RelayerFeePaid(from, executor, address(ASSET), fee);
        }
        yieldWrapper.deposit(assets);
        _mint(to, shares);

        emit Deposit(from, to, assets, shares);
    }

    function _withdraw(
        address spender,
        address receiver,
        address owner,
        uint256 assets,
        uint256 shares,
        address executor,
        uint256 fee
    )
        internal
    {
        _withdrawWithQueueIds(spender, receiver, owner, assets, shares, executor, fee);
    }

    function _withdrawWithQueueIds(
        address spender,
        address receiver,
        address owner,
        uint256 assets,
        uint256 shares,
        address executor,
        uint256 fee
    )
        internal
        returns (uint256 queueIdTo, uint256 queueIdFee)
    {
        if (spender != owner) {
            _spendAllowance(owner, spender, shares);
        }

        _burn(owner, shares);
        if (fee != 0) {
            queueIdFee = yieldWrapper.withdraw(fee, executor);
            emit RelayerFeePaid(owner, executor, address(ASSET), fee);
        }
        queueIdTo = yieldWrapper.withdraw(assets, receiver);

        emit Withdraw(spender, receiver, owner, assets, shares);
    }

    /// @dev Tokenize deposits 1:1 and enforce pause + reentrancy guard.
    function deposit(
        uint256 assets,
        address receiver
    )
        public
        override
        nonReentrant
        whenNotPaused
        returns (uint256 shares)
    {
        if (receiver == address(0)) revert ZeroAddress();
        if (assets == 0) revert ZeroAmount();

        uint256 maxAssets = maxDeposit(receiver);
        if (assets > maxAssets) revert ERC4626ExceededMaxDeposit(receiver, assets, maxAssets);

        shares = previewDeposit(assets);
        _deposit(msg.sender, receiver, assets, shares, msg.sender, 0);
    }

    /// @dev Tokenize deposits 1:1 and enforce pause + reentrancy guard.
    function mint(
        uint256 shares,
        address receiver
    )
        public
        override
        nonReentrant
        whenNotPaused
        returns (uint256 assets)
    {
        if (receiver == address(0)) revert ZeroAddress();
        if (shares == 0) revert ZeroAmount();

        uint256 maxShares = maxMint(receiver);
        if (shares > maxShares) revert ERC4626ExceededMaxMint(receiver, shares, maxShares);

        assets = previewMint(shares);
        _deposit(msg.sender, receiver, assets, shares, msg.sender, 0);
    }

    /// @dev Withdraw is allowed even if paused (so users can exit in emergencies).
    ///      Note: exits still rely on the external `yieldWrapper` behavior.
    function withdraw(
        uint256 assets,
        address receiver,
        address owner
    )
        public
        override
        nonReentrant
        returns (uint256 shares)
    {
        if (receiver == address(0) || owner == address(0)) revert ZeroAddress();
        if (assets == 0) revert ZeroAmount();

        uint256 maxAssets = maxWithdraw(owner);
        if (assets > maxAssets) revert ERC4626ExceededMaxWithdraw(owner, assets, maxAssets);

        shares = previewWithdraw(assets);
        _withdraw(msg.sender, receiver, owner, assets, shares, msg.sender, 0);
    }

    /// @dev Redeem is allowed even if paused (so users can exit in emergencies).
    ///      Note: exits still rely on the external `yieldWrapper` behavior.
    function redeem(
        uint256 shares,
        address receiver,
        address owner
    )
        public
        override
        nonReentrant
        returns (uint256 assets)
    {
        if (receiver == address(0) || owner == address(0)) revert ZeroAddress();
        if (shares == 0) revert ZeroAmount();

        uint256 maxShares = maxRedeem(owner);
        if (shares > maxShares) revert ERC4626ExceededMaxRedeem(owner, shares, maxShares);

        assets = previewRedeem(shares);
        _withdraw(msg.sender, receiver, owner, assets, shares, msg.sender, 0);
    }

    /// @dev Force 1:1 shares:assets conversions (no exchange-rate drift).
    function totalAssets() public view override returns (uint256) {
        return totalSupply();
    }

    /// @dev Reflect pause status for ERC4626 integrators.
    function maxDeposit(address receiver) public view override returns (uint256) {
        if (paused() || _assetPausedOrBlacklisted(receiver)) return 0;
        return super.maxDeposit(receiver);
    }

    /// @dev Reflect pause status for ERC4626 integrators.
    function maxMint(address receiver) public view override returns (uint256) {
        if (paused() || _assetPausedOrBlacklisted(receiver)) return 0;
        return super.maxMint(receiver);
    }

    /// @dev Reflect underlying asset compliance constraints for ERC4626 integrators.
    function maxWithdraw(address owner) public view override returns (uint256) {
        if (_assetPausedOrBlacklisted(owner)) return 0;
        return super.maxWithdraw(owner);
    }

    /// @dev Reflect underlying asset compliance constraints for ERC4626 integrators.
    function maxRedeem(address owner) public view override returns (uint256) {
        if (_assetPausedOrBlacklisted(owner)) return 0;
        return super.maxRedeem(owner);
    }

    /// @dev Returns the decimals of the underlying asset (ftUSD uses 6 decimals).
    function decimals() public view override(ERC20Upgradeable, ERC4626Upgradeable) returns (uint8) {
        return super.decimals();
    }

    /// @dev This vault uses a 1:1 shares-to-assets ratio. Rewards are distributed externally
    ///      via epochs, not through share appreciation. This invariant is relied upon by
    ///      authorization-bound permit flows for predictable authorization values.
    function _convertToShares(
        uint256 assets,
        Math.Rounding
    )
        internal
        pure
        override
        returns (uint256)
    {
        return assets;
    }

    /// @dev See `_convertToShares` for the 1:1 invariant documentation.
    function _convertToAssets(
        uint256 shares,
        Math.Rounding
    )
        internal
        pure
        override
        returns (uint256)
    {
        return shares;
    }

    function _update(address from, address to, uint256 value) internal override(ERC20Upgradeable) {
        _enforceAssetCompliance(from, to);

        // Only mint/burn changes total stake; sync integral before totalSupply() changes.
        if (from == address(0) || to == address(0)) {
            _syncTotalStakeTime();
        }

        // Transfers must checkpoint both sides so stake-time accrual follows the token.
        if (from != address(0)) {
            _settleUser(from);
            _accrueOpenStakeTime(from);
        }
        if (to != address(0) && to != from) {
            _settleUser(to);
            _accrueOpenStakeTime(to);
        }

        super._update(from, to, value);
    }

    function _enforceAssetCompliance(address from, address to) internal view {
        IFtUSDCompliance asset = IFtUSDCompliance(address(ASSET));

        if (asset.paused()) revert PausableUpgradeable.EnforcedPause();

        address sender = msg.sender;
        if (asset.isBlacklisted(sender)) revert AccountBlacklisted(sender);
        if (asset.isBlacklisted(from)) revert AccountBlacklisted(from);
        if (asset.isBlacklisted(to)) revert AccountBlacklisted(to);
    }

    function _enforceNotBlacklisted(address account) internal view {
        if (IFtUSDCompliance(address(ASSET)).isBlacklisted(account)) {
            revert AccountBlacklisted(account);
        }
    }

    function _assetPausedOrBlacklisted(address account) internal view returns (bool) {
        IFtUSDCompliance asset = IFtUSDCompliance(address(ASSET));
        return asset.paused() || asset.isBlacklisted(account);
    }

    /// @notice Close the current open epoch and distribute `rewardAmount` FT across stake-time in that epoch.
    /// @dev Pulls FT from msg.sender.
    ///      If rewardAmount > 0 and there was no stake-time, reverts to avoid locking FT.
    function settleEpoch(uint256 rewardAmount)
        external
        nonReentrant
        whenNotPaused
        onlyOwnerOrEpochSettler
    {
        if (rewardAmount == 0) revert ZeroAmount();

        _syncTotalStakeTime();

        EpochData storage prev = epochs[epoch];
        uint40 nowTs = uint40(block.timestamp);

        uint256 stakeTimeEpoch = totalStakeTime - prev.S_end; // ASSET*sec
        if (stakeTimeEpoch == 0) revert NoStakeTime();

        uint256 balBefore = FT.balanceOf(address(this));
        FT.safeTransferFrom(msg.sender, address(this), rewardAmount);
        uint256 received = FT.balanceOf(address(this)) - balBefore;
        if (received == 0) revert NotEnoughRewards();
        rewardAmount = received;

        uint256 rateRay = Math.mulDiv(rewardAmount, RAY, stakeTimeEpoch);
        uint256 duration = uint256(nowTs - prev.t_end);
        // X_end = X_prev + duration * rateRay
        uint256 X_end = prev.X_end + (duration * rateRay);

        uint32 newEpoch = epoch + 1;
        epochs[newEpoch] = EpochData({
            t_end: nowTs,
            S_end: totalStakeTime,
            rateRay: rateRay,
            X_end: X_end,
            rewardAmount: rewardAmount,
            stakeTime: stakeTimeEpoch
        });

        epoch = newEpoch;

        emit EpochSettled(newEpoch, rewardAmount, stakeTimeEpoch, rateRay);
    }

    function deposit(uint256 amount) external returns (uint256) {
        return depositFor(msg.sender, amount);
    }

    function depositFor(address receiver, uint256 amount) public returns (uint256) {
        return deposit(amount, receiver);
    }

    // -----------------------------
    // Session-key flows
    // -----------------------------

    /// @notice Deposit assets using a delegated session key and an optional EIP-2612 permit for ftUSD.
    /// @dev If `permit.deadline != 0`, applies the permit for `ASSET` from the session owner to this vault.
    function depositWithSessionAndPermit(
        uint256 assets,
        PermitParams calldata permitParams,
        ISessionManager.SessionCall calldata sessionCall,
        bytes calldata delegateSignature
    )
        external
        isRelayer
        nonReentrant
        whenNotPaused
        returns (uint256 sharesToUser)
    {
        if (address(sessionManager) == address(0)) revert SessionManagerNotSet();
        if (assets == 0) revert ZeroAmount();

        bytes32 expectedHash = keccak256(abi.encode(_SESSION_DEPOSIT_DATAHASH_TYPEHASH, assets));
        if (sessionCall.dataHash != expectedHash) {
            revert SessionDataHashMismatch(expectedHash, sessionCall.dataHash);
        }

        (address owner,, uint16 maxFeeBps) = sessionManager.validateAndConsume(
            address(ASSET), assets, sessionCall, delegateSignature, msg.sender
        );

        _tryPermitAsset(
            owner,
            permitParams.value,
            permitParams.deadline,
            permitParams.v,
            permitParams.r,
            permitParams.s
        );

        _enforceRelayerFee(assets, maxFeeBps, sessionCall.feeAmount);
        uint256 assetsForShares = assets - sessionCall.feeAmount;
        if (assetsForShares == 0) revert ZeroAmount();

        uint256 maxAssets = maxDeposit(owner);
        if (assetsForShares > maxAssets) {
            revert ERC4626ExceededMaxDeposit(owner, assetsForShares, maxAssets);
        }

        sharesToUser = previewDeposit(assetsForShares);
        _deposit(
            owner, owner, assetsForShares, sharesToUser, sessionCall.executor, sessionCall.feeAmount
        );
    }

    /// @notice Withdraw assets using a delegated session key for sftUSD.
    /// @dev `assets` is the gross withdrawal amount burned from owner shares.
    ///      Owner receives `assets - sessionCall.feeAmount`; relayer receives `sessionCall.feeAmount`.
    function withdrawWithSession(
        uint256 assets,
        ISessionManager.SessionCall calldata sessionCall,
        bytes calldata delegateSignature
    )
        external
        isRelayer
        nonReentrant
        returns (uint256 sharesBurned, uint256 queueIdTo, uint256 queueIdFee)
    {
        if (address(sessionManager) == address(0)) revert SessionManagerNotSet();
        if (assets == 0) revert ZeroAmount();

        bytes32 expectedHash = keccak256(abi.encode(_SESSION_WITHDRAW_DATAHASH_TYPEHASH, assets));
        if (sessionCall.dataHash != expectedHash) {
            revert SessionDataHashMismatch(expectedHash, sessionCall.dataHash);
        }

        sharesBurned = previewWithdraw(assets);

        (address owner,, uint16 maxFeeBps) = sessionManager.validateAndConsume(
            address(this), sharesBurned, sessionCall, delegateSignature, msg.sender
        );

        uint256 maxAssets = maxWithdraw(owner);
        if (assets > maxAssets) revert ERC4626ExceededMaxWithdraw(owner, assets, maxAssets);

        _enforceRelayerFee(assets, maxFeeBps, sessionCall.feeAmount);
        uint256 assetsToUser = assets - sessionCall.feeAmount;
        (queueIdTo, queueIdFee) = _withdrawWithQueueIds(
            owner,
            owner,
            owner,
            assetsToUser,
            sharesBurned,
            sessionCall.executor,
            sessionCall.feeAmount
        );
    }

    /// @notice Claim settled rewards using a delegated session key (no user signature per action).
    /// @dev Pays the relayer fee (if any) out of the FT output.
    function claimWithSession(
        ISessionManager.SessionCall calldata sessionCall,
        bytes calldata delegateSignature
    )
        external
        isRelayer
        nonReentrant
        returns (uint256 paidToUser)
    {
        if (address(sessionManager) == address(0)) revert SessionManagerNotSet();

        bytes32 expectedHash = keccak256(abi.encode(_SESSION_CLAIM_DATAHASH_TYPEHASH));
        if (sessionCall.dataHash != expectedHash) {
            revert SessionDataHashMismatch(expectedHash, sessionCall.dataHash);
        }

        (address owner,, uint16 maxFeeBps) = sessionManager.validateAndConsume(
            address(0), 0, sessionCall, delegateSignature, msg.sender
        );

        return _claim(owner, owner, sessionCall.executor, sessionCall.feeAmount, maxFeeBps);
    }

    function withdraw(uint256 amount) external returns (uint256 shares, uint256 queueId) {
        return withdrawTo(msg.sender, amount);
    }

    /// @dev Withdraw is allowed even if paused (so users can exit in emergencies).
    function withdrawTo(
        address to,
        uint256 amount
    )
        public
        returns (uint256 shares, uint256 queueId)
    {
        return withdrawWithQueueId(amount, to, msg.sender);
    }

    /// @notice Withdraw assets and return the yield wrapper queue ID (0 when immediate).
    /// @dev This is the queue-aware variant of ERC4626 `withdraw`.
    function withdrawWithQueueId(
        uint256 assets,
        address receiver,
        address owner
    )
        public
        nonReentrant
        returns (uint256 shares, uint256 queueId)
    {
        if (receiver == address(0) || owner == address(0)) revert ZeroAddress();
        if (assets == 0) revert ZeroAmount();

        uint256 maxAssets = maxWithdraw(owner);
        if (assets > maxAssets) revert ERC4626ExceededMaxWithdraw(owner, assets, maxAssets);

        shares = previewWithdraw(assets);
        (queueId,) =
            _withdrawWithQueueIds(msg.sender, receiver, owner, assets, shares, msg.sender, 0);
    }

    /// @notice Redeem shares and return the yield wrapper queue ID (0 when immediate).
    /// @dev This is the queue-aware variant of ERC4626 `redeem`.
    function redeemWithQueueId(
        uint256 shares,
        address receiver,
        address owner
    )
        public
        nonReentrant
        returns (uint256 assets, uint256 queueId)
    {
        if (receiver == address(0) || owner == address(0)) revert ZeroAddress();
        if (shares == 0) revert ZeroAmount();

        uint256 maxShares = maxRedeem(owner);
        if (shares > maxShares) revert ERC4626ExceededMaxRedeem(owner, shares, maxShares);

        assets = previewRedeem(shares);
        (queueId,) =
            _withdrawWithQueueIds(msg.sender, receiver, owner, assets, shares, msg.sender, 0);
    }

    /// @notice Claim settled FT rewards.
    /// @dev Does NOT include the currently-open (unsettled) epoch because its rate is unknown.
    function claim(address to) external nonReentrant returns (uint256 paidToUser) {
        return _claim(msg.sender, to, msg.sender, 0, 0);
    }

    function _claim(
        address owner,
        address to,
        address executor,
        uint256 fee,
        uint16 maxFeeBps
    )
        internal
        returns (uint256 paidToUser)
    {
        if (to == address(0)) revert ZeroAddress();

        _enforceNotBlacklisted(owner);
        _settleUser(owner);

        User storage user = users[owner];
        uint256 claimable = user.ftAccrued;
        if (claimable == 0) return 0;

        uint256 bal = FT.balanceOf(address(this));
        if (bal == 0) revert NotEnoughRewards();

        uint256 paidGross = claimable <= bal ? claimable : bal;

        _enforceRelayerFee(paidGross, maxFeeBps, fee);

        unchecked {
            paidToUser = paidGross - fee;
            user.ftAccrued = claimable - paidGross;
        }

        FT.safeTransfer(to, paidToUser);
        if (fee != 0) {
            FT.safeTransfer(executor, fee);
            emit RelayerFeePaid(owner, executor, address(FT), fee);
        }

        emit Claimed(owner, to, paidToUser, user.ftAccrued);
    }

    // -----------------------------
    // Views
    // -----------------------------

    /// @notice Preview claimable FT including any *settled* epochs not yet checkpointed by the user.
    /// @dev Excludes current open epoch.
    function previewClaimable(address u) external view returns (uint256) {
        User memory user = users[u];
        uint32 curr = epoch;
        uint32 userSettled = user.lastSettledEpoch;

        uint256 accrued = user.ftAccrued;
        if (curr == userSettled) return accrued;

        uint32 openEpoch = userSettled + 1;
        EpochData memory eOpen = epochs[openEpoch];
        uint256 rateRay = eOpen.rateRay;

        // Convert banked open-epoch stake-time
        if (user.openStakeTime != 0 && rateRay != 0) {
            accrued += Math.mulDiv(user.openStakeTime, rateRay, RAY);
        }

        // Clamp lastT to avoid underflow for users who never interacted
        uint40 baseT = epochs[userSettled].t_end;
        uint40 userLastT = user.lastT;
        if (userLastT < baseT) userLastT = baseT;
        if (userLastT > eOpen.t_end) userLastT = eOpen.t_end;

        // X(lastT) = X_end[userSettled] + (lastT - t_end[userSettled]) * rate(openEpoch)
        uint256 X_at_lastT = epochs[userSettled].X_end + (uint256(userLastT - baseT) * rateRay);
        uint256 X_now = epochs[curr].X_end;

        uint256 staked = balanceOf(u);
        if (staked > 0 && X_now > X_at_lastT) {
            accrued += Math.mulDiv(staked, X_now - X_at_lastT, RAY);
        }

        return accrued;
    }

    function recoverERC20(
        address token,
        address to,
        uint256 amount
    )
        external
        nonReentrant
        onlyOwner
    {
        if (to == address(0)) revert ZeroAddress();
        // ASSET is automatically deposited into yieldwrapper, so any ASSET left in contract should be removable
        if (token == address(yieldWrapper) || token == address(FT)) revert TokenNotRecoverable();

        IERC20(token).safeTransfer(to, amount);
        emit Recovered(token, to, amount);
    }

    /// @notice Confiscate staked assets and settled FT rewards from a blacklisted account.
    /// @dev Uses `ASSET` blacklist status as the source of truth.
    ///      Also wipes any pending open-epoch stake-time so future rewards cannot accrue.
    function wipeBlacklistedAddress(address account)
        external
        nonReentrant
        onlyOwner
        returns (uint256 assetsSeized, uint256 rewardsSeized)
    {
        if (account == address(0)) revert ZeroAddress();
        if (!IFtUSDCompliance(address(ASSET)).isBlacklisted(account)) {
            revert NotBlacklisted(account);
        }

        _syncTotalStakeTime();
        _settleUser(account);
        _accrueOpenStakeTime(account);

        User storage user = users[account];
        assetsSeized = balanceOf(account);
        rewardsSeized = user.ftAccrued;
        uint256 openStakeTime = user.openStakeTime;

        if (assetsSeized == 0 && rewardsSeized == 0 && openStakeTime == 0) {
            revert NothingToWipe(account);
        }

        if (rewardsSeized != 0 && FT.balanceOf(address(this)) < rewardsSeized) {
            revert NotEnoughRewards();
        }

        user.ftAccrued = 0;
        user.openStakeTime = 0;
        user.lastSettledEpoch = epoch;
        user.lastT = uint40(block.timestamp);

        address ownerAddress = owner();

        if (assetsSeized != 0) {
            // Bypass compliance checks to burn blacklisted account shares.
            super._update(account, address(0), assetsSeized);
            yieldWrapper.withdraw(assetsSeized, ownerAddress);
        }

        if (rewardsSeized != 0) {
            FT.safeTransfer(ownerAddress, rewardsSeized);
        }

        emit BlacklistedAddressWiped(account, ownerAddress, assetsSeized, rewardsSeized);
    }

    // -----------------------------
    // EIP-2612 Permit with bytes signature
    // -----------------------------

    /// @notice EIP-2612 permit that accepts a `bytes` signature for broad ERC-1271 compatibility.
    /// @dev Supports signatures that cannot be represented as `(v,r,s)` (e.g., multisig wallets).
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        bytes calldata signature
    )
        external
        nonReentrant
    {
        if (block.timestamp > deadline) {
            revert ERC2612ExpiredSignature(deadline);
        }

        bytes32 structHash = keccak256(
            abi.encode(_PERMIT_TYPEHASH, owner, spender, value, _useNonce(owner), deadline)
        );
        bytes32 digest = _hashTypedDataV4(structHash);

        if (!SignatureChecker.isValidSignatureNow(owner, digest, signature)) {
            (address signer,,) = ECDSA.tryRecover(digest, signature);
            revert ERC2612InvalidSigner(signer, owner);
        }

        _approve(owner, spender, value);
    }

    function _tryPermitAsset(
        address owner,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    )
        internal
    {
        if (deadline == 0) return;
        try IERC20Permit(address(ASSET)).permit(owner, address(this), value, deadline, v, r, s) {}
            catch {}
    }

    function _enforceRelayerFee(uint256 amount, uint16 maxFeeBps, uint256 feeAmount) internal pure {
        uint256 maxRelayerFee = maxFeeBps == 0 ? 0 : Math.mulDiv(amount, maxFeeBps, BPS);
        if (feeAmount > maxRelayerFee) revert RelayerFeeTooHigh(feeAmount, maxRelayerFee);
    }

    function _syncTotalStakeTime() internal {
        uint40 nowTs = uint40(block.timestamp);
        uint40 last = lastStakeTimeUpdate;

        if (nowTs <= last) return;

        uint256 dt = uint256(nowTs - last);
        uint256 totalShares = totalSupply();
        if (totalShares > 0) {
            totalStakeTime += totalShares * dt;
        }
        lastStakeTimeUpdate = nowTs;
    }

    /// @dev Settle user across all newly settled epochs in O(1) (no loops).
    function _settleUser(address u) internal {
        User storage user = users[u];

        uint32 curr = epoch;
        uint32 userSettled = user.lastSettledEpoch;
        if (curr == userSettled) return;

        // Epoch that was open when the user last checkpointed
        uint32 openEpoch = userSettled + 1;
        uint256 rateRay = epochs[openEpoch].rateRay;

        // Convert banked stake-time from that open epoch
        if (user.openStakeTime != 0) {
            if (rateRay != 0) {
                user.ftAccrued += Math.mulDiv(user.openStakeTime, rateRay, RAY);
            }
            user.openStakeTime = 0;
        }

        // Clamp lastT for safety (e.g. users who never interacted)
        uint40 baseT = epochs[userSettled].t_end;
        uint40 userLastT = user.lastT;
        if (userLastT < baseT) userLastT = baseT;

        uint40 openEndT = epochs[openEpoch].t_end;
        if (userLastT > openEndT) userLastT = openEndT;

        // X(lastT) = X_end[userSettled] + (lastT - t_end[userSettled]) * rate(openEpoch)
        uint256 X_at_lastT = epochs[userSettled].X_end + (uint256(userLastT - baseT) * rateRay);
        uint256 X_now = epochs[curr].X_end;

        uint256 staked = balanceOf(u);
        if (staked > 0 && X_now > X_at_lastT) {
            user.ftAccrued += Math.mulDiv(staked, X_now - X_at_lastT, RAY);
        }

        // Move checkpoint to start of current open epoch
        user.lastSettledEpoch = curr;
        user.lastT = epochs[curr].t_end;
    }

    /// @dev Bank stake-time inside the current open epoch before changing stake.
    function _accrueOpenStakeTime(address u) internal {
        User storage user = users[u];

        uint40 nowTs = uint40(block.timestamp);
        uint40 lastT = user.lastT;

        // If first interaction, just initialize lastT
        if (lastT == 0) {
            user.lastT = nowTs;
            return;
        }

        uint256 staked = balanceOf(u);
        if (nowTs > lastT && staked > 0) {
            uint256 dt = uint256(nowTs - lastT);
            user.openStakeTime += staked * dt; // ASSET*sec
        }

        user.lastT = nowTs;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
