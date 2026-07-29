// SPDX-License-Identifier: Apache2.0
pragma solidity 0.8.4;

import "./interface/IChannel.sol";
import "./interface/ICoreAgent.sol";
import "./interface/IParamSubscriber.sol";
import "./interface/ICandidateHub.sol";
import "./interface/ISystemReward.sol";
import "./interface/IStakeHub.sol";
import "./lib/Address.sol";
import "./lib/BytesToTypes.sol";
import "./lib/Memory.sol";
import "./lib/SatoshiPlusHelper.sol";
import "./System.sol";

/// This contract handles CORE staking.
contract CoreAgent is ICoreAgent, System, IParamSubscriber {

  uint256 public constant INIT_REQUIRED_COIN_DEPOSIT = 1e18;

  // minimal CORE require to stake
  uint256 public requiredCoinDeposit;

  // accrued reward of every 1 million CORE per validator on each round
  // validator => (round => 1 million CORE Reward)
  mapping(address => mapping(uint256 => uint256)) public accruedRewardMap;

  // key: delegator address
  // value: delegator info
  mapping(address => Delegator) public delegatorMap;

  // key: candidate op address
  // value: candidate info
  mapping(address => Candidate) public candidateMap;

  // This field is used to store reward of delegators
  // key: delegator address
  // value: amount of CORE tokens claimable
  mapping(address => Reward) public rewardMap;

  // roundTag is set to be timestamp / round interval,
  // the valid value should be greater than 10,000 since the chain started.
  // It is initialized to 1.
  uint256 public roundTag;

  struct CoinDelegator {
    uint256 stakedAmount;
    uint256 realtimeAmount;
    uint256 transferredAmount;
    uint256 changeRound;
  }

  struct Candidate {
    mapping(address => CoinDelegator) cDelegatorMap;
    // Staked amount on last turnround snapshot
    uint256 amount;
    // Realtime staked amount
    uint256 realtimeAmount;
    uint256[] continuousRewardEndRounds;
  }

  struct Delegator {
    address[] candidates;
    uint256 amount;
    uint256 channelAmount;
  }

  struct Reward {
    uint256 reward;
    uint256 accStakedAmount;
  }

  error NotImplemented();

  error InsufficientTokens(uint32 channelId);

  /*********************** events **************************/
  event delegatedCoin(address indexed candidate, address indexed delegator, uint256 amount, uint256 realtimeAmount);
  event undelegatedCoin(address indexed candidate, address indexed delegator, uint256 amount);
  event transferredCoin(
    address indexed sourceCandidate,
    address indexed targetCandidate,
    address indexed delegator,
    uint256 amount,
    uint256 realtimeAmount
  );
  event claimedCoinReward(address indexed delegator, uint256 amount, uint256 accStakedAmount);
  event storedCoinReward(address indexed delegator, uint256 amount, uint256 accStakedAmount);
  event collectedReward(address indexed candidate, address indexed delegator, uint256 reward, uint256 accStakedAmount);
  event storedReward(address indexed candidate, address indexed delegator, uint256 reward, uint256 accStakedAmount);

  modifier onlyInternalCall() {
    require(msg.sender == PLEDGE_AGENT_ADDR || msg.sender == CHANNEL_ADDR, "the sender must be PledgeAgent or Channel contracts");
    _;
  }

  /*********************** Init ********************************/
  function init() external onlyNotInit {
    requiredCoinDeposit = INIT_REQUIRED_COIN_DEPOSIT;
    roundTag = block.timestamp / SatoshiPlusHelper.ROUND_INTERVAL;
    alreadyInit = true;
  }

  /*********************** IAgent implementations ***************************/
  /// Receive round rewards from StakeHub, which is triggered at the beginning of turn round.
  /// @param validators List of validator operator addresses
  /// @param rewardList List of reward amount
  /// @param round The round tag
  function distributeReward(address[] calldata validators, uint256[] calldata rewardList, uint256 round) external override onlyStakeHub
  {
    uint256 validateSize = validators.length;
    require(validateSize == rewardList.length, "the length of validators and rewardList should be equal");

    uint256 historyReward;
    uint256 lastRewardRound;
    uint256 l;
    address validator;
    for (uint256 i = 0; i < validateSize; i++) {
      if (rewardList[i] == 0) {
        continue;
      }
      validator = validators[i];
      mapping(uint256 => uint256) storage m = accruedRewardMap[validator];
      Candidate storage c = candidateMap[validator];
      l = c.continuousRewardEndRounds.length;
      if (l != 0) {
        lastRewardRound = c.continuousRewardEndRounds[l - 1];
        historyReward = m[lastRewardRound];
      } else {
        historyReward = 0;
        lastRewardRound = 0;
      }
      // Calculate accrued reward of 1M Core on a validator for the round
      m[round] = historyReward + rewardList[i] * SatoshiPlusHelper.CORE_STAKE_DECIMAL / c.amount;
      if (lastRewardRound + 1 == round) {
        c.continuousRewardEndRounds[l - 1] = round;
      } else {
        c.continuousRewardEndRounds.push(round);
      }
    }
  }

  /// Get staked CORE amount
  /// @param candidates List of candidate operator addresses
  ///
  /// @return amounts List of staked CORE amounts on all candidates in the round
  /// @return totalAmount Total staked CORE on all candidates in the round
  function getStakeAmounts(address[] calldata candidates, uint256) external override view returns (uint256[] memory amounts, uint256 totalAmount) {
    uint256 candidateSize = candidates.length;
    amounts = new uint256[](candidateSize);
    for (uint256 i = 0; i < candidateSize; ++i) {
      amounts[i] = candidateMap[candidates[i]].realtimeAmount;
      totalAmount += amounts[i];
    }
  }

  /// Start new round, this is called by the StakeHub contract
  /// @param validators List of elected validators in this round
  /// @param round The new round tag
  function setNewRound(address[] calldata validators, uint256 round) external override onlyStakeHub {
    uint256 validatorSize = validators.length;
    for (uint256 i = 0; i < validatorSize; ++i) {
      Candidate storage a = candidateMap[validators[i]];
      a.amount = a.realtimeAmount;
    }
    roundTag = round;
  }

  /*********************** External methods ***************************/
  /// Delegate coin to a validator
  /// @param candidate The operator address of validator
  function delegateCoin(address candidate) external payable {
    if (!ICandidateHub(CANDIDATE_HUB_ADDR).canDelegate(candidate)) {
      revert InactiveCandidate(candidate);
    }
    require(msg.value >= requiredCoinDeposit, "delegate amount is too small");
    IStakeHub(STAKE_HUB_ADDR).onStakeChange(msg.sender);
    uint256 realtimeAmount = _delegateCoin(candidate, msg.sender, msg.value, false);
    emit delegatedCoin(candidate, msg.sender, msg.value, realtimeAmount);
  }

  /// Undelegate coin from a validator
  /// @param candidate The operator address of validator
  /// @param amount The amount of CORE to undelegate
  function undelegateCoin(address candidate, uint256 amount) public {
    amount = undelegate(candidate, msg.sender, amount);
    Address.sendValue(payable(msg.sender), amount);
  }

  /// Transfer coin stake to a new validator
  /// @param sourceCandidate The validator to transfer coin stake from
  /// @param targetCandidate The validator to transfer coin stake to
  /// @param amount The amount of CORE to transfer
  function transferCoin(address sourceCandidate, address targetCandidate, uint256 amount) public {
    if (!ICandidateHub(CANDIDATE_HUB_ADDR).canDelegate(targetCandidate)) {
      revert InactiveCandidate(targetCandidate);
    }
    if (sourceCandidate == targetCandidate) {
      revert SameCandidate(sourceCandidate);
    }
    IStakeHub(STAKE_HUB_ADDR).onStakeChange(msg.sender);
    _undelegateCoin(sourceCandidate, msg.sender, amount, true);
    uint256 newDeposit = _delegateCoin(targetCandidate, msg.sender, amount, true);

    emit transferredCoin(sourceCandidate, targetCandidate, msg.sender, amount, newDeposit);
  }

  /// Claim reward for delegator
  /// @param delegator the delegator address
  /// @param claim claim or store rewards
  /// @return reward Amount claimed
  /// @return stakedAmount1 the staked amount in the first round
  /// @return stakedAmount2 the real amount in the last round
  function claimReward(address delegator, bool claim) external override onlyStakeHub returns (uint256 reward, uint256 stakedAmount1, uint256 stakedAmount2) {
    uint256 initAmount = delegatorMap[delegator].amount;
    address[] storage candidates = delegatorMap[delegator].candidates;
    uint256 candidateSize = candidates.length;
    address candidate;
    uint256 rewardSum;
    uint256 s1;
    uint256 s2;
    for (uint256 i = candidateSize; i != 0; --i) {
      candidate = candidates[i - 1];
      CoinDelegator storage cd = candidateMap[candidate].cDelegatorMap[delegator];
      (reward, s1, s2) = _collectRewardFromCandidate(candidate, cd);
      rewardSum += reward;
      stakedAmount1 += s1;
      stakedAmount2 += s2;
      if (reward != 0) {
        if (claim) {
          emit collectedReward(candidate, delegator, reward, 0);
        } else {
          emit storedReward(candidate, delegator, reward, 0);
        }
      }
      if (cd.realtimeAmount == 0 && cd.transferredAmount == 0) {
        _removeDelegation(delegator, candidate);
      }
    }

    if (rewardSum != 0) {
      rewardSum = IChannel(CHANNEL_ADDR).payCommissions(delegator, initAmount, rewardSum);
    }

    reward = rewardMap[delegator].reward;
    if (reward != 0 || rewardMap[delegator].accStakedAmount != 0) {
      delete rewardMap[delegator];
    }
    reward += rewardSum;
    if (reward != 0) {
      if (claim) {
        emit claimedCoinReward(delegator, reward, 0);
      } else {
        emit storedCoinReward(delegator, reward, 0);
      }
    }
  }

  /// Claim reward for delegator
  function claimReward(address, uint256, uint256, bool) external override pure returns (uint256, int256) {
    revert NotImplemented();
  }

  /// for backward compatibility - allow users to unstake through PledgeAgent
  /// support channel from v1.0.20
  /// @param candidate the validator candidate address
  /// @param delegator the delegator address
  /// @param channelId the channel id, 0 represents from PledgeAgent
  function proxyDelegate(address candidate, address delegator, uint32 channelId) external payable override onlyInternalCall {
    if (!ICandidateHub(CANDIDATE_HUB_ADDR).canDelegate(candidate)) {
      revert InactiveCandidate(candidate);
    }
    require(msg.value >= requiredCoinDeposit, "delegate amount is too small");
    IStakeHub(STAKE_HUB_ADDR).onStakeChange(delegator);
    uint256 realtimeAmount = _delegateCoin(candidate, delegator, msg.value, false);
    emit delegatedCoin(candidate, delegator, msg.value, realtimeAmount);
    if (channelId != 0) {
      delegatorMap[delegator].channelAmount += msg.value;
    }
  }

  /// for backward compatibility - allow users to unstake through PledgeAgent
  /// support channel from v1.0.20
  /// @param candidate the validator candidate address
  /// @param delegator the delegator address
  /// @param amount the amount of CORE to unstake
  function proxyUnDelegate(address candidate, address delegator, uint256 amount) external override onlyInternalCall returns(uint256) {
    amount = undelegate(candidate, delegator, amount);
    Address.sendValue(payable(PLEDGE_AGENT_ADDR), amount);
    return amount;
  }

  /// for backward compatibility - allow users to transfer stake through PledgeAgent
  /// @param sourceCandidate the validator candidate address to transfer from
  /// @param targetCandidate the validator candidate address to transfer to
  /// @param delegator the delegator address
  /// @param amount the amount of CORE to unstake
  function proxyTransfer(address sourceCandidate, address targetCandidate, address delegator, uint256 amount) external onlyInternalCall {
    if (!ICandidateHub(CANDIDATE_HUB_ADDR).canDelegate(targetCandidate)) {
      revert InactiveCandidate(targetCandidate);
    }
    if (sourceCandidate == targetCandidate) {
      revert SameCandidate(sourceCandidate);
    }
    IStakeHub(STAKE_HUB_ADDR).onStakeChange(delegator);
    if (amount == 0) {
      amount = candidateMap[sourceCandidate].cDelegatorMap[delegator].realtimeAmount;
    }
    _undelegateCoin(sourceCandidate, delegator, amount, true);
    uint256 newDeposit = _delegateCoin(targetCandidate, delegator, amount, true);

    emit transferredCoin(sourceCandidate, targetCandidate, delegator, amount, newDeposit);
  }

  /*********************** Internal methods ***************************/
  /// delegate CORE tokens
  /// @param candidate the validator candidate to delegate to
  /// @param delegator the delegator address
  /// @param amount the amount of CORE 
  /// @param isTransfer is called from transfer workflow
  function _delegateCoin(address candidate, address delegator, uint256 amount, bool isTransfer) internal returns (uint256) {
    Candidate storage a = candidateMap[candidate];
    CoinDelegator storage cd = a.cDelegatorMap[delegator];
    uint256 changeRound = cd.changeRound;
    if (changeRound == 0) {
      cd.changeRound = roundTag;
      delegatorMap[delegator].candidates.push(candidate);
    }
    a.realtimeAmount += amount;
    cd.realtimeAmount += amount;
    if (!isTransfer) {
      delegatorMap[delegator].amount += amount;
    }

    return cd.realtimeAmount;
  }


  /// for backward compatibility - allow users to unstake through PledgeAgent
  /// support channel from v1.0.20
  /// @param candidate the validator candidate address
  /// @param delegator the delegator address
  /// @param amount the amount of CORE to unstake
  function undelegate(address candidate, address delegator, uint256 amount) internal returns(uint256) {
    IStakeHub(STAKE_HUB_ADDR).onStakeChange(delegator);
    if (amount == 0) {
      amount = candidateMap[candidate].cDelegatorMap[delegator].realtimeAmount;
    }

    uint256 dAmount = _undelegateCoin(candidate, delegator, amount, false);
    _deductTransferredAmount(delegator, dAmount);
    emit undelegatedCoin(candidate, delegator, amount);

    Delegator storage d = delegatorMap[delegator];
    uint256 undelegateAmount = amount;
    if (amount > d.channelAmount) {
      undelegateAmount = d.channelAmount;
      d.channelAmount = 0;
    } else {
      d.channelAmount -= amount;
    }
    if (undelegateAmount != 0) {
      IChannel(CHANNEL_ADDR).onUndelegateCoin(delegator, undelegateAmount);
    }

    return amount;
  }

  /// undelegate CORE tokens
  /// @param candidate the validator candidate to delegate to
  /// @param delegator the delegator address
  /// @param amount the amount of CORE 
  /// @param isTransfer is called from transfer workflow
  /// @return undelegatedNewAmount the amount minuses the reduced staked amount.
  function _undelegateCoin(address candidate, address delegator, uint256 amount, bool isTransfer) internal returns (uint256 undelegatedNewAmount) {
    require(amount != 0, 'Undelegate zero coin');
    Candidate storage a = candidateMap[candidate];
    CoinDelegator storage cd = a.cDelegatorMap[delegator];
    uint256 changeRound = cd.changeRound;
    require(changeRound != 0, 'no delegator information found');

    uint256 realtimeAmount = cd.realtimeAmount;
    require(realtimeAmount >= amount, "Not enough staked tokens");
    if (amount != realtimeAmount) {
      require(amount >= requiredCoinDeposit, "undelegate amount is too small");
      require(cd.realtimeAmount - amount >= requiredCoinDeposit, "remain amount is too small");
    }

    uint256 stakedAmount = cd.stakedAmount;
    a.realtimeAmount -= amount;
    if (isTransfer) {
      if (stakedAmount > amount) {
        cd.transferredAmount += amount;
      } else if (stakedAmount != 0) {
        cd.transferredAmount += stakedAmount;
      }
    } else {
      delegatorMap[delegator].amount -= amount;
    }
    if (!isTransfer && cd.realtimeAmount == amount && cd.transferredAmount == 0) {
      _removeDelegation(delegator, candidate);
    } else {
      cd.realtimeAmount -= amount;
      if (stakedAmount > amount) {
        cd.stakedAmount -= amount;
      } else if (stakedAmount != 0) {
        cd.stakedAmount = 0;
      }
    }
    undelegatedNewAmount = amount - (stakedAmount - cd.stakedAmount);
  }

  function _deductTransferredAmount(address delegator, uint256 amount) internal {
    Delegator storage d = delegatorMap[delegator];
    address[] storage candidates = d.candidates;
    address candidate;
    uint256 transferredAmount;
    for (uint256 i = candidates.length; i != 0; --i) {
      candidate = candidates[i - 1];
      CoinDelegator storage cd = candidateMap[candidate].cDelegatorMap[delegator];
      transferredAmount = cd.transferredAmount;
      if (transferredAmount != 0) {
        if (transferredAmount <= amount) {
          amount -= transferredAmount;
          cd.transferredAmount = 0;
          if (cd.realtimeAmount == 0) {
            delete candidateMap[candidate].cDelegatorMap[delegator];
            if (i < candidates.length) {
              d.candidates[i-1] = d.candidates[candidates.length-1];
            }
            d.candidates.pop();
          }
        } else {
          cd.transferredAmount -= amount;
          break;
        }
      }
    }
  }

  /// Exposed for staking API to do readonly calls, restricted to onlyStakeHub() for safety reasons.
  /// @param delegator the address of delegator
  /// @return candidates the validator list with stakes
  /// @return rewards rewards on each validator
  /// @return stakedAmount1 the staked amount in the first round
  /// @return stakedAmount2 the staked amount in the last round
  function calculateRewards(address delegator) external onlyStakeHub returns (address[] memory candidates, uint256[] memory rewards, uint256 stakedAmount1, uint256 stakedAmount2) {
    address candidate;
    uint256 size = delegatorMap[delegator].candidates.length;
    rewards = new uint256[](size);
    uint256 s1;
    uint256 s2;
    for (uint256 i = 0; i < size; ++i) {
      candidate = delegatorMap[delegator].candidates[i];
      CoinDelegator storage cd = candidateMap[candidate].cDelegatorMap[delegator];
      (rewards[i], s1, s2) = _collectRewardFromCandidate(candidate, cd);
      stakedAmount1 += s1;
      stakedAmount2 += s2;
    }
    return (delegatorMap[delegator].candidates, rewards, stakedAmount1, stakedAmount2);
  }

  /// collect reward from a validator candidate
  /// @param candidate the validator candidate to collect reward from
  /// @param cd the structure stores user CORE stake information
  /// @return reward the amount of rewards collected
  /// @return stakedAmount1 the staked amount in the first round
  /// @return stakedAmount2 the staked amount in the last round
  function _collectRewardFromCandidate(address candidate, CoinDelegator storage cd) internal returns (uint256 reward, uint256 stakedAmount1, uint256 stakedAmount2) {
    uint256 stakedAmount = cd.stakedAmount;
    uint256 realtimeAmount = cd.realtimeAmount;
    uint256 transferredAmount = cd.transferredAmount;

    uint256 changeRound = cd.changeRound;
    require(changeRound != 0, "invalid delegator");
    uint256 lastRound = roundTag - 1;

    if (changeRound <= lastRound) {
      uint256 changeRoundReward = _getRoundAccruedReward(candidate, changeRound);
      uint256 lastChangeRoundReward = _getRoundAccruedReward(candidate, changeRound - 1);
      stakedAmount1 = stakedAmount + transferredAmount;
      reward = stakedAmount1 * (changeRoundReward - lastChangeRoundReward) / SatoshiPlusHelper.CORE_STAKE_DECIMAL;

      if (changeRound < lastRound) {
        stakedAmount2 = realtimeAmount;
        uint256 lastRoundReward = _getRoundAccruedReward(candidate, lastRound);
        reward += stakedAmount2 * (lastRoundReward - changeRoundReward) / SatoshiPlusHelper.CORE_STAKE_DECIMAL;
      } else {
        stakedAmount2 = stakedAmount1;
      }

      if (transferredAmount != 0) {
        cd.transferredAmount = 0;
      }
      if (realtimeAmount != stakedAmount) {
        cd.stakedAmount = realtimeAmount;
      }
      cd.changeRound = roundTag;
    }
  }

  /// remove delegate record of a candidate/delegator pair
  /// @param delegator the delegator address
  /// @param candidate the validator candidate address
  function _removeDelegation(address delegator, address candidate) internal {
    Delegator storage d = delegatorMap[delegator];
    uint256 l = d.candidates.length;
    for (uint256 i = 0; i < l; ++i) {
      if (d.candidates[i] == candidate) {
        if (i + 1 < l) {
          d.candidates[i] = d.candidates[l-1];
        }
        d.candidates.pop();
        break;
      }
    }
    delete candidateMap[candidate].cDelegatorMap[delegator];
  }

  /// get accrued rewards of a validator candidate on a given round
  /// @param candidate validator candidate address
  /// @param round the round to calculate rewards
  /// @return reward the amount of rewards
  function _getRoundAccruedReward(address candidate, uint256 round) internal returns (uint256 reward) {
    reward = accruedRewardMap[candidate][round];
    if (reward != 0) {
      return reward;
    }
    
    // there might be no rewards for a candidate on a given round if it is unelected or jailed, etc
    // the accrued reward map will only be updated when reward is distributed to the candidate on that round
    // in that case, the accrued reward for round N == a round smaller but also closest to N
    // here we use binary search to get that round efficiently
    Candidate storage c = candidateMap[candidate];
    uint256 b = c.continuousRewardEndRounds.length;
    if (b == 0) {
      return 0;
    }
    b -= 1;
    uint256 a;
    uint256 m;
    uint256 targetRound;
    uint256 t;
    while (a <= b) {
      m = (a + b) / 2;
      t = c.continuousRewardEndRounds[m];
      if (t < round) {
        targetRound = t;
        a = m + 1;
      } else if (m == 0) {
        return 0;
      } else {
        b = m - 1;
      }
    }
    if (targetRound != 0) {
      reward = accruedRewardMap[candidate][targetRound];
      accruedRewardMap[candidate][round] = reward;
    }
    return reward;
  }
  
  /*********************** Governance ********************************/
  /// Update parameters through governance vote
  /// @param key The name of the parameter
  /// @param value the new value set to the parameter
  function updateParam(string calldata key, bytes calldata value) external override onlyInit onlyGov {
    if (value.length != 32) {
      revert MismatchParamLength(key);
    }
    if (Memory.compareStrings(key, "requiredCoinDeposit")) {
      uint256 newRequiredCoinDeposit = BytesToTypes.bytesToUint256(32, value);
      if (newRequiredCoinDeposit == 0) {
        revert OutOfBounds(key, newRequiredCoinDeposit, 1, type(uint256).max);
      }
      requiredCoinDeposit = newRequiredCoinDeposit;
    } else {
      revert UnsupportedGovParam(key);
    }
    emit paramChange(key, value);
  }

  /*********************** Public view methods ********************************/
  /// Get delegator information
  /// @param candidate The operator address of candidate
  /// @param delegator The delegator address
  /// @return CoinDelegator Information of the delegator
  function getDelegator(address candidate, address delegator) external view returns (CoinDelegator memory) {
    return candidateMap[candidate].cDelegatorMap[delegator];
  }

  /// Get delegator information
  /// @param delegator The delegator address
  /// return the delegated candidates list of the delegator
  function getCandidateListByDelegator(address delegator) external view returns (address[] memory) {
    return delegatorMap[delegator].candidates;
  }

  function getContinuousRewardEndRoundsByCandidate(address candidate) external view returns(uint256[] memory) {
    return candidateMap[candidate].continuousRewardEndRounds;
  }
}