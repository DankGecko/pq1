// SPDX-License-Identifier: MIT
pragma solidity 0.8.4; 

import "../lib/Structs.sol";

interface ICandidateHub {
  function canDelegate(address agent) external view returns(bool);
  function getRoundTag() external view returns(uint256);
  function operateMap(address operator) external view returns(uint256);
  function candidateSet(uint256 index) external view returns(Candidate memory);
}