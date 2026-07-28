// SPDX-License-Identifier: BUSL-1.1
// SPDX-FileCopyrightText: 2024 Kiln <contact@kiln.fi>
//
// ██╗  ██╗██╗██╗     ███╗   ██╗
// ██║ ██╔╝██║██║     ████╗  ██║
// █████╔╝ ██║██║     ██╔██╗ ██║
// ██╔═██╗ ██║██║     ██║╚██╗██║
// ██║  ██╗██║███████╗██║ ╚████║
// ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═══╝
//
pragma solidity 0.8.22;

import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

import {Splitter} from "./Splitter.sol";
import {Operator} from "./Operator.sol";

/// @title Factory
/// @notice Helper contract in charge of creating new Operator and Splitter contracts
contract Factory is Ownable2Step {
    /// @notice The implementation of the Splitter contract
    /// @dev Used with the Clones library to create new Splitter instances
    Splitter public immutable IMPLEMENTATION;

    /// @notice The list of Operator contracts
    mapping(address => bool) public isOperator;

    /// @notice Emitted when a new Splitter is created
    /// @param splitter The new Splitter contract
    /// @param operator The Operator contract that will receive a portion of the funds
    /// @param owner The owner of the contract
    /// @param salt The salt used to create the deterministic address
    event NewSplitter(Splitter splitter, Operator operator, address owner, bytes32 salt);

    /// @notice Emitted when a new Operator is created
    /// @param operator The new Operator contract
    /// @param owner The owner of the contract
    /// @param operatorFee The fee that is taken on each Splitter
    /// @param recipients The list of recipients
    /// @param percents The list of percentages for each recipient
    event NewOperator(Operator operator, address owner, uint256 operatorFee, address[] recipients, uint256[] percents);

    /// @notice Emitted when the provided operator address is invalid
    error InvalidOperatorAddress();

    /// @notice Emitted when a subcall reverts
    /// @param revertData The revert data
    error SubCallRevert(bytes revertData);

    /// @notice Emitted when the provided implementation address is invalid
    error InvalidImplementationAddress();

    /// @param _owner The owner of the contract
    /// @param implementation The implementation of the Splitter contract
    constructor(address _owner, Splitter implementation) Ownable(_owner) {
        if (address(implementation) == address(0) || address(implementation).code.length == 0) {
            revert InvalidImplementationAddress();
        }
        IMPLEMENTATION = implementation;
    }

    /// @notice Creates a new Operator contract
    /// @param _owner The owner of the contract
    /// @param _name The name of the Operator
    /// @param _operatorFee The fee that is taken on each Splitter
    /// @param _maximumOperatorFee The maximum fee that can be configured on the Operator
    /// @param _recipients The list of recipients, sorted in ascending order without duplicates
    /// @param _percents The list of percentages for each recipient
    function createOperator(
        address _owner,
        string calldata _name,
        uint256 _operatorFee,
        uint256 _maximumOperatorFee,
        address[] calldata _recipients,
        uint256[] calldata _percents
    ) external onlyOwner returns (Operator newOperator) {
        newOperator = new Operator(_owner, _name, _operatorFee, _maximumOperatorFee, _recipients, _percents);
        isOperator[address(newOperator)] = true;
        emit NewOperator(newOperator, _owner, _operatorFee, _recipients, _percents);
    }

    /// @notice Creates a new Splitter contract
    /// @param operator The Operator contract that will receive a portion of the funds
    /// @param salt The salt used to create the deterministic address
    /// @return The new Splitter contract
    function createSplitter(Operator operator, bytes32 salt) external returns (Splitter) {
        return _createSplitter(operator, salt);
    }

    /// @notice Creates a new Splitter contract and calls an address with the provided data and value
    /// @param operator The Operator contract that will receive a portion of the funds
    /// @param salt The salt used to create the deterministic address
    /// @param callAddress The address to call
    /// @param data The calldata to send
    /// @return newSplitter The new Splitter contract
    function createSplitterAndCall(Operator operator, bytes32 salt, address callAddress, bytes calldata data)
        external
        payable
        returns (Splitter newSplitter)
    {
        newSplitter = _createSplitter(operator, salt);
        (bool success, bytes memory rdata) = callAddress.call{value: msg.value}(data);
        if (!success) {
            revert SubCallRevert(rdata);
        }
    }

    /// @notice Predicts the address of a new Splitter contract
    /// @param operator The Operator contract that will receive a portion of the funds
    /// @param owner The owner of the contract
    /// @return The Splitter contract address for the given parameters
    function predictSplitter(Operator operator, address owner, bytes32 salt) external view returns (address) {
        return Clones.predictDeterministicAddress(
            address(IMPLEMENTATION), keccak256(abi.encodePacked(operator, owner, salt))
        );
    }

    /// @notice Internal utility function to create a new Splitter contract
    /// @param operator The Operator contract that will receive a portion of the funds
    /// @param salt The salt used to create the deterministic address
    /// @return newSplitter The new Splitter contract
    function _createSplitter(Operator operator, bytes32 salt) internal returns (Splitter newSplitter) {
        if (!isOperator[address(operator)]) {
            revert InvalidOperatorAddress();
        }
        newSplitter = Splitter(
            payable(
                Clones.cloneDeterministic(
                    address(IMPLEMENTATION), keccak256(abi.encodePacked(operator, msg.sender, salt))
                )
            )
        );
        newSplitter.init(operator, msg.sender);
        emit NewSplitter(newSplitter, operator, msg.sender, salt);
    }
}
