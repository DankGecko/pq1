// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AgentIdentityRegistry
/// @notice Registre universel d'identité pour agents autonomes — digitaux, physiques, et hybrides
/// @dev Implémente ERC-8004 + prépare ERC-8XXX

contract AgentIdentityRegistry {

    enum AgentType { DIGITAL, PHYSICAL, HYBRID }
    enum AgentStatus { PENDING, ACTIVE, SUSPENDED, REVOKED }
    enum Capability { TRADE, LEND, BORROW, MANAGE_VAULT, CERTIFY, DELEGATE, PHYSICAL_OPS, SCORE }

    struct AgentIdentity {
        address agentWallet;
        address ownerWallet;
        AgentType agentType;
        AgentStatus status;
        string name;
        string version;
        address mandateRegistry;
        address parentAgent;
        uint256 minColScore;
        uint256 maxLTV;
        uint256 reputationScore;
        bool isActive;
    }

    struct AgentMeta {
        string manufacturer;
        string serialNumber;
        uint256 totalDecisions;
        uint256 totalValueManaged;
        uint256 incidents;
        uint256 registeredAt;
        uint256 lastActivityAt;
    }

    struct SubMandate {
        address parentAgent;
        address subAgent;
        uint256 maxValue;
        uint256 validUntil;
        Capability[] capabilities;
        bool isActive;
    }

    struct Decision {
        address agent;
        string action;
        address assetInvolved;
        uint256 value;
        uint256 timestamp;
        bool success;
        bytes32 txHash;
    }

    address public owner;
    address public auditorRegistry;
    address public colOracle;

    mapping(address => AgentIdentity) public agents;
    mapping(address => AgentMeta) public agentMeta;
    mapping(address => Capability[]) public agentCapabilities;
    mapping(address => SubMandate[]) public subMandates;
    mapping(address => Decision[]) public decisionHistory;
    mapping(address => bool) public isRegistered;
    mapping(string => address) public serialToAgent;

    address[] public agentList;

    event AgentRegistered(address indexed agentWallet, address indexed ownerWallet, AgentType agentType, string name);
    event AgentStatusUpdated(address indexed agentWallet, AgentStatus oldStatus, AgentStatus newStatus, string reason);
    event SubMandateGranted(address indexed parentAgent, address indexed subAgent, uint256 maxValue, uint256 validUntil);
    event SubMandateRevoked(address indexed parentAgent, address indexed subAgent, string reason);
    event DecisionRecorded(address indexed agent, string action, address assetInvolved, uint256 value, bool success);
    event ReputationUpdated(address indexed agent, uint256 reputationBefore, uint256 reputationAfter, string reason);
    event IncidentRecorded(address indexed agent, string description, uint256 totalIncidents);

    modifier onlyOwner() {
        require(msg.sender == owner, "AgentIdentityRegistry: not owner");
        _;
    }

    modifier onlyAuthorized() {
        require(msg.sender == owner || msg.sender == auditorRegistry, "AgentIdentityRegistry: not authorized");
        _;
    }

    modifier agentExists(address _agent) {
        require(isRegistered[_agent], "AgentIdentityRegistry: agent not found");
        _;
    }

    modifier onlyAgentOwner(address _agent) {
        require(agents[_agent].ownerWallet == msg.sender || msg.sender == owner, "AgentIdentityRegistry: not agent owner");
        _;
    }

    constructor(address _auditorRegistry, address _colOracle) {
        owner = msg.sender;
        auditorRegistry = _auditorRegistry;
        colOracle = _colOracle;
    }

    function registerAgent(
        address _agentWallet,
        address _ownerWallet,
        AgentType _agentType,
        string calldata _name,
        string calldata _version,
        string calldata _manufacturer,
        string calldata _serialNumber,
        uint256 _minColScore,
        uint256 _maxLTV
    ) external onlyOwner {
        require(_agentWallet != address(0), "AgentIdentityRegistry: zero agent address");
        require(_ownerWallet != address(0), "AgentIdentityRegistry: zero owner address");
        require(!isRegistered[_agentWallet], "AgentIdentityRegistry: already registered");
        require(_minColScore <= 1000, "AgentIdentityRegistry: invalid COL score");
        require(_maxLTV <= 10000, "AgentIdentityRegistry: invalid LTV");

        if (_agentType == AgentType.PHYSICAL || _agentType == AgentType.HYBRID) {
            if (bytes(_serialNumber).length > 0) {
                require(serialToAgent[_serialNumber] == address(0), "AgentIdentityRegistry: serial already registered");
                serialToAgent[_serialNumber] = _agentWallet;
            }
        }

        agents[_agentWallet] = AgentIdentity({
            agentWallet: _agentWallet,
            ownerWallet: _ownerWallet,
            agentType: _agentType,
            status: AgentStatus.ACTIVE,
            name: _name,
            version: _version,
            mandateRegistry: address(0),
            parentAgent: address(0),
            minColScore: _minColScore,
            maxLTV: _maxLTV,
            reputationScore: 750,
            isActive: true
        });

        agentMeta[_agentWallet] = AgentMeta({
            manufacturer: _manufacturer,
            serialNumber: _serialNumber,
            totalDecisions: 0,
            totalValueManaged: 0,
            incidents: 0,
            registeredAt: block.timestamp,
            lastActivityAt: block.timestamp
        });

        isRegistered[_agentWallet] = true;
        agentList.push(_agentWallet);

        emit AgentRegistered(_agentWallet, _ownerWallet, _agentType, _name);
    }

    function setMandateRegistry(address _agent, address _mandateRegistry)
        external onlyAgentOwner(_agent) agentExists(_agent)
    {
        require(_mandateRegistry != address(0), "AgentIdentityRegistry: zero address");
        agents[_agent].mandateRegistry = _mandateRegistry;
    }

    function setCapabilities(address _agent, Capability[] calldata _capabilities)
        external onlyAgentOwner(_agent) agentExists(_agent)
    {
        delete agentCapabilities[_agent];
        for (uint256 i = 0; i < _capabilities.length; i++) {
            agentCapabilities[_agent].push(_capabilities[i]);
        }
    }

    function hasCapability(address _agent, Capability _capability) public view returns (bool) {
        Capability[] memory caps = agentCapabilities[_agent];
        for (uint256 i = 0; i < caps.length; i++) {
            if (caps[i] == _capability) return true;
        }
        return false;
    }

    function grantSubMandate(
        address _subAgent,
        uint256 _maxValue,
        uint256 _validityDays,
        Capability[] calldata _capabilities
    ) external agentExists(msg.sender) agentExists(_subAgent) {
        require(hasCapability(msg.sender, Capability.DELEGATE), "AgentIdentityRegistry: cannot delegate");
        require(_validityDays > 0 && _validityDays <= 365, "AgentIdentityRegistry: invalid validity");

        for (uint256 i = 0; i < _capabilities.length; i++) {
            require(hasCapability(msg.sender, _capabilities[i]), "AgentIdentityRegistry: capability not owned");
        }

        SubMandate memory subMandate = SubMandate({
            parentAgent: msg.sender,
            subAgent: _subAgent,
            maxValue: _maxValue,
            validUntil: block.timestamp + (_validityDays * 1 days),
            capabilities: _capabilities,
            isActive: true
        });

        subMandates[msg.sender].push(subMandate);
        agents[_subAgent].parentAgent = msg.sender;

        emit SubMandateGranted(msg.sender, _subAgent, _maxValue, subMandate.validUntil);
    }

    function revokeSubMandate(address _subAgent, string calldata _reason)
        external agentExists(msg.sender)
    {
        SubMandate[] storage mandates = subMandates[msg.sender];
        for (uint256 i = 0; i < mandates.length; i++) {
            if (mandates[i].subAgent == _subAgent && mandates[i].isActive) {
                mandates[i].isActive = false;
                agents[_subAgent].parentAgent = address(0);
                emit SubMandateRevoked(msg.sender, _subAgent, _reason);
                return;
            }
        }
        revert("AgentIdentityRegistry: sub-mandate not found");
    }

    function recordDecision(
        address _agent,
        string calldata _action,
        address _assetInvolved,
        uint256 _value,
        bool _success,
        bytes32 _txHash
    ) external onlyAuthorized agentExists(_agent) {
        decisionHistory[_agent].push(Decision({
            agent: _agent,
            action: _action,
            assetInvolved: _assetInvolved,
            value: _value,
            timestamp: block.timestamp,
            success: _success,
            txHash: _txHash
        }));

        agentMeta[_agent].totalDecisions++;
        agentMeta[_agent].totalValueManaged += _value;
        agentMeta[_agent].lastActivityAt = block.timestamp;

        _updateReputation(_agent, _success, _success ? "Successful decision" : "Failed decision");

        emit DecisionRecorded(_agent, _action, _assetInvolved, _value, _success);
    }

    function recordIncident(address _agent, string calldata _description)
        external onlyAuthorized agentExists(_agent)
    {
        agentMeta[_agent].incidents++;
        _updateReputation(_agent, false, _description);
        emit IncidentRecorded(_agent, _description, agentMeta[_agent].incidents);
    }

    function _updateReputation(address _agent, bool _positive, string memory _reason) internal {
        uint256 reputationBefore = agents[_agent].reputationScore;

        if (_positive) {
            agents[_agent].reputationScore = _min(1000, agents[_agent].reputationScore + 5);
        } else {
            if (agents[_agent].reputationScore >= 50) {
                agents[_agent].reputationScore -= 50;
            } else {
                agents[_agent].reputationScore = 0;
            }
        }

        if (agents[_agent].reputationScore < 300 && agents[_agent].status == AgentStatus.ACTIVE) {
            agents[_agent].status = AgentStatus.SUSPENDED;
            agents[_agent].isActive = false;
            emit AgentStatusUpdated(_agent, AgentStatus.ACTIVE, AgentStatus.SUSPENDED, "Reputation below threshold");
        }

        emit ReputationUpdated(_agent, reputationBefore, agents[_agent].reputationScore, _reason);
    }

    function updateAgentStatus(address _agent, AgentStatus _newStatus, string calldata _reason)
        external onlyOwner agentExists(_agent)
    {
        AgentStatus oldStatus = agents[_agent].status;
        agents[_agent].status = _newStatus;
        agents[_agent].isActive = (_newStatus == AgentStatus.ACTIVE);
        emit AgentStatusUpdated(_agent, oldStatus, _newStatus, _reason);
    }

    function updateFirmware(address _agent, string calldata _newVersion)
        external onlyAgentOwner(_agent) agentExists(_agent)
    {
        require(
            agents[_agent].agentType == AgentType.PHYSICAL || agents[_agent].agentType == AgentType.HYBRID,
            "AgentIdentityRegistry: not a physical agent"
        );
        agents[_agent].version = _newVersion;
        agentMeta[_agent].lastActivityAt = block.timestamp;
    }

    function transferOwnership(address _newOwner) external onlyOwner {
        require(_newOwner != address(0), "AgentIdentityRegistry: zero address");
        owner = _newOwner;
    }

    function getAgent(address _agent) external view agentExists(_agent) returns (AgentIdentity memory) {
        return agents[_agent];
    }

    function getAgentMeta(address _agent) external view agentExists(_agent) returns (AgentMeta memory) {
        return agentMeta[_agent];
    }

    function canActOn(address _agent, uint256 _colScore, uint256 _ltv)
        external view agentExists(_agent)
        returns (bool allowed, string memory reason)
    {
        AgentIdentity memory agent = agents[_agent];
        if (!agent.isActive) return (false, "Agent is not active");
        if (agent.status != AgentStatus.ACTIVE) return (false, "Agent is suspended or revoked");
        if (_colScore < agent.minColScore) return (false, "COL score below agent minimum");
        if (_ltv > agent.maxLTV) return (false, "LTV exceeds agent maximum");
        if (agent.reputationScore < 300) return (false, "Reputation too low");
        return (true, "Agent authorized");
    }

    function getReputation(address _agent)
        external view agentExists(_agent)
        returns (uint256 reputationScore, uint256 totalDecisions, uint256 totalValueManaged, uint256 incidents, AgentType agentType)
    {
        return (
            agents[_agent].reputationScore,
            agentMeta[_agent].totalDecisions,
            agentMeta[_agent].totalValueManaged,
            agentMeta[_agent].incidents,
            agents[_agent].agentType
        );
    }

    function getActiveSubMandates(address _agent)
        external view agentExists(_agent)
        returns (SubMandate[] memory)
    {
        SubMandate[] memory all = subMandates[_agent];
        uint256 count = 0;
        for (uint256 i = 0; i < all.length; i++) {
            if (all[i].isActive && block.timestamp <= all[i].validUntil) count++;
        }
        SubMandate[] memory active = new SubMandate[](count);
        uint256 index = 0;
        for (uint256 i = 0; i < all.length; i++) {
            if (all[i].isActive && block.timestamp <= all[i].validUntil) {
                active[index++] = all[i];
            }
        }
        return active;
    }

    function getDecisionHistory(address _agent)
        external view agentExists(_agent)
        returns (Decision[] memory)
    {
        return decisionHistory[_agent];
    }

    function getAgentsByType(AgentType _type) external view returns (address[] memory) {
        uint256 count = 0;
        for (uint256 i = 0; i < agentList.length; i++) {
            if (agents[agentList[i]].agentType == _type) count++;
        }
        address[] memory result = new address[](count);
        uint256 index = 0;
        for (uint256 i = 0; i < agentList.length; i++) {
            if (agents[agentList[i]].agentType == _type) {
                result[index++] = agentList[i];
            }
        }
        return result;
    }

    function getAgentBySerial(string calldata _serialNumber) external view returns (address) {
        return serialToAgent[_serialNumber];
    }

    function getAgentCount() external view returns (uint256) {
        return agentList.length;
    }

    function _min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}

