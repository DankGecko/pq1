// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AssetIdentityRegistry
/// @notice Layer 0 — Lien cryptographique entre un actif physique réel et son token on-chain
/// @dev Résout le problème fondamental : n'importe qui peut créer un token qui prétend
///      représenter de l'or, un appartement, ou un GPU. Ce registre ferme cette faille.

contract AssetIdentityRegistry {

    // ═══════════════════════════════════════════════════════════
    // TYPES
    // ═══════════════════════════════════════════════════════════

    enum AssetClass {
        BONDS,          // ISIN + CUSIP
        EQUITIES,       // ISIN + CUSIP
        REAL_ESTATE,    // Cadastre / Deed number
        PRECIOUS_METALS, // LBMA bar serial number
        CARBON_CREDITS, // Gold Standard / Verra serial
        PRIVATE_EQUITY, // Company registration number
        PHYSICAL_ASSETS, // Véhicules, GPU, infrastructure DePIN
        COMMODITIES,    // LME / CBOT reference
        PRIVATE_CREDIT, // Loan agreement reference
        DIGITAL_ASSETS  // On-chain native — pas de lien physique requis
    }

    enum BackingType {
        PHYSICAL_BACKED,    // Token backé physiquement 1:1
        SYNTHETIC_EXPOSURE, // Exposition synthétique — risque différent
        FRACTIONAL,         // Fraction d'un actif physique
        POOLED              // Pool d'actifs physiques
    }

    struct AssetIdentity {
        address tokenAddress;       // Adresse du token on-chain
        AssetClass assetClass;      // Classe d'actif
        BackingType backingType;    // Type de backing
        string legalIdentifier;     // ISIN / LBMA serial / Cadastre / Gold Standard
        string jurisdiction;        // FR · US · SG · UK · etc.
        string custodian;           // Nom du custodian (Brinks, LBMA vault, etc.)
        address registeredBy;       // Auditeur qui a enregistré l'identité
        uint256 registeredAt;       // Timestamp d'enregistrement
        uint256 updatedAt;          // Dernière mise à jour
        bool isActive;              // Actif ou révoqué
        bool isDuplicate;           // Flag double comptage détecté
    }

    struct CrossChainRecord {
        uint256 chainId;
        address tokenAddress;
        bool isActive;
    }

    // ═══════════════════════════════════════════════════════════
    // STATE
    // ═══════════════════════════════════════════════════════════

    address public owner;
    address public auditorRegistry;     // AuditorRegistry.sol

    // Token address → AssetIdentity
    mapping(address => AssetIdentity) public identities;

    // Legal identifier → token addresses (détection double comptage)
    mapping(string => address[]) public identifierToTokens;

    // Legal identifier → exists
    mapping(string => bool) public identifierExists;

    // Token address → cross-chain records
    mapping(address => CrossChainRecord[]) public crossChainRecords;

    // Token address → is registered
    mapping(address => bool) public isRegistered;

    address[] public assetList;

    // ═══════════════════════════════════════════════════════════
    // EVENTS
    // ═══════════════════════════════════════════════════════════

    event AssetRegistered(
        address indexed tokenAddress,
        AssetClass assetClass,
        BackingType backingType,
        string legalIdentifier,
        string jurisdiction,
        address registeredBy
    );

    event DuplicateDetected(
        address indexed tokenAddress,
        string legalIdentifier,
        address existingToken,
        string reason
    );

    event AssetRevoked(
        address indexed tokenAddress,
        string reason
    );

    event CrossChainRecordAdded(
        address indexed tokenAddress,
        uint256 chainId,
        address crossChainTokenAddress
    );

    event IdentityUpdated(
        address indexed tokenAddress,
        string field,
        address updatedBy
    );

    // ═══════════════════════════════════════════════════════════
    // MODIFIERS
    // ═══════════════════════════════════════════════════════════

    modifier onlyOwner() {
        require(msg.sender == owner, "AssetIdentityRegistry: not owner");
        _;
    }

    modifier onlyAuthorized() {
        require(
            msg.sender == owner || msg.sender == auditorRegistry,
            "AssetIdentityRegistry: not authorized"
        );
        _;
    }

    modifier assetExists(address _token) {
        require(isRegistered[_token], "AssetIdentityRegistry: asset not found");
        _;
    }

    // ═══════════════════════════════════════════════════════════
    // CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════

    constructor(address _auditorRegistry) {
        owner = msg.sender;
        auditorRegistry = _auditorRegistry;
    }

    // ═══════════════════════════════════════════════════════════
    // REGISTRATION
    // ═══════════════════════════════════════════════════════════

    /// @notice Enregistre l'identité d'un actif tokenisé
    /// @param _tokenAddress Adresse du token on-chain
    /// @param _assetClass Classe d'actif
    /// @param _backingType Type de backing (physique, synthétique, fractionnel, poolé)
    /// @param _legalIdentifier Identifiant légal (ISIN, LBMA serial, Cadastre, etc.)
    /// @param _jurisdiction Juridiction légale
    /// @param _custodian Custodian qui détient l'actif physique
    function registerAsset(
        address _tokenAddress,
        AssetClass _assetClass,
        BackingType _backingType,
        string calldata _legalIdentifier,
        string calldata _jurisdiction,
        string calldata _custodian
    ) external onlyOwner {
        require(_tokenAddress != address(0), "AssetIdentityRegistry: zero address");
        require(!isRegistered[_tokenAddress], "AssetIdentityRegistry: already registered");
        require(bytes(_legalIdentifier).length > 0, "AssetIdentityRegistry: empty identifier");

        // Détection double comptage
        bool isDuplicate = false;
        if (identifierExists[_legalIdentifier]) {
            isDuplicate = true;
            address existingToken = identifierToTokens[_legalIdentifier][0];
            emit DuplicateDetected(
                _tokenAddress,
                _legalIdentifier,
                existingToken,
                "Legal identifier already registered on this chain"
            );
        }

        AssetIdentity memory identity = AssetIdentity({
            tokenAddress: _tokenAddress,
            assetClass: _assetClass,
            backingType: _backingType,
            legalIdentifier: _legalIdentifier,
            jurisdiction: _jurisdiction,
            custodian: _custodian,
            registeredBy: msg.sender,
            registeredAt: block.timestamp,
            updatedAt: block.timestamp,
            isActive: true,
            isDuplicate: isDuplicate
        });

        identities[_tokenAddress] = identity;
        identifierToTokens[_legalIdentifier].push(_tokenAddress);
        identifierExists[_legalIdentifier] = true;
        isRegistered[_tokenAddress] = true;
        assetList.push(_tokenAddress);

        emit AssetRegistered(
            _tokenAddress,
            _assetClass,
            _backingType,
            _legalIdentifier,
            _jurisdiction,
            msg.sender
        );
    }

    /// @notice Ajoute un enregistrement cross-chain pour un actif existant
    /// @dev Permet de détecter si le même actif est tokenisé sur plusieurs chains
    /// @param _tokenAddress Token sur cette chain
    /// @param _chainId Chain ID de l'autre chain
    /// @param _crossChainToken Adresse du token sur l'autre chain
    function addCrossChainRecord(
        address _tokenAddress,
        uint256 _chainId,
        address _crossChainToken
    ) external onlyOwner assetExists(_tokenAddress) {
        require(_crossChainToken != address(0), "AssetIdentityRegistry: zero address");

        CrossChainRecord memory record = CrossChainRecord({
            chainId: _chainId,
            tokenAddress: _crossChainToken,
            isActive: true
        });

        crossChainRecords[_tokenAddress].push(record);

        emit CrossChainRecordAdded(_tokenAddress, _chainId, _crossChainToken);
    }

    // ═══════════════════════════════════════════════════════════
    // ADMIN
    // ═══════════════════════════════════════════════════════════

    /// @notice Révoque l'identité d'un actif (fraude détectée, erreur, etc.)
    function revokeAsset(
        address _tokenAddress,
        string calldata _reason
    ) external onlyOwner assetExists(_tokenAddress) {
        identities[_tokenAddress].isActive = false;
        identities[_tokenAddress].updatedAt = block.timestamp;

        emit AssetRevoked(_tokenAddress, _reason);
    }

    /// @notice Met à jour le custodian d'un actif
    function updateCustodian(
        address _tokenAddress,
        string calldata _newCustodian
    ) external onlyOwner assetExists(_tokenAddress) {
        identities[_tokenAddress].custodian = _newCustodian;
        identities[_tokenAddress].updatedAt = block.timestamp;

        emit IdentityUpdated(_tokenAddress, "custodian", msg.sender);
    }

    /// @notice Met à jour l'adresse de AuditorRegistry
    function setAuditorRegistry(address _auditorRegistry) external onlyOwner {
        require(_auditorRegistry != address(0), "AssetIdentityRegistry: zero address");
        auditorRegistry = _auditorRegistry;
    }

    /// @notice Transfert ownership
    function transferOwnership(address _newOwner) external onlyOwner {
        require(_newOwner != address(0), "AssetIdentityRegistry: zero address");
        owner = _newOwner;
    }

    // ═══════════════════════════════════════════════════════════
    // VIEWS — lecture publique gratuite
    // ═══════════════════════════════════════════════════════════

    /// @notice Retourne l'identité complète d'un actif
    function getIdentity(address _tokenAddress)
        external
        view
        assetExists(_tokenAddress)
        returns (AssetIdentity memory)
    {
        return identities[_tokenAddress];
    }

    /// @notice Vérifie si un actif est authentique et actif
    function isAuthentic(address _tokenAddress)
        external
        view
        returns (
            bool authentic,
            bool active,
            bool duplicate,
            string memory legalIdentifier,
            string memory custodian
        )
    {
        if (!isRegistered[_tokenAddress]) {
            return (false, false, false, "", "");
        }

        AssetIdentity memory identity = identities[_tokenAddress];
        return (
            isRegistered[_tokenAddress],
            identity.isActive,
            identity.isDuplicate,
            identity.legalIdentifier,
            identity.custodian
        );
    }

    /// @notice Retourne tous les tokens enregistrés pour un identifiant légal
    /// @dev Utilisé pour détecter le double comptage cross-protocol
    function getTokensByIdentifier(string calldata _legalIdentifier)
        external
        view
        returns (address[] memory)
    {
        return identifierToTokens[_legalIdentifier];
    }

    /// @notice Retourne les enregistrements cross-chain d'un actif
    function getCrossChainRecords(address _tokenAddress)
        external
        view
        assetExists(_tokenAddress)
        returns (CrossChainRecord[] memory)
    {
        return crossChainRecords[_tokenAddress];
    }

    /// @notice Retourne tous les actifs enregistrés
    function getAllAssets() external view returns (address[] memory) {
        return assetList;
    }

    /// @notice Retourne le nombre d'actifs enregistrés
    function getAssetCount() external view returns (uint256) {
        return assetList.length;
    }

    /// @notice Filtre les actifs par classe
    function getAssetsByClass(AssetClass _class)
        external
        view
        returns (address[] memory)
    {
        uint256 count = 0;
        for (uint256 i = 0; i < assetList.length; i++) {
            if (identities[assetList[i]].assetClass == _class) count++;
        }

        address[] memory result = new address[](count);
        uint256 index = 0;
        for (uint256 i = 0; i < assetList.length; i++) {
            if (identities[assetList[i]].assetClass == _class) {
                result[index++] = assetList[i];
            }
        }
        return result;
    }

    /// @notice Filtre les actifs par juridiction
    function getAssetsByJurisdiction(string calldata _jurisdiction)
        external
        view
        returns (address[] memory)
    {
        uint256 count = 0;
        for (uint256 i = 0; i < assetList.length; i++) {
            if (
                keccak256(bytes(identities[assetList[i]].jurisdiction)) ==
                keccak256(bytes(_jurisdiction))
            ) count++;
        }

        address[] memory result = new address[](count);
        uint256 index = 0;
        for (uint256 i = 0; i < assetList.length; i++) {
            if (
                keccak256(bytes(identities[assetList[i]].jurisdiction)) ==
                keccak256(bytes(_jurisdiction))
            ) {
                result[index++] = assetList[i];
            }
        }
        return result;
    }
}
