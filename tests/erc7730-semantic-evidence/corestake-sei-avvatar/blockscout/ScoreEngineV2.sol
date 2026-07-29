// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

// ═══════════════════════════════════════════════════════════════════════════════
//  ScoreEngine V2 — ALIA Quality Network · alia-core/alia-engine
//
//  Nouveautés V2 :
//    - IScoreModule : interface standard pour tout modèle externe
//    - Registre de modules pondérés (OpenClaw, Temporal, Portfolio, Behavioral)
//    - getCompositeScore() : agrégation COLOracle + modules
//    - getEffectiveScore() appelle getCompositeScore() — interface externe inchangée
//    - Pondération configurable par module (0–100)
//    - Circuit breaker par module (désactivation sans redéploiement)
//
//  Contrats référencés (ABIs vérifiés 6 avril 2026) :
//    COLOracle           0xe1D56f8DB28C4F257dF4A501e1D304073475ce14
//    MandateRegistry     0xd6fdF5fa1BD5A839755E0aa19Aa25b5f7739444c
//    CollateralRegistry  0x6Bc6c7E0154dAcA03Cd3f1997b193f552A8Fad4F
//
//  V1 : 0x8E6434d860A9c83728376E807b6c55C8e3395d2c (remplacée — aucun dépendant)
//  Déploiement : Base mainnet Q2 2026
// ═══════════════════════════════════════════════════════════════════════════════


// ───────────────────────────────────────────────────────────────────────────────
//  INTERFACE MODULES — standard pour tout modèle externe
// ───────────────────────────────────────────────────────────────────────────────

/**
 * @title IScoreModule
 * @notice Interface que tout module de scoring doit implémenter.
 *
 *         Un module reçoit le score COLOracle de base et retourne
 *         un score ajusté. Il est consultatif — jamais décisionnaire.
 *         ELIERouter voit uniquement le score final de ScoreEngine.
 *
 *         Types de modules prévus :
 *           OPENCLAW   — machine node temps réel 24/7 (depeg, liquidité)
 *           TEMPORAL   — dépréciation continue entre audits humains
 *           PORTFOLIO  — risque concentration sectorielle / custodian
 *           BEHAVIORAL — Avvatar ZKai scoring comportemental
 *           CUSTOM     — tout modèle propriétaire futur
 *
 *         Contraintes :
 *           - getAdjustedScore() doit être pure ou view (pas d'état modifié)
 *           - Doit retourner un score dans [0, 1000]
 *           - Ne doit jamais revert (utiliser try/catch côté ScoreEngine)
 */
interface IScoreModule {
    /**
     * @param asset      Adresse du token collatéral
     * @param baseScore  Score COLOracle de base (0–1000)
     * @return adjustedScore Score ajusté par ce module (0–1000)
     */
    function getAdjustedScore(address asset, uint256 baseScore)
        external view returns (uint256 adjustedScore);

    /**
     * @return Type du module — utilisé pour les logs et le monitoring
     *         Valeurs : "OPENCLAW" | "TEMPORAL" | "PORTFOLIO" | "BEHAVIORAL" | "CUSTOM"
     */
    function moduleType() external pure returns (string memory);
}


// ───────────────────────────────────────────────────────────────────────────────
//  INTERFACES CONTRATS DÉPLOYÉS
// ───────────────────────────────────────────────────────────────────────────────

interface ICOLOracle {
    enum CollateralType { STABLECOIN, RWA, LST }
    function getScore(address collateral)
        external view
        returns (uint256 score, CollateralType ctype, uint256 lastAuditDate, uint256 confidence, bool isActive);
    function getBestCollateral(address[] calldata candidates)
        external view
        returns (address best, uint256 bestScore);
}

interface IMandateRegistry {
    enum MandateLevel   { ROOKIE, DRIVER, PRO, EXPERT, CHAMPION }
    enum MandateStatus  { PENDING, INVESTOR_SIGNED, AUDITOR_SIGNED, ACTIVE, PAUSED, CLOSED, LIQUIDATED }
    enum AssetClass     { STABLECOIN, PHYSICAL_ASSET, BOND, EQUITY, PRIVATE_CREDIT, CARBON_CREDIT, LST, UNKNOWN }
    struct RiskPolicy {
        uint256 minColScore;
        uint256 maxLTV;
        uint256 targetYield;
        uint256 maxSingleAsset;
        uint256 maxSectorConcentration;
        uint256 shieldThreshold;
        uint256 rebalanceThreshold;
        bool    allowLeverage;
    }
    struct Mandate {
        bytes32       mandateId;
        address       investor;
        address       auditor;
        address       complianceAgent;
        address       executor;
        MandateLevel  level;
        MandateStatus status;
        RiskPolicy    riskPolicy;
        AssetClass[]  allowedAssets;
        uint256       depositAmount;
        uint256       minDeposit;
        uint256       lockupDays;
        uint256       performanceFee;
        uint256       managementFee;
        uint256       hurdleRate;
    }
    function getMandate(bytes32 mandateId) external view returns (Mandate memory);
}

interface ICollateralRegistry {
    function isAcceptable(address _token, uint256 _colScore, uint256 _ltv)
        external view returns (bool acceptable, string memory reason);
    function getActiveCollaterals() external view returns (address[] memory);
}


// ───────────────────────────────────────────────────────────────────────────────
//  CONTRAT PRINCIPAL
// ───────────────────────────────────────────────────────────────────────────────

contract ScoreEngineV2 {

    // ─── Access control ───────────────────────────────────────────────────────

    address public owner;
    mapping(address => bool) public keepers;
    mapping(address => bool) public engines;
    bool public paused;

    modifier onlyOwner() {
        require(msg.sender == owner, "SE: not owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "SE: paused");
        _;
    }

    // ─── Références externes ──────────────────────────────────────────────────

    ICOLOracle          public colOracle;
    IMandateRegistry    public mandateRegistry;
    ICollateralRegistry public collateralRegistry;

    // ─── Cache des scores ─────────────────────────────────────────────────────

    struct CachedScore {
        uint256 score;
        uint256 confidence;
        uint256 updatedAt;
        bool    isActive;
    }
    mapping(address => CachedScore) public scoreCache;

    // ─── Override d'urgence ───────────────────────────────────────────────────

    struct ScoreOverride {
        uint256 score;
        string  reason;
        address setBy;
        uint256 setAt;
        bool    active;
    }
    mapping(address => ScoreOverride) public overrides;

    // ─── Registre de modules ──────────────────────────────────────────────────

    /**
     * @dev Un module enregistré dans ScoreEngine.
     *
     *      weight       : pondération du module dans l'agrégation (0–100)
     *                     La somme des poids n'est pas forcée à 100 —
     *                     ScoreEngine normalise automatiquement.
     *      active       : circuit breaker — désactivable sans retirer le module
     *      callsSuccess : compteur de succès (monitoring santé du module)
     *      callsFailed  : compteur d'échecs (détection module défaillant)
     */
    struct ScoreModuleConfig {
        address module;
        uint256 weight;       // 0–100
        bool    active;
        uint256 callsSuccess;
        uint256 callsFailed;
        string  moduleType;   // snapshot du type au moment de l'enregistrement
    }

    /// @notice Liste ordonnée des modules enregistrés
    ScoreModuleConfig[] public modules;

    /// @notice module address → index dans le tableau (1-indexed, 0 = absent)
    mapping(address => uint256) public moduleIndex;

    /// @notice Nombre maximum de modules simultanés (protection gas)
    uint256 public constant MAX_MODULES = 10;

    /// @notice Poids minimum accordé à COLOracle dans l'agrégation (0–100)
    ///         Empêche les modules de prendre le contrôle total du score.
    ///         Valeur par défaut : 60% pour COLOracle, 40% max pour les modules.
    uint256 public colOracleBaseWeight = 60;

    // ─── Courbe LTV par MandateLevel ─────────────────────────────────────────

    mapping(uint8 => uint256) public levelMaxLTV;
    mapping(uint8 => uint256) public levelMinScore;

    // ─── Constantes ───────────────────────────────────────────────────────────

    uint256 public constant MAX_SCORE = 1_000;
    uint256 public constant BPS_BASE  = 10_000;
    uint256 public stalePeriod             = 30 minutes;
    uint256 public degradationThresholdBps = 500;

    // ─── Événements ───────────────────────────────────────────────────────────

    event ScoreUpdated(address indexed asset, uint256 previousScore, uint256 newScore, uint256 confidence, uint256 timestamp);
    event ScoreDegraded(address indexed asset, uint256 previousScore, uint256 newScore, uint256 dropBps, uint256 timestamp);
    event ScoreBelowThreshold(address indexed asset, bytes32 indexed mandateId, uint256 score, uint256 minColScore, uint256 timestamp);
    event ShieldThresholdReached(address indexed asset, bytes32 indexed mandateId, uint256 score, uint256 shieldThreshold, uint256 timestamp);
    event OverrideSet(address indexed asset, uint256 score, string reason, address indexed setBy, uint256 timestamp);
    event OverrideRevoked(address indexed asset, address indexed revokedBy, uint256 timestamp);

    // Événements modules
    event ModuleRegistered(address indexed module, uint256 weight, string moduleType, uint256 timestamp);
    event ModuleRemoved(address indexed module, uint256 timestamp);
    event ModuleWeightUpdated(address indexed module, uint256 oldWeight, uint256 newWeight, uint256 timestamp);
    event ModuleToggled(address indexed module, bool active, uint256 timestamp);
    event ModuleCallFailed(address indexed module, address asset, uint256 timestamp);
    event CompositeScoreComputed(address indexed asset, uint256 baseScore, uint256 compositeScore, uint256 modulesUsed, uint256 timestamp);

    event ColOracleBaseWeightUpdated(uint256 newWeight, uint256 timestamp);
    event KeeperUpdated(address keeper, bool status);
    event EngineUpdated(address engine, bool status);


    // ─── Constructeur ─────────────────────────────────────────────────────────

    constructor(
        address _colOracle,
        address _mandateRegistry,
        address _collateralRegistry
    ) {
        require(_colOracle          != address(0), "SE: zero oracle");
        require(_mandateRegistry    != address(0), "SE: zero mandate");
        require(_collateralRegistry != address(0), "SE: zero collateral");

        owner               = msg.sender;
        colOracle           = ICOLOracle(_colOracle);
        mandateRegistry     = IMandateRegistry(_mandateRegistry);
        collateralRegistry  = ICollateralRegistry(_collateralRegistry);

        _initLevelParams();
    }


    // ═══════════════════════════════════════════════════════════════════════════
    //  SECTION 1 — PULL DE SCORES (COLOracle)
    // ═══════════════════════════════════════════════════════════════════════════

    function refreshScore(address asset) public whenNotPaused {
        (uint256 score, , , uint256 confidence, bool isActive) = colOracle.getScore(asset);

        CachedScore storage cached = scoreCache[asset];
        uint256 prevScore = cached.score;

        if (prevScore > 0 && score < prevScore) {
            uint256 dropBps = ((prevScore - score) * BPS_BASE) / prevScore;
            if (dropBps >= degradationThresholdBps)
                emit ScoreDegraded(asset, prevScore, score, dropBps, block.timestamp);
        }

        cached.score      = score;
        cached.confidence = confidence;
        cached.updatedAt  = block.timestamp;
        cached.isActive   = isActive;

        emit ScoreUpdated(asset, prevScore, score, confidence, block.timestamp);
    }

    function refreshScoreBatch(address[] calldata assets) external whenNotPaused {
        for (uint256 i = 0; i < assets.length; ) {
            refreshScore(assets[i]);
            unchecked { ++i; }
        }
    }


    // ═══════════════════════════════════════════════════════════════════════════
    //  SECTION 2 — AGRÉGATION DES MODULES (le coeur de la V2)
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Score composite = agrégation pondérée de COLOracle + modules actifs.
     *
     *         Algorithme :
     *           1. Score de base = cache COLOracle (ou override)
     *           2. Pour chaque module actif : appel try/catch getAdjustedScore()
     *              - Succès → score module intégré avec son poids
     *              - Échec  → module ignoré, compteur callsFailed++, event émis
     *           3. Score final = moyenne pondérée normalisée
     *              colOracleBaseWeight donne le poids minimum de COLOracle
     *
     *         Propriétés de sécurité :
     *           - Un module défaillant n'empêche pas le calcul
     *           - colOracleBaseWeight garantit que les modules ne prennent
     *             jamais plus de (100 - colOracleBaseWeight)% du score final
     *           - Le résultat est toujours dans [0, 1000]
     *
     * @param  asset         Adresse du token collatéral
     * @return compositeScore Score composite 0–1000
     * @return modulesUsed   Nombre de modules ayant contribué
     */
    function getCompositeScore(address asset)
        public
        returns (uint256 compositeScore, uint256 modulesUsed)
    {
        // Score de base COLOracle depuis le cache
        uint256 baseScore = scoreCache[asset].score;

        // Aucun module → retourner directement le score de base
        if (modules.length == 0) {
            return (baseScore, 0);
        }

        // Agrégation pondérée
        uint256 weightedSum  = baseScore * colOracleBaseWeight;
        uint256 totalWeight  = colOracleBaseWeight;

        uint256 mLen = modules.length;
        for (uint256 i = 0; i < mLen; ) {
            ScoreModuleConfig storage mod = modules[i];

            if (mod.active && mod.weight > 0) {
                // try/catch — un module qui revert est ignoré
                try IScoreModule(mod.module).getAdjustedScore(asset, baseScore)
                    returns (uint256 adjustedScore)
                {
                    // Clamp à [0, MAX_SCORE]
                    if (adjustedScore > MAX_SCORE) adjustedScore = MAX_SCORE;

                    weightedSum += adjustedScore * mod.weight;
                    totalWeight += mod.weight;
                    mod.callsSuccess++;
                    modulesUsed++;
                } catch {
                    // Module défaillant — ignoré silencieusement
                    mod.callsFailed++;
                    emit ModuleCallFailed(mod.module, asset, block.timestamp);
                }
            }

            unchecked { ++i; }
        }

        // Normalisation
        compositeScore = totalWeight > 0
            ? weightedSum / totalWeight
            : baseScore;

        // Clamp final
        if (compositeScore > MAX_SCORE) compositeScore = MAX_SCORE;

        emit CompositeScoreComputed(asset, baseScore, compositeScore, modulesUsed, block.timestamp);
    }

    /**
     * @notice Version view de getCompositeScore — pour lecture externe sans état.
     *         Ne met pas à jour les compteurs callsSuccess/callsFailed.
     *         Utilisée par ELIERouter et les dashboards.
     */
    function getCompositeScoreView(address asset)
        public
        view
        returns (uint256 compositeScore, uint256 modulesUsed)
    {
        uint256 baseScore = scoreCache[asset].score;

        if (modules.length == 0) return (baseScore, 0);

        uint256 weightedSum = baseScore * colOracleBaseWeight;
        uint256 totalWeight = colOracleBaseWeight;

        uint256 mLen = modules.length;
        for (uint256 i = 0; i < mLen; ) {
            ScoreModuleConfig storage mod = modules[i];

            if (mod.active && mod.weight > 0) {
                try IScoreModule(mod.module).getAdjustedScore(asset, baseScore)
                    returns (uint256 adjustedScore)
                {
                    if (adjustedScore > MAX_SCORE) adjustedScore = MAX_SCORE;
                    weightedSum += adjustedScore * mod.weight;
                    totalWeight += mod.weight;
                    modulesUsed++;
                } catch {}
            }

            unchecked { ++i; }
        }

        compositeScore = totalWeight > 0 ? weightedSum / totalWeight : baseScore;
        if (compositeScore > MAX_SCORE) compositeScore = MAX_SCORE;
    }


    // ═══════════════════════════════════════════════════════════════════════════
    //  SECTION 3 — GETTERS (interface externe inchangée vs V1)
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Score effectif d'un actif.
     *         Priorité : override → composite (COLOracle + modules) → cache brut
     *
     *         Interface identique à V1 — ELIERouter n'a pas besoin de changer.
     */
    function getEffectiveScore(address asset)
        public
        view
        returns (uint256 score, bool fresh)
    {
        // Override prioritaire
        ScoreOverride storage ov = overrides[asset];
        if (ov.active) return (ov.score, true);

        // Score composite (view — sans modification d'état)
        (uint256 composite, ) = getCompositeScoreView(asset);

        fresh = (block.timestamp - scoreCache[asset].updatedAt) <= stalePeriod;
        score = composite;
    }

    function checkMandateHealth(bytes32 mandateId)
        external
        view
        returns (bool healthy, uint256 worstScore, address worstAsset)
    {
        IMandateRegistry.Mandate memory mandate = mandateRegistry.getMandate(mandateId);
        require(mandate.status == IMandateRegistry.MandateStatus.ACTIVE, "SE: mandate not active");

        address[] memory actives = collateralRegistry.getActiveCollaterals();
        healthy = true; worstScore = MAX_SCORE; worstAsset = address(0);

        for (uint256 i = 0; i < actives.length; ) {
            address a = actives[i];
            (bool acceptable, ) = collateralRegistry.isAcceptable(a, scoreCache[a].score, mandate.riskPolicy.maxLTV);
            if (acceptable) {
                (uint256 score, ) = getEffectiveScore(a);
                if (score < worstScore) { worstScore = score; worstAsset = a; }
                if (score < mandate.riskPolicy.minColScore) healthy = false;
            }
            unchecked { ++i; }
        }
    }

    function getAdjustedLTV(address asset, bytes32 mandateId)
        external
        view
        returns (uint256 ltvBps)
    {
        IMandateRegistry.Mandate memory mandate = mandateRegistry.getMandate(mandateId);
        require(mandate.status == IMandateRegistry.MandateStatus.ACTIVE, "SE: mandate not active");
        if (!mandate.riskPolicy.allowLeverage) return 0;

        (uint256 score, ) = getEffectiveScore(asset);
        if (score < mandate.riskPolicy.minColScore) return 0;

        uint256 curveLTV = levelMaxLTV[uint8(mandate.level)];
        ltvBps = curveLTV < mandate.riskPolicy.maxLTV ? curveLTV : mandate.riskPolicy.maxLTV;
    }

    function isShieldTriggered(address asset, bytes32 mandateId)
        external view returns (bool)
    {
        IMandateRegistry.Mandate memory mandate = mandateRegistry.getMandate(mandateId);
        (uint256 score, ) = getEffectiveScore(asset);
        return score < mandate.riskPolicy.shieldThreshold;
    }

    function isRebalanceTriggered(address asset, bytes32 mandateId)
        external view returns (bool)
    {
        IMandateRegistry.Mandate memory mandate = mandateRegistry.getMandate(mandateId);
        (uint256 score, ) = getEffectiveScore(asset);
        return score < mandate.riskPolicy.rebalanceThreshold;
    }

    function getBestActiveCollateral()
        external view
        returns (address best, uint256 bestScore)
    {
        return colOracle.getBestCollateral(collateralRegistry.getActiveCollaterals());
    }

    function getActiveScoresSnapshot()
        external view
        returns (address[] memory assets, uint256[] memory scores, bool[] memory freshFlags)
    {
        assets = collateralRegistry.getActiveCollaterals();
        scores = new uint256[](assets.length);
        freshFlags = new bool[](assets.length);
        for (uint256 i = 0; i < assets.length; ) {
            (scores[i], freshFlags[i]) = getEffectiveScore(assets[i]);
            unchecked { ++i; }
        }
    }


    // ═══════════════════════════════════════════════════════════════════════════
    //  SECTION 4 — GESTION DES MODULES
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Enregistre un nouveau module de scoring.
     *
     *         Le module doit implémenter IScoreModule.
     *         Le poids est relatif — l'agrégation normalise automatiquement.
     *         colOracleBaseWeight garantit que COLOracle garde au minimum
     *         (colOracleBaseWeight / (colOracleBaseWeight + totalModuleWeights)) du score.
     *
     * @param module  Adresse du contrat module
     * @param weight  Poids relatif (0–100)
     */
    function registerModule(address module, uint256 weight)
        external
        onlyOwner
    {
        require(module != address(0),         "SE: zero module");
        require(weight > 0 && weight <= 100,  "SE: weight out of range");
        require(moduleIndex[module] == 0,     "SE: module already registered");
        require(modules.length < MAX_MODULES, "SE: max modules reached");

        // Vérification que le module implémente IScoreModule
        string memory mType = IScoreModule(module).moduleType();

        modules.push(ScoreModuleConfig({
            module:       module,
            weight:       weight,
            active:       true,
            callsSuccess: 0,
            callsFailed:  0,
            moduleType:   mType
        }));

        // Index 1-based
        moduleIndex[module] = modules.length;

        emit ModuleRegistered(module, weight, mType, block.timestamp);
    }

    /**
     * @notice Retire définitivement un module.
     *         Pour désactiver temporairement, utiliser toggleModule().
     */
    function removeModule(address module) external onlyOwner {
        uint256 idx = moduleIndex[module];
        require(idx > 0, "SE: module not found");

        uint256 arrayIdx = idx - 1;
        uint256 lastIdx  = modules.length - 1;

        // Swap avec le dernier puis pop
        if (arrayIdx != lastIdx) {
            modules[arrayIdx] = modules[lastIdx];
            moduleIndex[modules[arrayIdx].module] = idx;
        }

        modules.pop();
        delete moduleIndex[module];

        emit ModuleRemoved(module, block.timestamp);
    }

    /**
     * @notice Met à jour le poids d'un module.
     */
    function setModuleWeight(address module, uint256 newWeight)
        external
        onlyOwner
    {
        require(newWeight > 0 && newWeight <= 100, "SE: weight out of range");
        uint256 idx = moduleIndex[module];
        require(idx > 0, "SE: module not found");

        uint256 oldWeight = modules[idx - 1].weight;
        modules[idx - 1].weight = newWeight;

        emit ModuleWeightUpdated(module, oldWeight, newWeight, block.timestamp);
    }

    /**
     * @notice Active ou désactive un module sans le retirer.
     *         Circuit breaker — réponse rapide en cas de module défaillant.
     */
    function toggleModule(address module, bool active) external onlyOwner {
        uint256 idx = moduleIndex[module];
        require(idx > 0, "SE: module not found");
        modules[idx - 1].active = active;
        emit ModuleToggled(module, active, block.timestamp);
    }

    /**
     * @notice Liste tous les modules enregistrés avec leurs stats.
     */
    function getModules() external view returns (ScoreModuleConfig[] memory) {
        return modules;
    }

    /**
     * @notice Stats d'un module spécifique.
     */
    function getModuleStats(address module)
        external view
        returns (uint256 weight, bool active, uint256 success, uint256 failed, string memory mType)
    {
        uint256 idx = moduleIndex[module];
        require(idx > 0, "SE: module not found");
        ScoreModuleConfig storage mod = modules[idx - 1];
        return (mod.weight, mod.active, mod.callsSuccess, mod.callsFailed, mod.moduleType);
    }


    // ═══════════════════════════════════════════════════════════════════════════
    //  SECTION 5 — ALERTES DE SEUIL
    // ═══════════════════════════════════════════════════════════════════════════

    function checkThresholds(bytes32 mandateId) external whenNotPaused {
        IMandateRegistry.Mandate memory mandate = mandateRegistry.getMandate(mandateId);
        if (mandate.status != IMandateRegistry.MandateStatus.ACTIVE) return;

        address[] memory actives = collateralRegistry.getActiveCollaterals();
        for (uint256 i = 0; i < actives.length; ) {
            address a = actives[i];
            (uint256 score, ) = getEffectiveScore(a);
            if (score < mandate.riskPolicy.minColScore)
                emit ScoreBelowThreshold(a, mandateId, score, mandate.riskPolicy.minColScore, block.timestamp);
            if (score < mandate.riskPolicy.shieldThreshold)
                emit ShieldThresholdReached(a, mandateId, score, mandate.riskPolicy.shieldThreshold, block.timestamp);
            unchecked { ++i; }
        }
    }


    // ═══════════════════════════════════════════════════════════════════════════
    //  SECTION 6 — OVERRIDE D'URGENCE
    // ═══════════════════════════════════════════════════════════════════════════

    function setScoreOverride(address asset, uint256 score, string calldata reason)
        external onlyOwner
    {
        require(score <= MAX_SCORE,       "SE: score > 1000");
        require(bytes(reason).length > 0, "SE: reason required");
        overrides[asset] = ScoreOverride({ score: score, reason: reason, setBy: msg.sender, setAt: block.timestamp, active: true });
        emit OverrideSet(asset, score, reason, msg.sender, block.timestamp);
    }

    function revokeScoreOverride(address asset) external onlyOwner {
        require(overrides[asset].active, "SE: no active override");
        overrides[asset].active = false;
        emit OverrideRevoked(asset, msg.sender, block.timestamp);
    }


    // ═══════════════════════════════════════════════════════════════════════════
    //  SECTION 7 — CONFIGURATION
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Ajuste le poids minimum de COLOracle dans l'agrégation.
     *         Valeur recommandée : 50–80.
     *         En dessous de 50, les modules peuvent prendre trop d'influence.
     */
    function setColOracleBaseWeight(uint256 weight) external onlyOwner {
        require(weight >= 30 && weight <= 100, "SE: weight out of range");
        colOracleBaseWeight = weight;
        emit ColOracleBaseWeightUpdated(weight, block.timestamp);
    }

    function setLevelParams(uint8 level, uint256 maxLTV, uint256 minScore)
        external onlyOwner
    {
        require(level <= 4,            "SE: invalid level");
        require(maxLTV <= BPS_BASE,    "SE: LTV > 100%");
        require(minScore <= MAX_SCORE, "SE: minScore > 1000");
        levelMaxLTV[level]   = maxLTV;
        levelMinScore[level] = minScore;
    }

    function setColOracle(address _oracle) external onlyOwner {
        require(_oracle != address(0), "SE: zero address");
        colOracle = ICOLOracle(_oracle);
    }

    function setStalePeriod(uint256 _seconds) external onlyOwner {
        require(_seconds >= 5 minutes && _seconds <= 24 hours, "SE: out of range");
        stalePeriod = _seconds;
    }

    function setDegradationThreshold(uint256 _bps) external onlyOwner {
        require(_bps > 0 && _bps <= 2_000, "SE: out of range");
        degradationThresholdBps = _bps;
    }

    function setKeeper(address keeper, bool status) external onlyOwner {
        keepers[keeper] = status;
        emit KeeperUpdated(keeper, status);
    }

    function setEngine(address engine, bool status) external onlyOwner {
        engines[engine] = status;
        emit EngineUpdated(engine, status);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "SE: zero address");
        owner = newOwner;
    }

    function pause()   external onlyOwner { paused = true;  }
    function unpause() external onlyOwner { paused = false; }


    // ═══════════════════════════════════════════════════════════════════════════
    //  SECTION 8 — INIT INTERNE
    // ═══════════════════════════════════════════════════════════════════════════

    function _initLevelParams() internal {
        levelMaxLTV[0] = 6_500; levelMinScore[0] = 400; // ROOKIE
        levelMaxLTV[1] = 7_200; levelMinScore[1] = 500; // DRIVER
        levelMaxLTV[2] = 7_800; levelMinScore[2] = 600; // PRO
        levelMaxLTV[3] = 8_500; levelMinScore[3] = 700; // EXPERT
        levelMaxLTV[4] = 9_000; levelMinScore[4] = 800; // CHAMPION
    }
}

