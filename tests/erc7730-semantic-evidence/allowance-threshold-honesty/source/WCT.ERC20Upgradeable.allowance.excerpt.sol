/*
 * Normalized-LF, non-contiguous excerpts from the verified WCT implementation
 * source set. This is an evidence excerpt, not a compilable source unit.
 */

contract WCT is NttTokenUpgradeable, ERC20VotesUpgradeable, ERC20PermitUpgradeable, AccessControlUpgradeable {

contract L2WCT is
    NttTokenUpgradeable,
    ERC20PermitUpgradeable,
    ERC20VotesUpgradeable,
    AccessControlUpgradeable,
    ISemver,
    IERC7802
{

abstract contract NttTokenUpgradeable is ERC20BurnableUpgradeable, INttToken, IERC165 {

    function _spendAllowance(address owner, address spender, uint256 value) internal virtual {
        uint256 currentAllowance = allowance(owner, spender);
        if (currentAllowance != type(uint256).max) {
            if (currentAllowance < value) {
                revert ERC20InsufficientAllowance(spender, currentAllowance, value);
            }
            unchecked {
                _approve(owner, spender, currentAllowance - value, false);
            }
        }
    }
