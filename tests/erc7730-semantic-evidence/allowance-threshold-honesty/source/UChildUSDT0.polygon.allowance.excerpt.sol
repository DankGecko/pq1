/*
 * Normalized-LF, non-contiguous excerpts from the verified Polygon USDT
 * implementation source set. This is an evidence excerpt, not a compilable
 * source unit.
 */

contract UChildUSDT0 is UChildERC20, IERC7802, WithBlockedList {

contract UChildERC20 is
    ERC20,
    IChildToken,
    AccessControlMixin,
    NativeMetaTransaction,
    ContextMixin
{

    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        _approve(_msgSender(), spender, amount);
        return true;
    }

    function transferFrom(address sender, address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(sender, recipient, amount);
        _approve(sender, _msgSender(), _allowances[sender][_msgSender()].sub(amount, "ERC20: transfer amount exceeds allowance"));
        return true;
    }

    function _approve(address owner, address spender, uint256 amount) internal virtual {
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }
