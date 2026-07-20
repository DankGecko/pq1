function permit(
  address owner,
  address spender,
  uint256 value,
  uint256 deadline,
  uint8 v,
  bytes32 r,
  bytes32 s
) external override {
  require(owner != address(0), Errors.ZeroAddressNotValid());
  //solium-disable-next-line
  require(block.timestamp <= deadline, Errors.InvalidExpiration());
  uint256 currentValidNonce = _nonces[owner];
  bytes32 digest = keccak256(
    abi.encodePacked(
      '\x19\x01',
      DOMAIN_SEPARATOR(),
      keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, currentValidNonce, deadline))
    )
  );
  require(owner == ECDSA.recover(digest, v, r, s), Errors.InvalidSignature());
  _nonces[owner] = currentValidNonce + 1;
  _approve({owner: owner, spender: spender, amount: value, emitEvent: true});
}
