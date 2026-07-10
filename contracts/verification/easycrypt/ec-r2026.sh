#!/usr/bin/env bash
# EasyCrypt run helper for the PINNED r2026.02 release.
#   switch: ec-r2026 (OCaml 4.14.2; EasyCrypt r2026.02 + Alt-Ergo 2.6.0 + why3 1.8.2)
# This is separate from ec.sh, which loads the `checkct` dev switch. It uses a
# SWITCH-LOCAL why3 conf so checkct's shared ~/.config/easycrypt/why3.conf is
# never touched (that shared conf still points at checkct's own alt-ergo).
#
# Note: EasyCrypt's `-why3` flag must come AFTER the subcommand, so this helper
# injects it right after the command word.
#
# Usage:
#   bash ec-r2026.sh compile -I proofs proofs/WOTS_TW_ES.ec
#   bash ec-r2026.sh config
export PATH="/usr/bin:/bin:$HOME/.nix-profile/bin:$PATH"
eval "$($HOME/.nix-profile/bin/opam env --switch=ec-r2026)"
export PATH="$HOME/.opam/ec-r2026/bin:$PATH"
WHY3CONF="$HOME/.config/easycrypt/why3-ec-r2026.conf"
if [ "$#" -ge 1 ]; then
  cmd="$1"; shift
  exec easycrypt "$cmd" -why3 "$WHY3CONF" "$@"
else
  exec easycrypt
fi
