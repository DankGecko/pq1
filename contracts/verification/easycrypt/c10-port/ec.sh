#!/usr/bin/env bash
# EasyCrypt run helper — pins the system libs ahead of nix, then loads the
# opam `checkct` switch (OCaml 4.14.2; EC dev + Alt-Ergo 2.6.0 additive).
# Usage: bash ec.sh compile -p Alt-Ergo@2.6.0 <file.ec>
export PATH="/usr/bin:/bin:$HOME/.nix-profile/bin:$PATH"
eval "$($HOME/.nix-profile/bin/opam env --switch=checkct)"
exec easycrypt "$@"
