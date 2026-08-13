#!/usr/bin/env bash
# Reconstruct the experiment trees.  Only the EDITED WOTS_TW_ES.ec files are
# committed; every other file in base/ and probe/ is a VERBATIM copy of
# base-c10-split, restored here rather than duplicated in git (the same reason
# experiments/wots-tw-incenc/chain/ carries only its two edited files).
set -eu
cd "$(dirname "$0")/../.."
for d in base probe; do
  mkdir -p "experiments/wots-badenc/$d"
  for f in base-c10-split/*.ec base-c10-split/*.eca; do
    b=$(basename "$f")
    [ "$b" = "WOTS_TW_ES.ec" ] && continue     # the edited file is committed
    cp "$f" "experiments/wots-badenc/$d/$b"
  done
done

# The cdrafts tree, for threading the charge into the closure.  Only the edited
# XmssmtCC_All.ec is committed; everything else is a verbatim copy.
mkdir -p experiments/wots-badenc/cd
for f in cdrafts-split/*.ec cdrafts-split/*.eca; do
  b=$(basename "$f")
  [ "$b" = "XmssmtCC_All.ec" ] && continue
  cp "$f" "experiments/wots-badenc/cd/$b"
done
chmod -R 777 experiments/wots-badenc
echo "trees reconstructed; base/ and probe/ WOTS_TW_ES.ec are the committed edits"
