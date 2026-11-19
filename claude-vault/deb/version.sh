#!/usr/bin/env bash
# Print the Cargo version for a checkout, as openshell-core/build.rs computes it:
# latest vX.Y.Z tag, next patch, commits since, short sha -> 0.1.9-dev.25+g0ad0c122b.
# On the tag itself: 0.1.9. Needs the upstream release tags in the repository.
#
#   claude-vault/deb/version.sh [<repo>]
set -euo pipefail

repo=${1:-.}
tag=$(git -C "$repo" describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*')
distance=$(git -C "$repo" rev-list --count "$tag..HEAD")
sha=$(git -C "$repo" rev-parse --short=9 HEAD)
IFS=. read -r major minor patch <<<"${tag#v}"
if [[ "$distance" -eq 0 ]]; then
    echo "${tag#v}"
else
    echo "$major.$minor.$((patch + 1))-dev.$distance+g$sha"
fi
