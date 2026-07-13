#!/bin/bash
# Build a release: releases/php-banlist-<version>.tar.gz + .zip
# Usage:
#   ./build-release.sh            build the tarball and zip
#   ./build-release.sh --publish  build, then tag (if needed) and publish a
#                                 GitHub release with both assets via gh
# Run from the project root on a machine with tar (and gh for --publish).
set -euo pipefail

VERSION="0.5"
STAGE="php-banlist-${VERSION}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="${ROOT}/releases"
REPO="zermus/php-banlist"

cd "$ROOT"

echo ">> Staging ${STAGE}/ ..."
TMP="$(mktemp -d)"
DEST="${TMP}/${STAGE}"
mkdir -p "$DEST"

# What ships in a release: the pages, the shared layer under private/, the
# schema, the web-server configs, and the docs. Not the website, build
# script, git metadata, CLAUDE.md, releases/, or a local config.php.
cp -- *.php "$DEST/"
rm -f "$DEST/config.php" 2>/dev/null || true
cp -r -- private assets cron sql "$DEST/"
cp -- .htaccess nginx.conf.example README.txt INSTALL.txt CHANGELOG.txt LICENSE "$DEST/"

# Scrub anything that shouldn't ship.
find "$DEST" -name '.DS_Store' -delete 2>/dev/null || true

mkdir -p "$OUT"
echo ">> Creating ${OUT}/${STAGE}.tar.gz ..."
tar -czf "${OUT}/${STAGE}.tar.gz" -C "$TMP" "$STAGE"

echo ">> Creating ${OUT}/${STAGE}.zip ..."
rm -f "${OUT}/${STAGE}.zip"
if command -v zip >/dev/null 2>&1; then
    (cd "$TMP" && zip -qr "${OUT}/${STAGE}.zip" "$STAGE")
elif command -v powershell.exe >/dev/null 2>&1; then
    # Git Bash on Windows usually lacks zip; use Compress-Archive instead.
    WIN_SRC="$(cygpath -w "$TMP/$STAGE")"
    WIN_ZIP="$(cygpath -w "${OUT}/${STAGE}.zip")"
    powershell.exe -NoProfile -Command \
        "Compress-Archive -Path '${WIN_SRC}' -DestinationPath '${WIN_ZIP}' -CompressionLevel Optimal"
else
    echo "!! Neither zip nor powershell.exe found; skipping .zip" >&2
fi

rm -rf "$TMP"
echo ">> Done:"
ls -lh "${OUT}/${STAGE}".tar.gz "${OUT}/${STAGE}".zip 2>/dev/null || true

# ===== Optional: publish a GitHub release =====
if [[ "${1:-}" == "--publish" ]]; then
    # Locate gh (winget installs it outside Git Bash's PATH).
    GH="$(command -v gh || true)"
    [[ -z "$GH" && -x "/c/Program Files/GitHub CLI/gh.exe" ]] && GH="/c/Program Files/GitHub CLI/gh.exe"
    if [[ -z "$GH" ]]; then
        echo "!! gh CLI not found; install it (winget install GitHub.cli) or publish manually." >&2
        exit 1
    fi

    TAG="v${VERSION}"

    # Tag the current commit if the tag doesn't exist yet, and push it.
    if ! git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
        echo ">> Tagging ${TAG} ..."
        git tag -a "${TAG}" -m "php-banlist ${VERSION}"
    fi
    git push origin "${TAG}"

    NOTES="${OUT}/release-notes-${VERSION}.md"
    if "$GH" release view "${TAG}" --repo "$REPO" >/dev/null 2>&1; then
        echo ">> Release ${TAG} exists; uploading assets (clobber) ..."
        "$GH" release upload "${TAG}" \
            "${OUT}/${STAGE}.tar.gz" "${OUT}/${STAGE}.zip" \
            --repo "$REPO" --clobber
    else
        echo ">> Creating release ${TAG} ..."
        if [[ -f "$NOTES" ]]; then
            "$GH" release create "${TAG}" \
                "${OUT}/${STAGE}.tar.gz" "${OUT}/${STAGE}.zip" \
                --repo "$REPO" \
                --title "php-banlist ${VERSION}" \
                --notes-file "$NOTES" \
                --latest
        else
            "$GH" release create "${TAG}" \
                "${OUT}/${STAGE}.tar.gz" "${OUT}/${STAGE}.zip" \
                --repo "$REPO" \
                --title "php-banlist ${VERSION}" \
                --generate-notes \
                --latest
        fi
    fi
    echo ">> Published: https://github.com/${REPO}/releases/tag/${TAG}"
fi
