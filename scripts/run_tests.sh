#!/bin/bash
# run_tests.sh - Build and test runner for Ghidra UF2 Loader
set -e

CACHE_DIR="$(pwd)/.ghidra_cache"
GRADLE_VERSION="8.5"
mkdir -p "$CACHE_DIR"

setup_gradle() {
    if [ ! -d "$CACHE_DIR/gradle-$GRADLE_VERSION" ]; then
        echo "Downloading Gradle $GRADLE_VERSION..."
        GRADLE_ZIP="gradle-$GRADLE_VERSION-bin.zip"
        curl -L "https://services.gradle.org/distributions/$GRADLE_ZIP" -o "$CACHE_DIR/$GRADLE_ZIP"
        unzip -q "$CACHE_DIR/$GRADLE_ZIP" -d "$CACHE_DIR"
        rm "$CACHE_DIR/$GRADLE_ZIP"
    fi
    GRADLE_BIN="$CACHE_DIR/gradle-$GRADLE_VERSION/bin/gradle"
}

setup_ghidra() {
    echo "Checking for Ghidra installation..."
    # Check if any ghidra_*_PUBLIC directory exists
    GHIDRA_INSTALL_DIR=$(ls -d "$CACHE_DIR"/ghidra_*_PUBLIC 2>/dev/null | head -n 1)
    
    if [ -z "$GHIDRA_INSTALL_DIR" ]; then
        echo "Fetching latest Ghidra release info..."
        LATEST_RELEASE_JSON=$(curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest)
        DOWNLOAD_URL=$(python3 -c "import sys, json; print([a['browser_download_url'] for a in json.load(sys.stdin).get('assets', []) if a['name'].endswith('.zip')][0])" <<< "$LATEST_RELEASE_JSON")
        ZIP_FILE=$(basename "$DOWNLOAD_URL")
        
        echo "Downloading $ZIP_FILE..."
        curl -L "$DOWNLOAD_URL" -o "$CACHE_DIR/$ZIP_FILE"
        echo "Extracting..."
        unzip -q "$CACHE_DIR/$ZIP_FILE" -d "$CACHE_DIR"
        rm "$CACHE_DIR/$ZIP_FILE"
        GHIDRA_INSTALL_DIR=$(ls -d "$CACHE_DIR"/ghidra_*_PUBLIC 2>/dev/null | head -n 1)
    fi

    export GHIDRA_INSTALL_DIR
    echo "Using Ghidra: $GHIDRA_INSTALL_DIR"
}

build_extension() {
    setup_gradle
    setup_ghidra
    echo "Building extension with args: $@"
    "$GRADLE_BIN" -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR" "$@" clean buildExtension
}

run_tests() {
    setup_ghidra
    echo "Running tests..."
    
    EXT_ZIP=$(ls dist/*.zip 2>/dev/null | head -n 1)
    if [ -z "$EXT_ZIP" ]; then
        echo "Extension ZIP not found in dist/. Building first..."
        build_extension
        EXT_ZIP=$(ls dist/*.zip 2>/dev/null | head -n 1)
    fi

    echo "Installing extension $EXT_ZIP into $GHIDRA_INSTALL_DIR..."
    mkdir -p "$GHIDRA_INSTALL_DIR/Ghidra/Extensions"
    # Remove existing extension if any
    rm -rf "$GHIDRA_INSTALL_DIR/Ghidra/Extensions/ghidra_uf2loader"
    unzip -o "$EXT_ZIP" -d "$GHIDRA_INSTALL_DIR/Ghidra/Extensions"

    # Run headless Ghidra to import UF2 and run verification script
    PROJECT_DIR="/tmp/ghidra_test_project"
    rm -rf "$PROJECT_DIR"
    mkdir -p "$PROJECT_DIR"
    
    "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJECT_DIR" TestProj \
        -import tests/examples/bus_pirate5_rev8.uf2 \
        -loader uf2loaderLoader \
        -scriptPath "$(pwd)/tests" \
        -postScript VerifyUF2Import.java \
        -deleteProject
}

COMMAND=$1
shift
case "$COMMAND" in
    setup) setup_gradle; setup_ghidra ;;
    build) build_extension "$@" ;;
    test) run_tests ;;
    *) echo "Usage: $0 {setup|build|test}"; exit 1 ;;
esac
