# OpenAuthFederated — task runner
#
# The application code (pnpm workspace: @auth/backend + @auth/react SDKs)
# lives under code/. These recipes proxy into that workspace so they can be
# run from the repo root with `just <recipe>`.

# Directory holding the pnpm workspace.
code_dir := justfile_directory() / "code"

# Default recipe: list everything available.
default:
    @just --list

# Install all workspace dependencies.
install:
    cd {{code_dir}} && pnpm install

# Build every package in the workspace (tsc per package).
build:
    cd {{code_dir}} && pnpm -r build

# Run all package test suites.
test:
    cd {{code_dir}} && pnpm -r test

# Remove build output (dist/) from every package.
clean:
    cd {{code_dir}} && pnpm -r exec rm -rf dist

# Fresh build: clean, install, then build.
rebuild: clean install build
