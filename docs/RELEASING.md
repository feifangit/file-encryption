# Releasing fileencrypt

The CLI version is defined by `version` in `cmd/fileencrypt/main.go`. Release tags use the same version with a `v` prefix.

1. Update the CLI version, README, and release notes as needed.
2. Run the release checks locally:

   ```bash
   gofmt -w cmd internal
   go vet ./...
   go test -race ./...
   ```

3. Commit and push the release changes.
4. Create and push the matching tag. For version `0.3.1`:

   ```bash
   git tag -a v0.3.1 -m "v0.3.1"
   git push origin v0.3.1
   ```

5. The release workflow verifies the tag, runs the tests, cross-compiles macOS and Linux archives, generates SHA-256 checksums, and creates a draft GitHub Release.
6. Download at least one archive, verify its checksum and `fileencrypt version`, review the generated notes, mark it as a pre-release when appropriate, and publish the draft.

Do not commit locally built binaries or files from `test/`. Release artifacts are produced from the tagged source by GitHub Actions.
