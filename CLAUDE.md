# CLAUDE.md

Project guidance for Claude Code. The full agent guide lives in `AGENTS.md` —
read it; it is the source of truth for layout, commands, conventions, the Helm
chart, releases, and the planning workflow.

@AGENTS.md

## Claude-specific notes

- **Always** run `go build ./... && go vet ./... && go test ./...` (and
  `helm lint charts/portreach` for chart edits) before reporting a change done.
  State failures plainly with output.
- Keep changes small and idiomatic — match the comment density and style of the
  surrounding code (see Conventions in `AGENTS.md`).
- Don't add dependencies without a clear reason; this project is deliberately
  near-stdlib.
- Releases go through `./release.sh` (interactive, run from a terminal on `main`) —
  don't hand-roll the tagging unless the script can't be used.
- `.ralphex/` is tooling state (gitignored); never edit or commit it.
