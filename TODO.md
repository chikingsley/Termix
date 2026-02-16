# TODO

## Upstream PR

- [ ] Submit PR to [LukeGus/Termix](https://github.com/LukeGus/Termix) with macOS monitoring support
  - Branch: `feat/macos-support` on `chikingsley/Termix`
  - 4 commits: macOS collector support, bug fixes, tests, example config
  - All 10 monitoring widgets work on macOS (CPU, memory, disk, network, uptime, system, processes, ports, login stats, firewall)
  - Includes vitest test suite with 17 tests covering all collectors

## Investigate

- [ ] Docker management shows 0 containers for gmk-server despite 32+ running
  - `enable_docker` is set to 1 in DB
  - `simon` user is in `docker` group
  - Docker runs on port 30007 as a separate SSH session, not a stats widget
  - Need to check if the Docker panel is connecting properly via the UI

## Future

- [ ] Add more collector tests as edge cases are found
- [ ] Consider adding macOS integration tests with real SSH connections
