# nix-utils

Reusable Nix utilities (scripts and small packages) shared across
[d3strukt0r](https://github.com/d3strukt0r) projects.

## Utilities

### Packages

| Output | Purpose |
|---|---|
| `packages.<system>.fixOciImageHistory` | stdin/stdout post-processor for nixpkgs `dockerTools.streamLayeredImage` tarballs. Copies `history[].comment → history[].created_by` so dive / Docker Desktop show readable per-layer commands, appends a synthetic `HEALTHCHECK` history entry (Trivy DS-0026 workaround), recomputes the config-blob digest, rewrites `manifest.json`. |

### Helper functions (`lib.oci`)

| Function | Purpose |
|---|---|
| `lib.oci.secondsToNanos n` | Convert seconds → nanoseconds. OCI image spec stores Healthcheck `Interval`/`Timeout`/`StartPeriod` in nanoseconds. |
| `lib.oci.createdFromDate d` | Convert a Nix-flake `YYYYMMDDHHMMSS` date string (e.g. `self.lastModifiedDate`) to RFC3339 for the OCI image `created` field. |

## Use

Add as a flake input, share `nixpkgs` to keep the lock file clean:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    nix-utils.url = "github:d3strukt0r/nix-utils";
    nix-utils.inputs.nixpkgs.follows = "nixpkgs";
  };
  outputs = { self, nixpkgs, nix-utils }:
    let
      pkgs = import nixpkgs { system = "x86_64-linux"; };
      stream = pkgs.dockerTools.streamLayeredImage { /* ... */ };
    in {
      packages.x86_64-linux.image = pkgs.runCommand "image.tar" { } ''
        ${stream} | ${nix-utils.packages.x86_64-linux.fixOciImageHistory} > $out
      '';
    };
}
```

Supported systems: `x86_64-linux`, `aarch64-linux`, `riscv64-linux`.

## Contributing

Please read [CONTRIBUTING.md][contributing] for details on our code of conduct and the process for submitting pull requests.

This project uses [Conventional Commits](https://www.conventionalcommits.org/).

## Versioning

We use [SemVer](http://semver.org/) for versioning. For available versions, see the [tags on this repository][gh-tags].

## Authors

### Special thanks for all the people who had helped this project so far

- **Manuele** - [D3strukt0r](https://github.com/D3strukt0r)

See also the full list of [contributors][gh-contributors] who participated in this project.

### I would like to join this list. How can I help the project?

We're currently looking for contributions for the following:

- [ ] Bug fixes
- [ ] etc...

For more information, please refer to our [CONTRIBUTING.md][contributing] guide.

## License

This project is licensed under the MIT License - see the [LICENSE.txt](LICENSE.txt) file for details.

## Acknowledgments

This project currently uses no third-party libraries or copied code.

[gh-tags]: https://github.com/D3strukt0r/nix-utils/tags
[gh-contributors]: https://github.com/D3strukt0r/nix-utils/contributors
[contributing]: https://github.com/D3strukt0r/.github/blob/master/CONTRIBUTING.md
[code-of-conduct]: https://github.com/D3strukt0r/.github/blob/master/CODE_OF_CONDUCT.md
