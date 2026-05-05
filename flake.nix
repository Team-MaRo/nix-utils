{
  description = "Reusable Nix utilities (scripts, packages) for d3strukt0r projects";

  # Pinning the nixpkgs branch (not a SHA) lets `nix flake update` resolve
  # the latest commit on that branch into flake.lock. Consumers should set
  # `inputs.nix-utils.inputs.nixpkgs.follows = "nixpkgs"` so they don't
  # carry a duplicate nixpkgs entry in their own lock file.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "riscv64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems
        (system: f (import nixpkgs { inherit system; }));
    in
    {
      # Pure helper functions. Grouped under `oci` because that's where
      # they're consumed today; the implementations themselves are general.
      lib.oci = {
        # Convert seconds → nanoseconds. The OCI image spec stores the
        # Healthcheck `Interval`/`Timeout`/`StartPeriod` fields as int64
        # nanoseconds, which is cumbersome to write inline.
        # Usage:  Interval = secondsToNanos 30;
        secondsToNanos = n: n * 1000000000;

        # Convert a Nix-flake date string (`YYYYMMDDHHMMSS`, as found in
        # `self.lastModifiedDate`) to an RFC3339 timestamp suitable for the
        # OCI image config `created` field. On a clean git tree, the source
        # `lastModifiedDate` is the HEAD commit time of the whole repo —
        # identical sources produce an identical config blob digest. On a
        # dirty tree, current Nix falls back to wall-clock time and warns.
        # Usage:  created = createdFromDate self.lastModifiedDate;
        createdFromDate = d:
          "${builtins.substring 0 4 d}-"
          + "${builtins.substring 4 2 d}-"
          + "${builtins.substring 6 2 d}T"
          + "${builtins.substring 8 2 d}:"
          + "${builtins.substring 10 2 d}:"
          + "${builtins.substring 12 2 d}Z";
      };

      packages = forAllSystems (pkgs: {
        # Post-processor for `streamLayeredImage` tarballs (stdin → stdout):
        #
        # - copies history[].comment → history[].created_by so `dive` and
        #   Docker Desktop show a readable per-layer "Command" column. The
        #   nixpkgs streamer leaves created_by empty by default and writes
        #   the store path into `comment` instead.
        # - appends a synthetic HEALTHCHECK history entry mirroring
        #   config.Healthcheck. Trivy's DS-0026 rule reads
        #   history[].created_by, not Config.Healthcheck — without this it
        #   raises a false positive on every non-Dockerfile build.
        # - recomputes the config-blob sha256 and rewrites manifest.json
        #   so the new config blob is referenced.
        # - drops index.json + oci-layout from the archive (their digest
        #   cascade isn't needed for `docker load`).
        #
        # Shape:  ${stream} | ${fixOciImageHistory} > $out
        fixOciImageHistory = pkgs.writers.writePython3 "fix-oci-image-history" {
          flakeIgnore = [ "E302" "E305" "E401" "E501" "E702" ];
        } ''
          import sys, tarfile, io, json, hashlib, re

          raw = sys.stdin.buffer.read()
          src = tarfile.open(fileobj=io.BytesIO(raw))
          members = [(m, src.extractfile(m).read() if src.extractfile(m) else None)
                     for m in src.getmembers()]
          src.close()

          def find(name):
              for m, c in members:
                  if m.name == name:
                      return m, c
              return None, None

          _, mraw = find("manifest.json")
          manifest = json.loads(mraw)
          cfg_path = manifest[0]["Config"]
          _, cfg_raw = find(cfg_path)
          cfg = json.loads(cfg_raw)

          # Resolve a sensible timestamp for the synthetic HEALTHCHECK
          # history entry below. Without this it shows up as 1970-01-01
          # next to real layer timestamps. Prefer the image's top-level
          # `created`; fall back to the latest non-1970 history.created.
          img_created = cfg.get("created", "")
          if not img_created or img_created.startswith("1970") or img_created == "now":
              for h in cfg.get("history", []):
                  c = h.get("created", "")
                  if c and not c.startswith("1970"):
                      img_created = c
          if not img_created:
              img_created = "1970-01-01T00:00:00Z"

          store_re = re.compile(r"/nix/store/[a-z0-9]{32}-([^/'\"]+)")
          for h in cfg.get("history", []):
              cmt = h.get("comment", "")
              m = store_re.search(cmt)
              if m:
                  label = m.group(1)
                  # streamLayeredImage's customisation layer holds whatever
                  # the consumer wrote via extraCommands / fakeRootCommands.
                  # We don't know what's there, so use a neutral label.
                  if "customisation-layer" in label:
                      label = "customisation layer"
                  h["created_by"] = label
              elif cmt:
                  h["created_by"] = cmt

          # Mirror the real Healthcheck as one synthetic empty-layer history
          # entry so Trivy's DS-0026 sees it. Derived from Config.Healthcheck
          # so the two never drift.
          hc = cfg.get("config", {}).get("Healthcheck") or {}
          test = hc.get("Test") or []
          hc_str = None
          if test and test[0] == "CMD":
              hc_str = "HEALTHCHECK CMD " + " ".join(test[1:])
          elif test and test[0] == "CMD-SHELL":
              hc_str = "HEALTHCHECK CMD-SHELL " + test[1]
          if hc_str:
              cfg.setdefault("history", []).append({
                  "created": img_created,
                  "created_by": hc_str,
                  "empty_layer": True,
                  "comment": "trivy-compat: DS-0026 reads created_by, not Config.Healthcheck",
              })

          new_cfg = json.dumps(cfg, separators=(",", ":")).encode()
          new_digest = hashlib.sha256(new_cfg).hexdigest()
          new_cfg_path = (f"blobs/sha256/{new_digest}"
                          if cfg_path.startswith("blobs/sha256/")
                          else f"{new_digest}.json")
          manifest[0]["Config"] = new_cfg_path
          new_manifest = json.dumps(manifest).encode()

          buf = io.BytesIO()
          dst = tarfile.open(fileobj=buf, mode="w")
          for m, c in members:
              if m.name == "manifest.json":
                  info = tarfile.TarInfo("manifest.json")
                  info.size = len(new_manifest); info.mtime = m.mtime; info.mode = m.mode
                  dst.addfile(info, io.BytesIO(new_manifest))
              elif m.name == cfg_path:
                  info = tarfile.TarInfo(new_cfg_path)
                  info.size = len(new_cfg); info.mtime = m.mtime; info.mode = m.mode
                  dst.addfile(info, io.BytesIO(new_cfg))
              elif m.name in ("index.json", "oci-layout"):
                  continue
              else:
                  if c is None:
                      dst.addfile(m)
                  else:
                      dst.addfile(m, io.BytesIO(c))
          dst.close()
          sys.stdout.buffer.write(buf.getvalue())
        '';
      });
    };
}
