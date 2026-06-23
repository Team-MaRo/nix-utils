FROM mcr.microsoft.com/devcontainers/base:debian

# Install Nix with the Determinate Systems installer instead of the
# devcontainers/features/nix feature. That feature fails to install under
# OrbStack's seccomp profile: its post-install `nix-collect-garbage` issues
# io_uring reads the profile rejects with EPERM
# ("error: read of 65536 bytes: Operation not permitted"). The Determinate
# installer runs no GC step, so it gets past that.
#
#   --init none   : this base image has no systemd to manage the daemon.
#   sandbox=false : keeps Nix builds working under restrictive container
#                   seccomp profiles (and is required for Podman).
RUN curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix \
      | sh -s -- install linux \
        --no-confirm \
        --init none \
        --extra-conf "experimental-features = nix-command flakes" \
        --extra-conf "sandbox = false"

ENV PATH="/nix/var/nix/profiles/default/bin:${PATH}"
