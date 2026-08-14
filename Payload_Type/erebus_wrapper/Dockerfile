FROM itsafeaturemythic/mythic_python_dotnet:latest
RUN apt-get clean
RUN dpkg --add-architecture i386
RUN apt-get update && apt-get install python3 python3-pip python3-venv wget curl ca-certificates openssl mingw-w64 git msitools wixl make g++ p7zip-full zip osslsigncode wine wine32 wine64 libcairo2 --no-install-recommends -y

# Node.js 20 LTS - used by the Erebus.Electron fake-installer *container*
# ("3.0 Container Type = Electron"): npm + electron-builder run under wine
# to produce the NSIS. No native addon / mingw cross-compile is required
# any more - Electron is now a pure JS wrapper that extract-and-spawns
# the embedded loader.
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# ----------------------------------------------------------------------------
# VSCode Extension Trigger - vsce prewarm
# ----------------------------------------------------------------------------
# Prewarm @vscode/vsce globally so the VSCode extension trigger plugin
# (plugin_trigger_vscode_ext.py) can package .vsix files without hitting
# the network on every build. Node.js 20 is already present from the
# Erebus.Electron install step above.
# ----------------------------------------------------------------------------
RUN npm install -g @vscode/vsce --no-audit --no-fund \
    && vsce --version

# ----------------------------------------------------------------------------
# .NET SDK 8.0 (official Microsoft container)
# ----------------------------------------------------------------------------
# The parent itsafeaturemythic/mythic_python_dotnet base ships an older
# dotnet toolchain that caps out at .NET Framework 4.7 / .NET 6, which is
# not enough for Erebus.ClickOnce's AppDomain Injection path - that
# implementation needs .NET Framework 4.8 (net48) reference assemblies so
# the classic `AppDomain.CreateDomain` surface is available at compile
# time. Rather than apt-installing a whole new SDK, we lift the official
# Microsoft dotnet/sdk:8.0 tree straight out of their container and
# overlay it. The new SDK understands net48 as a TFM as long as the
# Microsoft.NETFramework.ReferenceAssemblies.net48 NuGet targeting pack
# is available - which we pre-warm below so ClickOnce builds never hit
# the network.
COPY --from=mcr.microsoft.com/dotnet/sdk:8.0 /usr/share/dotnet /usr/share/dotnet
ENV DOTNET_ROOT=/usr/share/dotnet
ENV PATH="/usr/share/dotnet:${PATH}"
ENV DOTNET_NOLOGO=1
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1

# Pre-warm the NuGet global cache with the net48 reference assemblies
# package. We build a throwaway csproj that targets net48 and references
# the Microsoft.NETFramework.ReferenceAssemblies.net48 package; the
# restore pulls the targeting pack into /root/.nuget/packages and leaves
# it on disk. Subsequent Erebus.ClickOnce builds inside the running
# container resolve net48 references from the cached copy and never
# touch the network.
RUN set -eux; \
    mkdir -p /tmp/net48-prewarm/prewarm; \
    cd /tmp/net48-prewarm/prewarm; \
    printf '%s\n' \
        '<Project Sdk="Microsoft.NET.Sdk">' \
        '  <PropertyGroup>' \
        '    <TargetFramework>net48</TargetFramework>' \
        '  </PropertyGroup>' \
        '  <ItemGroup>' \
        '    <PackageReference Include="Microsoft.NETFramework.ReferenceAssemblies.net48" Version="1.0.3" PrivateAssets="all" />' \
        '  </ItemGroup>' \
        '</Project>' > prewarm.csproj; \
    printf 'namespace Prewarm { internal static class Stub { } }\n' > Stub.cs; \
    dotnet restore; \
    cd /; \
    rm -rf /tmp/net48-prewarm

# Pre-warm electron-builder + electron caches so the wine mode does not hit
# the network on every build. Versions must match Erebus.Electron/package.json.
ENV ELECTRON_CACHE=/root/.cache/electron
ENV ELECTRON_BUILDER_CACHE=/root/.cache/electron-builder
RUN mkdir -p "$ELECTRON_CACHE" "$ELECTRON_BUILDER_CACHE"

# ----------------------------------------------------------------------------
# Prewarm Erebus.Electron node_modules + electron-builder caches.
# ----------------------------------------------------------------------------
# In-Container (Wine) builds previously ran `npm ci` per build (downloading
# electron + electron-builder + ~400 transitive deps), then electron-builder
# would fetch winCodeSign + nsis-resources, then wine cold-started. Combined
# this routinely pushed past Mythic's payload build timeout. We do all of
# that exactly once here at image build time and persist the artefacts so
# every subsequent build is offline + cache-warm.
# Whole prewarm step is best-effort: the build host may have no network
# (corporate proxy, offline buildkit, registry rate-limit) in which case
# `npm ci` fails with ETIMEDOUT. We do NOT want that to fail image build
# - the per-build Makefile path already handles a cold node_modules
# correctly, the image just won't be cache-warm. Wrap the whole block in
# `|| echo` so any failure prints a notice and yields exit 0. Also bump
# npm fetch timeouts so flaky-but-present networks succeed.
COPY erebus_wrapper/agent_code/Erebus.Loaders/Erebus.Electron /tmp/electron-prewarm
RUN set -eu; \
    cd /tmp/electron-prewarm; \
    ( npm ci --no-audit --no-fund --prefer-offline \
            --fetch-retries=5 --fetch-retry-mintimeout=20000 \
            --fetch-retry-maxtimeout=120000 --fetch-timeout=300000 \
            --loglevel=error \
      && mkdir -p build/resources/payload \
      && : > build/resources/payload/.keep \
      && npx --no-install electron-builder --win nsis --x64 --publish never \
            --config.compression=store \
            --config.nsis.oneClick=true \
      || true; \
      rm -rf dist build/resources \
    ) || echo "[prewarm] electron prewarm failed (no network?) - per-build path will populate caches on first real build"

# Wineprefix cold-start adds ~10-20s on the first wine invocation per
# container. Initialise it now so the first real build skips it.
RUN wineboot --init >/dev/null 2>&1 || true; \
    wineserver -w || true

WORKDIR /Mythic/

COPY [".", "."]

# Move the prewarmed node_modules into the source-of-truth agent_code path
# so that builder.py's per-build copytree picks it up (it copies the whole
# agent_code tree into a fresh tempdir each build).
RUN set -eux; \
    SRC=/Mythic/erebus_wrapper/agent_code/Erebus.Loaders/Erebus.Electron; \
    if [ -d /tmp/electron-prewarm/node_modules ]; then \
        rm -rf "$SRC/node_modules"; \
        mv /tmp/electron-prewarm/node_modules "$SRC/node_modules"; \
    fi; \
    rm -rf /tmp/electron-prewarm

RUN pip3 install -r requirements.txt --break-system-packages

CMD ["python3", "main.py"]