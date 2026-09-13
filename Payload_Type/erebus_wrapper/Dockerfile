FROM itsafeaturemythic/mythic_python_dotnet:latest
RUN apt-get clean
RUN dpkg --add-architecture i386

RUN if grep -q bullseye /etc/apt/sources.list 2>/dev/null; then \
        sed -i \
            -e '/debian-security\|security\.debian/d' \
            -e 's|deb.debian.org/debian|archive.debian.org/debian|g' \
            -e '/bullseye-updates/d' -e '/bullseye-backports/d' \
            /etc/apt/sources.list && \
        echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99archive; \
    fi
RUN rm -f /etc/apt/sources.list.d/*.list 2>/dev/null || true

RUN apt-get update \
    && apt-get install -y --no-install-recommends --allow-downgrades \
        libc6 libc6:i386 libc-bin \
    && apt-get install -y --no-install-recommends \
        python3 python3-pip \
        wget curl ca-certificates openssl \
        mingw-w64 git msitools wixl make g++ \
        p7zip-full zip osslsigncode \
        wine wine32 wine64 libcairo2 \
    && python3 -m ensurepip --upgrade 2>/dev/null || true \
    && python3 -m venv --help >/dev/null 2>&1 || true

RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g @vscode/vsce --no-audit --no-fund \
    && vsce --version

COPY --from=mcr.microsoft.com/dotnet/sdk:8.0 /usr/share/dotnet /usr/share/dotnet
ENV DOTNET_ROOT=/usr/share/dotnet
ENV PATH="/usr/share/dotnet:${PATH}"
ENV DOTNET_NOLOGO=1
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1

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

ENV ELECTRON_CACHE=/root/.cache/electron
ENV ELECTRON_BUILDER_CACHE=/root/.cache/electron-builder
RUN mkdir -p "$ELECTRON_CACHE" "$ELECTRON_BUILDER_CACHE"

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

RUN wineboot --init >/dev/null 2>&1 || true; \
    wineserver -w || true

WORKDIR /Mythic/

COPY [".", "."]

RUN set -eux; \
    SRC=/Mythic/erebus_wrapper/agent_code/Erebus.Loaders/Erebus.Electron; \
    if [ -d /tmp/electron-prewarm/node_modules ]; then \
        rm -rf "$SRC/node_modules"; \
        mv /tmp/electron-prewarm/node_modules "$SRC/node_modules"; \
    fi; \
    rm -rf /tmp/electron-prewarm

RUN pip3 install -r requirements.txt --break-system-packages

CMD ["python3", "main.py"]