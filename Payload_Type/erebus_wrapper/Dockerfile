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
# .NET SDK 8.0 (official Microsoft container)
# ----------------------------------------------------------------------------
# The parent itsafeaturemythic/mythic_python_dotnet base ships an older
# dotnet toolchain that caps out at .NET Framework 4.7 / .NET 6, which is
# not enough for Erebus.ClickOnce's AppDomain Injection path — that
# implementation needs .NET Framework 4.8 (net48) reference assemblies so
# the classic `AppDomain.CreateDomain` surface is available at compile
# time. Rather than apt-installing a whole new SDK, we lift the official
# Microsoft dotnet/sdk:8.0 tree straight out of their container and
# overlay it. The new SDK understands net48 as a TFM as long as the
# Microsoft.NETFramework.ReferenceAssemblies.net48 NuGet targeting pack
# is available — which we pre-warm below so ClickOnce builds never hit
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

WORKDIR /Mythic/
    
COPY [".", "."]

RUN pip3 install -r requirements.txt --break-system-packages

CMD ["python3", "main.py"]