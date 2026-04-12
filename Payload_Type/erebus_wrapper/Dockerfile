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

# Pre-warm electron-builder + electron caches so the wine mode does not hit
# the network on every build. Versions must match Erebus.Electron/package.json.
ENV ELECTRON_CACHE=/root/.cache/electron
ENV ELECTRON_BUILDER_CACHE=/root/.cache/electron-builder
RUN mkdir -p "$ELECTRON_CACHE" "$ELECTRON_BUILDER_CACHE"

WORKDIR /Mythic/
    
COPY [".", "."]

RUN pip3 install -r requirements.txt --break-system-packages

CMD ["python3", "main.py"]