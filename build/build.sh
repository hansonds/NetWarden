#!/bin/sh
# Builds NetWarden.exe on Linux using Roslyn (from the .NET SDK) + Mono's .NET Framework 4.8 reference assemblies.
set -e
SRC=$(cd "$(dirname "$0")/../src" && pwd)
OUT=$(cd "$(dirname "$0")/.." && pwd)/out
REF=/usr/lib/mono/4.8-api
CSC=$(ls -d /usr/lib/dotnet/sdk/*/Roslyn/bincore/csc.dll | head -1)
mkdir -p "$OUT"
dotnet "$CSC" -nologo -noconfig -nostdlib+ -target:winexe -platform:x64 -optimize+ -unsafe+ -langversion:latest \
  -warn:4 -nowarn:1701,1702 -deterministic+ \
  -lib:$REF -lib:$REF/Facades \
  -r:mscorlib.dll -r:System.dll -r:System.Core.dll -r:System.Drawing.dll -r:System.Windows.Forms.dll \
  -r:System.Runtime.Serialization.dll -r:System.Xml.dll \
  -win32manifest:"$SRC/app.manifest" -win32icon:"$SRC/app.ico" \
  -resource:"$SRC/WinDivert.dll",NetWarden.WinDivert.dll \
  -resource:"$SRC/WinDivert64.sys",NetWarden.WinDivert64.sys \
  -out:"$OUT/NetWarden.exe" "$SRC"/*.cs
cp "$SRC/App.config" "$OUT/NetWarden.exe.config"
ls -la "$OUT"
