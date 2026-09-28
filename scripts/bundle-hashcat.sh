#!/bin/bash
set -euo pipefail

# Xcode calls this after compiling the app. The build machine needs Homebrew's
# pinned hashcat release; the resulting app does not need Homebrew.
HASHCAT_ROOT="/opt/homebrew/Cellar/hashcat/7.1.2"
APP_CONTENTS="${TARGET_BUILD_DIR}/${CONTENTS_FOLDER_PATH}"
if [[ ! -x "${HASHCAT_ROOT}/bin/hashcat_bin" ]]; then
  echo "error: Install hashcat 7.1.2 with Homebrew on the build Mac."
  exit 1
fi

mkdir -p "${APP_CONTENTS}/MacOS" "${APP_CONTENTS}/Frameworks" "${APP_CONTENTS}/Resources/hashcat"
for bundled in "${APP_CONTENTS}/MacOS/hashcat_bin" \
               "${APP_CONTENTS}/Frameworks/libminizip.1.dylib" \
               "${APP_CONTENTS}/Frameworks/libxxhash.0.dylib"; do
  if [[ -f "${bundled}" ]]; then chmod u+w "${bundled}"; fi
done
cp "${HASHCAT_ROOT}/bin/hashcat_bin" "${APP_CONTENTS}/MacOS/hashcat_bin"
rsync -a "${HASHCAT_ROOT}/share/hashcat/" "${APP_CONTENTS}/Resources/hashcat/"
cp "${HASHCAT_ROOT}/share/doc/hashcat/docs/license.txt" "${APP_CONTENTS}/Resources/hashcat-license.txt"
cp "${PROJECT_DIR}/../docdecrypt/rules/best-effort.rule" "${APP_CONTENTS}/Resources/best-effort.rule"

cp /opt/homebrew/opt/minizip/lib/libminizip.1.dylib "${APP_CONTENTS}/Frameworks/"
cp /opt/homebrew/opt/xxhash/lib/libxxhash.0.dylib "${APP_CONTENTS}/Frameworks/"
install_name_tool -change /opt/homebrew/opt/minizip/lib/libminizip.1.dylib \
  @loader_path/../Frameworks/libminizip.1.dylib "${APP_CONTENTS}/MacOS/hashcat_bin"
install_name_tool -change /opt/homebrew/opt/xxhash/lib/libxxhash.0.dylib \
  @loader_path/../Frameworks/libxxhash.0.dylib "${APP_CONTENTS}/MacOS/hashcat_bin"
codesign --force --sign - "${APP_CONTENTS}/Frameworks/libminizip.1.dylib"
codesign --force --sign - "${APP_CONTENTS}/Frameworks/libxxhash.0.dylib"
codesign --force --sign - "${APP_CONTENTS}/MacOS/hashcat_bin"
# Older test runs may have left hashcat's cache beside the executable.
rm -f "${APP_CONTENTS}/MacOS/hashcat.dictstat2" "${APP_CONTENTS}/MacOS/hashcat.log"
rm -rf "${APP_CONTENTS}/MacOS/kernels"
rm -f "${APP_CONTENTS}/MacOS/OpenCL" "${APP_CONTENTS}/MacOS/modules"
