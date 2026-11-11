## Download

Pick the file for your computer. On Windows, the **installer** adds Start menu and desktop shortcuts and an uninstaller. The portable file and the macOS and Linux builds need no installation: download and run them.

| Platform                               | Download                                                                                                                                                   | How to run                               |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| **Windows** (most PCs), installer      | [ez-azfw-manager-${VERSION}-win-x64-setup.exe](https://github.com/${REPO}/releases/download/${TAG}/ez-azfw-manager-${VERSION}-win-x64-setup.exe)           | Run it and follow the prompts            |
| **Windows on Arm**, installer          | [ez-azfw-manager-${VERSION}-win-arm64-setup.exe](https://github.com/${REPO}/releases/download/${TAG}/ez-azfw-manager-${VERSION}-win-arm64-setup.exe)       | Run it and follow the prompts            |
| **Windows** (most PCs), portable       | [ez-azfw-manager-${VERSION}-win-x64-portable.exe](https://github.com/${REPO}/releases/download/${TAG}/ez-azfw-manager-${VERSION}-win-x64-portable.exe)     | Double-click it                          |
| **Windows on Arm**, portable           | [ez-azfw-manager-${VERSION}-win-arm64-portable.exe](https://github.com/${REPO}/releases/download/${TAG}/ez-azfw-manager-${VERSION}-win-arm64-portable.exe) | Double-click it                          |
| **macOS** (Apple silicon, M1 or later) | [ez-azfw-manager-${VERSION}-mac-arm64.zip](https://github.com/${REPO}/releases/download/${TAG}/ez-azfw-manager-${VERSION}-mac-arm64.zip)                   | Unzip, then open **EZ AzFW Manager.app** |
| **macOS** (Intel)                      | [ez-azfw-manager-${VERSION}-mac-x64.zip](https://github.com/${REPO}/releases/download/${TAG}/ez-azfw-manager-${VERSION}-mac-x64.zip)                       | Unzip, then open **EZ AzFW Manager.app** |
| **Linux** (x64)                        | [ez-azfw-manager-${VERSION}-linux-x86_64.AppImage](https://github.com/${REPO}/releases/download/${TAG}/ez-azfw-manager-${VERSION}-linux-x86_64.AppImage)   | `chmod +x` the file, then run it         |

If Windows SmartScreen or macOS Gatekeeper warns about the app on first launch, see [First launch on each OS](https://github.com/${REPO}#first-launch-on-each-os). To check a download, compare its hash with `SHA256SUMS.txt`. See the [Code signing policy](https://github.com/${REPO}#code-signing-policy) for who signs releases and how your data is handled.

## What's changed

${CHANGES}
