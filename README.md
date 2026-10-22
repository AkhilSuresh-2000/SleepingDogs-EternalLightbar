# Eternal Lightbar 🚨

**Persistent emergency vehicle lights for Sleeping Dogs: Definitive Edition.**

Eternal Lightbar is a small ASI mod that lets emergency vehicle lights continue flashing after Wei Shen exits the vehicle. Normally, the game turns the lights off when the player gets out. This mod changes that behavior so you can leave a vehicle with its emergency lights running.

> **Status:** `v0.1.0-beta` release candidate — tested in-game, with wider compatibility testing still pending.

## Features

- Keeps activated emergency lights flashing after Wei exits a supported vehicle.
- Works without replacing game assets or modifying the game executable on disk.
- Uses a runtime hook and vehicle-component checks to apply the change.

## Tested vehicles

The behavior has been observed during development on:

- Police cruiser
- Police SUV
- Police motorcycle
- Fire truck
- Ambulance

Multiple police cruisers have also been tested in a single session, and lights have persisted through at least one mission transition. **These are development observations, not a guarantee of compatibility with every vehicle, mission, or game build.**

## Requirements

- **Sleeping Dogs: Definitive Edition** (PC)
- A compatible **ASI loader** installed for the game
- The compiled **Eternal Lightbar `.asi`** from this project's Releases page, once published

Development and testing were performed with the Steam version under Proton on Linux. Native Windows and other distributions or editions have not yet been comprehensively verified.

## Installation

1. Back up any existing mod files you may need to restore.
2. Download [Ultimate ASI Loader by ThirteenAG](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases).
3. Install the 64-bit `dinput8.dll` from Ultimate ASI Loader in the main *Sleeping Dogs: Definitive Edition* game directory.
4. Download and extract the Eternal Lightbar release archive.
5. Place the supplied `base.asi` file inside the game's `plugins` folder. Create the folder if it does not already exist.
6. Launch the game, enter an emergency vehicle, activate its emergency lights, and exit to test the effect.

### Example Directory Structure

```text
SleepingDogsDefinitiveEdition/
├── dinput8.dll
└── plugins/
    └── base.asi
```

**Important:** Ultimate ASI Loader is a separate dependency developed by ThirteenAG and is not included in the Eternal Lightbar release archive. Other compatible ASI loaders may work, but have not been verified for this release. Follow their respective installation instructions if using an alternative loader.

## Uninstallation

Remove the Eternal Lightbar `.asi` file from your loader's plugin directory. Restart the game. The mod does not patch the game executable on disk.

## Known limitations

- **Beta software:** Behavior may vary with game updates, other mods, missions, and vehicles that have not been tested.
- The mod uses memory addresses and offsets identified for the tested game build. Compatibility with other executable versions is not guaranteed.
- The current implementation uses experimental single-vehicle tracking variables for diagnostics and does not provide a full registry or cleanup system for modified vehicles.
- The mod preserves the game's existing emergency-light behavior where possible; it does not add new sirens or custom light effects.
- A compatible ASI loader is required. Loader compatibility and interactions with other plugins have not been exhaustively tested.

Please include your game version, loader, other installed mods, and steps to reproduce when reporting an issue.

## Technical overview

Eternal Lightbar is written in C++ and runs as an ASI plugin. It hooks the game's in-game update callback, follows the player-to-vehicle component chain, validates the candidate `CopUnit` owner, and sets the scripted-light flag (`0x04`) in the relevant flags byte. The update callback checks the vehicle periodically rather than changing game files on disk.

The implementation was developed using Ghidra analysis, SDK references, debugging, and repeated in-game tests. Runtime memory validation reduces some risks but does not guarantee that a game object remains valid for its entire lifetime.

### Building from source

The source includes `SDK/sdhd_sdk.hh` from the **SDmodding SDK**. To build it, obtain that SDK separately and configure a compatible Windows C++ development environment and include path. The original development environment used Visual Studio. A complete, reproducible public build project has **not yet been packaged**; the source is provided for inspection and future development.

## Credits and acknowledgements

Special thanks to the **[SDmodding](https://github.com/SDmodding)** contributors, particularly the maintainers of the following resources:

- **[SDmodding SDK](https://github.com/SDmodding/SDK)** — development dependency and reference for game internals.
- **[TheoryEngine](https://github.com/SDmodding/TheoryEngine)** — consulted during research into the game's architecture; no direct code reuse is claimed here.
- Additional thanks to:

    ThirteenAG — developer of Ultimate ASI Loader, used to load Eternal Lightbar into Sleeping Dogs: Definitive Edition.

Eternal Lightbar was developed through reverse engineering, C++ implementation, debugging, and hands-on testing, with AI assistance during research, code development, and troubleshooting.

*Sleeping Dogs: Definitive Edition* and its associated trademarks belong to their respective rights holders. This is an unofficial fan-made modification, not affiliated with or endorsed by the game's creators or publishers.

## Source and licensing

The SDmodding SDK is an external dependency and is **not bundled** in this repository. Third-party code remains subject to its authors' terms. No license is assigned to this repository until the project's dependency and redistribution requirements have been reviewed.

## Feedback

Found a bug or an unexpected vehicle behavior? Please open a GitHub issue with reproduction steps. Contributions and suggestions are welcome, subject to a review of third-party licensing and compatibility.
