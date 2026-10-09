# Imperivm HD native 1440p patch

A command-line patcher that writes a 2560×1440-capable copy of the official
**Imperivm: Great Battles of Rome HD** executable (`gbr.exe`).

## What the patch does

- Adds 2560×1440 to the game's resolution list. The game switches the monitor
  to the chosen size as a real display mode and restores the desktop mode when
  it exits.
- Lets you switch resolution from the in-game Options, for example between
  2560×1440 and 1920×1080. The list only shows sizes the monitor offers as
  32-bit display modes.
- Enlarges the zoom-map column storage (2048 → 4096 columns). The storage lives
  in a new uninitialized section, and the helper code lives in a new code
  section (`.hirest`). No existing code is overwritten, including the
  GameSpy/online code.
- Redraws the full viewport, which fixes rendering above 1536 px of height.
- Makes the game DPI aware, so it works with Windows display scaling.
- Confines the cursor to the game area and puts the edge-scroll zones at its
  edges.

## Requirements

- The official HD `gbr.exe`, SHA-256
  `72b09d1abd4f311efe4213a9a1110185519bde4db4ee57769d346b475c748473`.
  The patcher refuses any other file.
- To build: Visual Studio 2019 or later (or Build Tools) with the
  *Desktop development with C++* workload.

## Build

Run `build.bat`. It produces `1440p_patch.exe`: 32-bit, with a static CRT and
no runtime dependencies.

## Patch

Drag the game's `gbr.exe` onto `1440p_patch.exe`. The patcher:

1. Writes `gbr_1440p.exe` next to it. The source is never modified.
2. Writes `DATA\CONST.INI` in the game folder with 2560×1440 first in
   `[Resolutions]`. The game reads its resolution list from this file. The
   copy inside `Packs\data.pak` stops at 1920×1080, and a loose file in `DATA`
   takes priority over it. If `DATA\CONST.INI` already exists, it is edited in
   place and the previous version is kept as `CONST.INI.bak`. If it already
   lists 2560×1440, it is left unchanged.

From a console:

```
1440p_patch.exe <gbr.exe> [output.exe] [--force]
1440p_patch.exe --identify <exe>
```

- `--force`: overwrite an existing output file.
- `--identify`: reports whether an executable is the vanilla build or a known
  patched build.

## Install

1. Back up the original `gbr.exe`, then replace it with `gbr_1440p.exe`
   (renamed to `gbr.exe`).
2. Pick 2560 × 1440 in the game's Options, or set `Resolution=` under
   `[Options]` in `Settings.ini`. The index is zero-based and only counts the
   sizes your monitor supports.

Steam's "Verify integrity of game files" restores the original `gbr.exe`.

## Known limitations

- If the game is ended from Task Manager, the display stays at the game's
  resolution until you change it back. The unpatched game behaves the same.
- Alt+Tab keeps the game's display mode, as in the unpatched game.
- The interface is not scaled. Units and menus look smaller at 1440p, and the
  main menu artwork stays 1920×1080, centred with black bars.
- Windows sizes the cursor. At 1440p with 100 % display scaling it is small;
  125 % is recommended.
