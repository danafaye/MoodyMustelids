# RF Ghidra MCP class packet

Two audiences share this folder. Only `student/` is handed out.

## Student handout: `student/`

Everything a student receives. Do not add anything from the instructor areas.

- `README.md` – class guide: schedule, key terms, evidence rules, paired tasks, Hour 6 steps
- `evidence_template.md` – one-page evidence and IOC template
- `SHA256SUMS` – checksums for the handed-out binaries (`sha256sum -c SHA256SUMS`)
- `grumpyFerret/` – release binary `grumpyFerret`, `student.md` (step-by-step guide) and `README.md`
- `soggyBadger/` – Windows executable `soggyBadger.exe`, `student.md` and `README.md`
- `restlessOtter/` – arm64 Mach-O `restlessOtter` (stripped), `student.md` and `README.md`. Arm64 only: it runs on Apple Silicon Macs.
- `vexedWolverineBonus/` – optional bonus: Linux build, `student.md`, README, checksum

## Instructor material (teacher version)

Everything in this folder outside `student/` is instructor-only: source, solutions, answer keys, generated data, verification tools and planning notes.

- `notes.md` – master instructor plan: schedule, runbooks, answer keys, prep checklist
- `grumpyFerret/` – source (`grumpyferret.c`), `Makefile`, `SOLUTION.md`, `instructor.md` (answer key), instructor README, embedded stage (`youtube_stage.h`, `embed_youtube_stage.py`), and `instructor_youtube/` (plaintext stage `youtube_stage.py`, fixtures and live-verification records)
- `soggyBadger/` – source, `Makefile`, `SOLUTION.md`, `instructor.md` (answer key), instructor README, and the Windows build
- `restlessOtter/` – source, `Makefile`, `SOLUTION.md`, `instructor.md` (answer key), instructor README, and the Mach-O build (stripped)
- `vexedWolverine/` – `src/` (source), `instructor/` (`instructor.md` answer key, `SOLUTION.md`, generator, solver, verifier, answers, and `dist/` with the Windows build), `student/` (Linux build, `student.md` guide, README, checksum), `Makefile`, README
- `ghidra/` – shared Ghidra project for the class (see note below)
- `archive/` – superseded files kept for reference; not used by the build or the handout

## Build and check

- Grumpy Ferret: `cd grumpyFerret && make release` builds `grumpyFerret`. Copy it to `student/grumpyFerret/` and regenerate `student/SHA256SUMS`. The copy in `grumpyFerret/` is named `grumpyFerret` and has the same contents as the release build.
- Vexed Wolverine: `cd vexedWolverine && make linux` builds the Linux copy into `student/`. `make windows` builds into `instructor/dist/`, which is not handed out. Copy the Linux build into `student/vexedWolverineBonus/`.
- Soggy Badger: build with its Makefile, then copy the binary into `student/soggyBadger/`.
- Restless Otter: build on a Mac with `make release` (it strips with `strip -x`). Then check with `nm restlessOtter | grep -c _ro_` (should print 0) and copy it into `student/restlessOtter/`.

## Notes

- `ghidra/RE_class.lock` and `RE_class.lock~` are Ghidra lock files left by an open project. Delete them only when Ghidra is closed.
- The Vexed Wolverine ZIP that earlier notes referred to is no longer in the folder. Rebuild the handout from `student/vexedWolverineBonus/` instead.
