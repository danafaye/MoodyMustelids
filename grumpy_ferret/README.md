# Grumpy Ferret (student)

Linux x86-64 classroom crackme. Run it from a shell as `./grumpyFerret <input>`.

It is a benign educational program. It makes a few network requests, prints text and exits. It does not execute anything it downloads, and it has no real command-and-control server or persistence.

Python 3 at `/usr/bin/python3` is needed for the optional final stage. Without it, the core exercise still works.

## What to establish

1. **Execution flow.** Find the main routine and the order of its major steps: display, configuration, network activity, anti-debug check, input check and reveal.
2. **Network activity.** Connect the DNS and HTTP events you see in the sandbox to the code that makes them. Give the function address and list its callers.
3. **Configuration.** Find the encoded configuration in the binary. Work out the decoding from the code and reproduce the output yourself. Name each field and what consumes it.
4. **Input check.** Describe the transform the program applies to your input, and how you would invert it. Confirm your inverse against the code. Keep any recovered input out of shared notes until your partner has checked it.
5. **Anti-debug gate.** Find the check and state which behavior it controls and which behavior happens before it.
6. **Decoys.** Some strings look like flags or indicators but are not used on the success path. Decide which ones are used, and show the reference.

## Indicators

Record each configured or observed domain and IP in your IOC table, with its label. Reserved documentation names and addresses are `classroom decoy`. Public services the program contacts are `shared service`.

## Optional final stage

The program contains an encoded helper. It reads a public page without login and retrieves a public text resource. The helper runs on every launch, so its network requests appear in the sandbox. Its output, including any text flag, is shown only after you enter the correct serial. Record what it attempted, what it retrieved, and whether you saw the retrieval yourself. Do not assume a successful retrieval unless you observed one.

## Files

- `grumpyFerret` – the stripped release binary you analyze.
- `student.md` – the step-by-step guide for this exercise.
- `README.md` – this file.
