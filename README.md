### Overview
This is a small proof-of-concept showing how to use Certora's Sunbeam prover on Wasm generated from C.

This repository contains a bounded Wasm witness model for the `concat_ws` overflow mechanism behind [CVE-2025-3277](https://nvd.nist.gov/vuln/detail/CVE-2025-3277).

It demonstrates that, for one concrete witness in this model, the buggy version violates and the fixed version verifies. It is not intended as a universal proof over all SQLite inputs. Instead, this provides evidence that the approach could be extended to broader verification with additional modeling and engineering effort.

To that end,
we developed a simplified model of the heap, using AI, against which the function `concatFuncCore` is written. 

The bug is on line 222: `n += (argc-1)*nSep;`. If you compile and verify this version, the tool will show a violation, which will manifest as a trap (`unreachable` in wasm) which Sunbeam will treat as an `assert(false).`

If you fix this line of code to be this: `n += (argc-1)*(i64)nSep;` (commented out in the code),
then the verification will succeed.



### How to run
Compile the `mocksql.c` file to generate wasm like so:
```
clang --target=wasm32 -O0 -mbulk-memory -nostdlib  -Wl,--export-all -Wl,--no-entry   mocksql.c -o concat_mock.wasm
```

Then run Certora's Sunbeam verifier for wasm like so (assuming it is [installed](https://docs.certora.com/en/latest/docs/sunbeam/installation.html)):
```
certoraSorobanProver sunbeam.conf
```


### Additional Notes
The current `mocksql.c` harness is a bounded verification model, not a full model of SQLite's runtime.

- The proof target is a single concrete witness with `argc = 3`, `nSep = 2147483647`, and three 1-byte values.
- The heap model tracks allocation size and liveness, but it is intentionally small and seeded by the verifier harness before `run_case`.
- The fake SQLite layer uses shadow state for exactly three argv slots, three values, and one result context.
- The result "buggy version violates, fixed version verifies" should be read as a witness-level proof of the CVE mechanism in this model, not as a universal proof over all possible inputs.

The model is split into three layers:

1. `concatFuncCore`: This is the function under test. It preserves the loop structure and allocation/concatenation logic relevant to the original bug.

2. Bounded heap model: The heap tracks allocation size and liveness for a small number of allocation ids. It is intentionally bounded and seeded specifically for this witness.

3. Shadow SQLite state: The harness models exactly three argv slots, three value records, and one result context using small shadow globals.

Object ids are used as follows:

- `1`: result context
- `2`: argv array
- `3`: separator buffer
- `4`: shared text buffer
- `5`, `6`, `7`: value records
- `8+`: dynamic allocations returned by `sqlite3_malloc64`

`HEAP_MAX = 10` is a harness bound, not a claim about SQLite in general.

This model is designed to preserve the parts of the program relevant to the CVE witness:

- integer size arithmetic
- allocation size
- pointer offset tracking
- read/write bounds checks
- selected SQLite-facing state for argv, values, and result context

It does not attempt to model:

- arbitrary SQLite runtime behavior
- general byte-level memory contents
- all possible heap interactions
- all possible input values

So the claim is intentionally narrow: this repository demonstrates that, for one concrete witness in this bounded model, the buggy version violates and the fixed version verifies.


#### AI Acknowledgement
We used Claude Code, ChatGPT, and Codex for developing the proof of concept.
