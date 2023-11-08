The files in `regression_samples` are basically pcap files (not necessarily valid ones) that triggered crashes in the past.
Since the issues are fixed they don't trigger the crashes anymore.
On every pull request an [ASAN](https://clang.llvm.org/docs/AddressSanitizer.html)/[USAN](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)/[MSAN](https://clang.llvm.org/docs/MemorySanitizer.html) instrumented build opens all of them one by one.
If there is a crash - the pull request introduced memory corruption.
