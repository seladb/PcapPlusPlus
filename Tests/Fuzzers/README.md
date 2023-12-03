The fuzzers here are used by [oss-fuzz](https://github.com/google/oss-fuzz/tree/master/projects/pcapplusplus).
Oss-fuzz uses its own [tracker for found issues](https://bugs.chromium.org/p/oss-fuzz/issues/list?q=proj%3Apcapplusplus&can=1).

Read more about oss-fuzz and fuzzing [here](https://google.github.io/oss-fuzz/).

Current fuzzers either try to open and parse different pcap, pcapng and snoop files or convert pcap files to pcapng and vice versa.

To analyze the fuzzing coverage (code that is called and that is not by the fuzzers) open https://introspector.oss-fuzz.com/project-profile?project=pcapplusplus and click on the `Code coverage report` link to follow to the latest coverage statistics.
It may also generate it locally using the [instructions](https://google.github.io/oss-fuzz/advanced-topics/code-coverage/).

The fuzzers are built as part of CI, you will be notified you break something.
See [oss-fuzz instructions](https://google.github.io/oss-fuzz/advanced-topics/reproducing/#building-using-docker) how to build locally.
You may also check [how it is built in CI](https://github.com/sashashura/PcapPlusPlus/blob/4d12307aac20d6387956a1eae0b5274a0d3f922b/.cirrus.yml#L71-L83).
