# Contributing to PcapPlusPlus

Thanks for contributing to PcapPlusPlus! Any contribution is highly welcome and appreciated

If you haven't already, please take a look at [PcapPlusPlus web-site](http://seladb.github.io/PcapPlusPlus-Doc) which provides a lot of information on exsiting features and capabilities, tutorials and build instructions

## Bug Reports

If you find a bug, please don't hesitate to open a GiHub issue for it. Any bug report is highly welcome. In order for the bug to be solved as quickly as possible, please make sure to provide the following details:
- Verify that the bug is easily reproducable, we can't do much with bugs we can't reproduce
- A detailed explanation of the issue - what did you expect to happen vs. what really happenned?
- The operating system you're using, please include the OS version as well
- If you can provide a pcap file or anything else that will help us to reproduce the bug / verify the fix, please do so
- If you already looked at the code and found the root cause - that's great! You can either issue a GitHub pull request (please see below how) or point us to the exact place in the code where you think the bug is

## Pull Requests

Every code contribution to this project is highly valued and appreciated. I encourage you to contribute any code, from small fixes or typos, up to bugfixes and new features. But when doing so, in order to get your pull request merged as fast as possible, please pay attention to the following:
- Please make sure to fork the **dev** branch and not **master**, so the pull request will happen on **dev**
- After you're done writing your code, please make sure that:
   - You added unit-tests for all of the new code, either on `Tests/Packet++Test` or `Tests/Pcap++Test` (whichever makes sense)
   - PcapPlusPlus compiles successfully on your machine, including all unit-tests and examples (just run `make` from PcapPlusPlus main directory)
   - Unit-tests pass succssfully on your machine (both `Tests/Packet++Test` and `Tests/Pcap++Test`)
   - All new APIs are well documented using Doxygen (please use @ for keywords)
- After you commit the code and push it to GitHub, before creating the pull request please make sure that:
   - You merge all new code from **dev** to your fork
   - Register an account on Appveyor and TravisCI and make sure all unit-tests pass on all platforms
- Create a GitHub pull request. In the pull request please document what it contains. If it's a bugfix, please assign the bug number (using the # sign). The process of handling pull requests is as follows:
   - We'll try to review it as quickly as possible
   - We'll review the code that was changed/added and comment either next to specific code lines or in the pull request thread
   - Please try to respond to these comments as quickly as possible, make the neccessary fixes and add them to the pull request
   - After review is done we'll merge the pull request into **dev** branch, and assuming all CI tests pass we'll merge it into **master**

This process may seem long and complicated but it's actually quite short and straight-forward most of the times, especially for small contributions.

If you make sure to follow this guide your code contribution should be merged in no time!

Thank you very much for your contribution! please help us make PcapPlusPlus better!
