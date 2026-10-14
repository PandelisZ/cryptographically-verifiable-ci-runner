// node:test collector, part 1. vci starts `node --require <preload.cjs> <user flags>
// --import ./late.js --test <file>`; Node passes the flags on to the child process that runs the
// test file, where this installs the collector (fs/env/process/network patches and module hooks)
// before any preload of the user's (`--require` modules run before `--import` ones, in order).
// The `node --test` process itself also loads `--require` modules: there it installs the
// main-process collector instead, whose records the reporter adds to the file. Inert unless
// VCI_OUT and VCI_TEST_FILE are set.
import { installNodeTest, installNodeTestParent } from "../worker/collector.js";

if (!installNodeTest()) installNodeTestParent();
