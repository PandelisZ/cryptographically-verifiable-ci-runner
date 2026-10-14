// The `--require` entry of the node:test collector (see preload.js). CommonJS, so that it is only
// required on the main thread: Node also runs `--require` preloads in the thread of
// `module.register` hooks (node:test's `mock.module` uses one on Node 22), where requiring an ES
// module fails.
"use strict";

if (require("node:worker_threads").isMainThread) require("./preload.js");
