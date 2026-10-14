// node:test collector, part 2, loaded with `--import` after the user's own `--import`/`--require`
// preloads. Module hooks registered last run first: these see every specifier and the final
// resolution and load of the whole chain, including what the user's hooks answer themselves.
import { installLateHooks } from "../worker/collector.js";

installLateHooks();
