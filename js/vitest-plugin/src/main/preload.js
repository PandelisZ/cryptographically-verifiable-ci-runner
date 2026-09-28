// Loaded in the Vitest main process with `--import` (the vci adapter adds it to the node command
// line). Installs the main-process collector before Vitest loads the config, so reads and env
// lookups made by the config file, inline plugins and globalSetup files are recorded. Inert
// unless VCI_OUT is set; a no-op in Vitest workers.
import { installMain } from "../worker/collector.js";

installMain();
