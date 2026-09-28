// Loaded in every Vitest worker via `--import` (injected into `project.config.execArgv` by the
// plugin). Installs the collector before Vitest or any test code runs.
import { install } from "./collector.js";

install({ preload: true });
