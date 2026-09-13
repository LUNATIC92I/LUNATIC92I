import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// Without `test.globals: true` in vitest.config.ts, @testing-library/react's
// automatic per-test cleanup (which relies on detecting a global `afterEach`)
// never registers, so the DOM from one test leaks into the next.
afterEach(cleanup);
