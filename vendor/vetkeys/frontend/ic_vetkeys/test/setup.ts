import { beforeAll } from "vitest";
import indexeddb from "fake-indexeddb";

beforeAll(() => {
    globalThis.indexedDB = indexeddb;
});
