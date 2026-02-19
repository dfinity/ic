import { writable } from "svelte/store";
import { auth } from "./auth";

interface DraftModel {
    content: string;
}

let initialDraft: DraftModel = {
    content: "",
};

try {
    const getDraft = localStorage.getItem("draft");
    if (getDraft) {
        const savedDraft = JSON.parse(getDraft) as DraftModel;
        if ("content" in savedDraft && "tags" in savedDraft) {
            initialDraft = savedDraft;
        }
    } else {
        throw new Error("Draft not found");
    }
} catch {
    // ignore error
}

export const draft = writable<DraftModel>(initialDraft);

draft.subscribe((draft) => {
    localStorage.setItem("draft", JSON.stringify(draft));
});

auth.subscribe(($auth) => {
    if ($auth.state === "anonymous") {
        draft.set(initialDraft);
    }
});
