import type { Principal } from "@dfinity/principal";

export interface PasswordModel {
    owner: Principal;
    parentVaultName: string;
    passwordName: string;
    content: string;
}

export function passwordFromContent(
    owner: Principal,
    parentVaultName: string,
    passwordName: string,
    content: string,
): PasswordModel {
    return {
        owner,
        parentVaultName,
        passwordName,
        content,
    };
}

export function summarize(note: PasswordModel, maxLength = 50) {
    const div = document.createElement("div");
    div.innerHTML = note.content;

    let text = div.innerText;
    const title = extractTitleFromDomEl(div);
    if (title) {
        text = text.replace(title, "");
    }

    return text.slice(0, maxLength) + (text.length > maxLength ? "..." : "");
}

function extractTitleFromDomEl(el: HTMLElement): string {
    const title = el.querySelector("h1");
    if (title) {
        return title.innerText;
    }

    const blockElements = el.querySelectorAll("h1,h2,p,li");
    for (const el of blockElements) {
        if (el.textContent && el.textContent.trim().length > 0) {
            return el.textContent.trim();
        }
    }
    return "";
}

export function extractTitle(html: string) {
    const div = document.createElement("div");
    div.innerHTML = html;
    return extractTitleFromDomEl(div);
}
