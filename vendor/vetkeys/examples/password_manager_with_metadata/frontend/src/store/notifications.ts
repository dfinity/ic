import { writable } from "svelte/store";

export interface Notification {
    type: "error" | "info" | "success";
    message: string;
    id: number;
}

export type NewNotification = Omit<Notification, "id">;

let nextId = 0;

export const notifications = writable<Notification[]>([]);

export function addNotification(notification: NewNotification, timeout = 2000) {
    const id = nextId++;

    notifications.update(($n) => [...$n, { ...notification, id }]);

    setTimeout(() => {
        notifications.update(($n) => $n.filter((n) => n.id != id));
    }, timeout);
}

export function showError(e: Error, message: string): never {
    addNotification({ type: "error", message });
    console.error(e);
    console.error(e.stack);
    throw e;
}
