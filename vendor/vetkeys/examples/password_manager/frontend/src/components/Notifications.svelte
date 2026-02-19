<script lang="ts">
    import { type Notification, notifications } from "../store/notifications";
    import { fly, fade } from "svelte/transition";

    const classMap: Record<Notification["type"], string> = {
        info: "alert-info",
        error: "alert-error",
        success: "alert-success",
    };
</script>

<div class="absolute right-4 bottom-4 flex flex-col max-w-xs space-y-4">
    {#each $notifications as n (n.id)}
        <div
            class="alert {classMap[n.type]} bg-opacity-100 text-white"
            in:fly={{ x: 100, duration: 200 }}
            out:fade
        >
            <p>{n.message}</p>
        </div>
    {/each}
</div>
