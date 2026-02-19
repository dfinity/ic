<script lang="ts">
  import { auth, logout } from '../store/auth';
  import FaPlusSquare from 'svelte-icons/fa/FaPlusSquare.svelte';
  import FaBook from 'svelte-icons/fa/FaBook.svelte';
  import FaMobileAlt from 'svelte-icons/fa/FaMobileAlt.svelte';
  import FaDoorOpen from 'svelte-icons/fa/FaDoorOpen.svelte';
  import Disclaimer from './Disclaimer.svelte';
</script>

<div class="bg-base-200 drawer drawer-mobile min-h-screen">
  <input id="my-drawer-3" type="checkbox" class="drawer-toggle" />
  <div class="flex flex-col drawer-content lg:!z-[1000]">
    <div class="flex-1">
      <slot />
    </div>
    <Disclaimer />
  </div>
  <div class="drawer-side">
    <label for="my-drawer-3" class="drawer-overlay" />
    <aside
      class="flex flex-col justify-between border-r border-base-300 bg-base-100 text-base-content w-64 sm:w-80 "
    >
      <div
        class="sticky h-16 py-4 pl-5 text-2xl font-bold border-b border-base-300 text-primary dark:text-white"
      >
        Encrypted Notes
      </div>
      <div class="border-b">
        <div class="pl-4">My Principal:</div>
        <div class="pl-4">{$auth.client.getIdentity().getPrincipal()}</div>
      </div>
      <ul
        class="p-4 overflow-y-auto menu w-full bg-base-100 flex-1 flex flex-col"
      >
        <li>
          <a href="/">
            <span class="w-6 h-6 p-1 mr-2">
              <FaPlusSquare />
            </span>
            New note
          </a>
        </li>
        <li>
          <a href="/notes">
            <span class="w-6 h-6 p-1 mr-2">
              <FaBook />
            </span>
            Your notes</a
          >
        </li>
        <li class="flex-1" />
        <li>
          <button on:click={() => logout()}>
            <span class="w-6 h-6 p-1 mr-2">
              <FaDoorOpen />
            </span>
            Log out</button
          >
        </li>
      </ul>
      <div class="px-5 pb-4">
        <img
          src="/img/ic-badge-powered-by-crypto_transparent-white-text.png"
          alt="Powered by the Internet Computer"
          class="hidden dark:inline "
        />
        <img
          src="/img/ic-badge-powered-by-crypto_transparent-dark-text.png"
          alt="Powered by the Internet Computer"
          class="dark:hidden inline "
        />
      </div>
    </aside>
  </div>
</div>
