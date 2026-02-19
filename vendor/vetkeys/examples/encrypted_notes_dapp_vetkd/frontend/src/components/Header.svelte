<div class="w-full navbar bg-base-100 border-b border-base-300">
  <div class="flex-none lg:hidden">
    <label for="my-drawer-3" class="btn btn-square btn-ghost">
      <svg
        xmlns="http://www.w3.org/2000/svg"
        fill="none"
        viewBox="0 0 24 24"
        class="inline-block w-6 h-6 stroke-current"
      >
        <path
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="2"
          d="M4 6h16M4 12h16M4 18h16"
        />
      </svg>
    </label>
  </div>
  <div class="flex-1 px-2 mx-2 font-bold text-lg">
    <slot name="title" />
  </div>
  <div>
    <slot name="actions" />
  </div>
</div>
