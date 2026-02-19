import App from "./App.svelte";

const init = async () => {
  const app = new App({
    target: document.body,
  });
};

init();