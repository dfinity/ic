import './components';
import { InstallView } from './views/install';
import { UnsupportedView } from './views/unsupported';

class App {
  private constructor() {
    // preventing app direct initialization from outer scope
  }

  private unsupported(): string {
    const unsupported = [
      ['service worker', window.navigator.serviceWorker],
      ['BigInt', window.BigInt],
      ['web assembly', window.WebAssembly],
      ['IndexedDB', window.indexedDB],
    ]
      .filter((tuple) => !tuple[1])
      .map((tuple) => tuple[0])
      .join(', ');

    return unsupported;
  }

  private async start(): Promise<void> {
    const unsupported = this.unsupported();

    if (unsupported) {
      return UnsupportedView.load({ unsupported });
    }

    return InstallView.load();
  }

  static async init(): Promise<void> {
    return new App().start();
  }
}

App.init();
