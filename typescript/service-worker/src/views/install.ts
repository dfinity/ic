import { TemplateResult, html } from 'lit';
import {
  ICHostInfoEvent,
  SaveICHostInfoMessage,
  ServiceWorkerEvents,
} from '../typings';
import { getValueFromCookie } from '../utils';
import { BaseView } from './base';
import { ErrorView } from './error';
import logger from '../logger';

export type ServiceWorkerRegistrationResult =
  | {
      registered: ServiceWorkerRegistration;
      err: null;
    }
  | {
      registered: null;
      err: string;
    };

export class InstallView extends BaseView {
  async content(): Promise<TemplateResult> {
    return html`
      <p class="transparent">This app is powered by</p>
      <ic-logo aria-label="Internet Computer."></ic-logo>
      <ic-loading></ic-loading>
      <h1 aria-label="Loading resources.">Loading Resources...</h1>
      <h3>Blockchain cryptography will make this domain more secure.</h3>
    `;
  }

  static async load(): Promise<void> {
    const view = new InstallView();

    return view.render();
  }

  updateStatus(message: string): void {
    const statusEl = document.getElementById('status');
    if (statusEl) {
      statusEl.innerText = message;
    }
  }

  resolveICHostInfo(): ICHostInfoEvent | null {
    const canisterId = getValueFromCookie('__Secure-IcCanisterId');
    if (canisterId) {
      return {
        canisterId,
      };
    }

    return null;
  }

  async registerServiceWorker(): Promise<ServiceWorkerRegistrationResult> {
    try {
      const registered = await navigator.serviceWorker.register('/sw.js');

      return {
        registered,
        err: null,
      };
    } catch (e) {
      return {
        registered: null,
        err: String(e),
      };
    }
  }

  async beforeRender(): Promise<boolean> {
    logger.info(
      `Installing a service worker ${process.env.VERSION} to proxy and validate content...`
    );

    // Ok, let's install the service worker...
    // note: if the service worker was already installed, when the browser requested <domain>/, it would have
    // proxied the response from <domain>/<canister-id>/, so this bootstrap file would have never been
    // retrieved from the boundary nodes
    const registration = await this.registerServiceWorker();
    if (registration.err) {
      logger.error(`Service worker registration failed (${registration.err})`);
      await ErrorView.load({
        title:
          'Failed to create a secure connection with the Internet Computer.',
        subtitle:
          'Please try clearing your browser cache and refreshing the page to try again.',
      });

      return false;
    }

    return true;
  }

  async afterRender(): Promise<void> {
    try {
      // delays code execution until serviceworker is ready
      const worker = await navigator.serviceWorker.ready;
      // caches the domain ic host equivalent to avoid an additional fetch call
      const icHostInfo = this.resolveICHostInfo();
      if (icHostInfo) {
        const message: SaveICHostInfoMessage = {
          action: ServiceWorkerEvents.SaveICHostInfo,
          data: icHostInfo,
        };
        if (worker.active) {
          worker.active.postMessage(message);
        }
      }
      // reload the page so the service worker can intercept the requests
      window.location.reload();
    } catch (e) {
      logger.error(`Service worker install failed (${String(e)})`);

      await ErrorView.load({
        title:
          'Failed to create a secure connection with the Internet Computer',
      });
    }
  }
}
