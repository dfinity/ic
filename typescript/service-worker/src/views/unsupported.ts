import { html, TemplateResult } from 'lit';
import { BaseView } from './base';

export interface UnsupportedViewProps {
  unsupported?: string;
}

export class UnsupportedView extends BaseView {
  static serviceWorkerUnsupported = 'service worker';

  private constructor(
    protected props: UnsupportedViewProps = UnsupportedView.defaultProps()
  ) {
    super();
  }

  static defaultProps(): UnsupportedViewProps {
    return {};
  }

  unsupportedServiceWorkerElement(): TemplateResult {
    return html`<style>
        ul {
          list-style: none;
        }

        hr {
          width: 100%;
          margin-bottom: 16px;
          border: 1px solid #e5e3e9;
        }

        @media only screen and (max-width: 600px) {
          ul {
            list-style: square;
          }
        }
      </style>
      <hr />
      <div>
        <strong>What could be causing this?</strong>
        <br />
        <ul>
          <li>
            You're using a 'mini' version of a browser within another app (e.g.
            clicking a link in a social media app).
          </li>
          <li>
            You're in 'Private' or 'Incognito' browsing mode (e.g. Firefox
            privacy mode).
          </li>
          <li>
            Your browser is outdated or not fully supported (e.g. Opera Mini).
          </li>
        </ul>
      </div>
      <div>
        <strong>What can you do?</strong>
        <br />
        <ul>
          <li>
            Try opening
            <a href="${window.location.href}" rel="noopener noreferrer"
              >this page</a
            >
            in a fully-featured web browser like Chrome, Firefox, or Safari.
          </li>
          <li>
            If you're in a 'Private' or 'Incognito' mode, exit and try again.
          </li>
          <li>Try updating your browser to make sure its up-to-date.</li>
        </ul>
      </div>
      <div>
        <strong>Still having issues?</strong>
        <br /><br />
        Feel free to ask for help on
        <a
          href="https://forum.dfinity.org/"
          target="_blank"
          rel="noopener noreferrer"
          >the Internet Computer forum</a
        >.
      </div>`;
  }

  async content(): Promise<TemplateResult> {
    const title = this.props.unsupported
      ? 'Oops! Something went wrong.'
      : 'This web browser cannot interact with the Internet Computer securely.';
    const subtitle = this.props.unsupported
      ? `Your web browser isn't compatible with this dapp.`
      : `Please try updating your browser.`;

    if (
      this.props.unsupported?.includes(UnsupportedView.serviceWorkerUnsupported)
    ) {
      const subtitleEl = this.unsupportedServiceWorkerElement();

      return html`
        <ic-logo class="mb-3rem"></ic-logo>
        <ic-banner
          aria-label="${title} ${subtitle}"
          title="${title}"
          subtitle="${subtitle}"
        >
          ${subtitleEl}
        </ic-banner>
      `;
    }

    return html`
      <ic-logo class="mb-3rem"></ic-logo>
      <ic-banner
        aria-label="${title} ${subtitle}"
        title="${title}"
        subtitle="${subtitle}"
      ></ic-banner>
    `;
  }

  static async load(props: UnsupportedViewProps): Promise<void> {
    const view = new UnsupportedView(props);

    return view.render();
  }
}
