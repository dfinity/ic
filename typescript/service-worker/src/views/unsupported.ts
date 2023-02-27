import { html, TemplateResult } from 'lit';
import { BaseView } from './base';

export interface UnsupportedViewProps {
  unsupported?: string;
}

export class UnsupportedView extends BaseView {
  private constructor(
    protected props: UnsupportedViewProps = UnsupportedView.defaultProps()
  ) {
    super();
  }

  static defaultProps(): UnsupportedViewProps {
    return {};
  }

  async content(): Promise<TemplateResult> {
    const title =
      'This web browser cannot interact with the Internet Computer securely.';
    const subtitle = this.props.unsupported
      ? `Please try updating your browser or enabling support for ${this.props.unsupported}.`
      : `Please try updating your browser.`;

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
