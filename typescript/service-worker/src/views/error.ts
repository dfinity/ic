import { html, TemplateResult } from 'lit';
import { BaseView } from './base';

export interface ErrorViewProps {
  title: string;
  subtitle?: string;
}

export class ErrorView extends BaseView {
  private constructor(
    protected props: ErrorViewProps = ErrorView.defaultProps()
  ) {
    super();
  }

  static defaultProps(): ErrorViewProps {
    return { title: 'Error' };
  }

  async content(): Promise<TemplateResult> {
    return html`
      <ic-logo class="mb-3rem"></ic-logo>
      <ic-banner
        class="error"
        title="${this.props.title}"
        subtitle="${this.props.subtitle}"
      ></ic-banner>
    `;
  }

  static async load(props: ErrorViewProps): Promise<void> {
    const view = new ErrorView(props);

    return view.render();
  }
}
