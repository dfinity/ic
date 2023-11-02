import { LitElement, TemplateResult, css, html } from 'lit';
import { customElement, property } from 'lit/decorators.js';

@customElement('ic-banner')
export class BannerElement extends LitElement {
  static styles = css`
    :host {
      display: block;
      padding: 0.75rem;
      margin: 0 16px;
      background-color: hsla(0, 0%, 100%, 0.2);
      border: transparent;
    }

    .container {
      border-color: transparent;
      padding: 2rem;
      background-color: hsla(0, 0%, 100%, 0.8);
    }

    h1 {
      font-size: 20px;
      line-height: 20px;
    }

    [role='doc-subtitle'] {
      margin-bottom: 1rem;
    }

    [role='doc-message'] {
      margin-bottom: 1rem;
    }

    .info-message {
      text-align: center;
      display: flex;
      align-items: center;
      flex-direction: column;
      justify-content: center;
    }

    @media only screen and (max-width: 600px) {
      :host {
        margin: 0;
      }
    }
  `;

  @property({ type: String })
  title = 'Error';

  @property({ type: String })
  subtitle = '';

  render(): TemplateResult {
    if (this.subtitle) {
      return html`
        <div class="container">
          <h1>${this.title}</h1>
          <div role="doc-subtitle">${this.subtitle}</div>
          <div class="info-message">
            <slot></slot>
          </div>
        </div>
      `;
    }

    return html`
      <div class="container">
        <h1>${this.title}</h1>
        <div class="info-message">
          <slot></slot>
        </div>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'ic-banner': BannerElement;
  }
}
