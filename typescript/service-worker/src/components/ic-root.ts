import { LitElement, css, html, TemplateResult } from 'lit';
import { customElement } from 'lit/decorators.js';

@customElement('ic-root')
export class RootElement extends LitElement {
  static styles = css`
    :host {
      margin: 0;
      min-height: 100vh;
      text-align: center;
      font-size: 14px;
      padding: 5em 1em 1em;
      box-sizing: border-box;
      font-family: sans-serif;
      font-style: normal;
      color: #1c1e21;
      display: flex;
      flex-flow: column nowrap;
      background: rgb(241, 238, 245);
      background: linear-gradient(
        180deg,
        rgba(241, 238, 245, 1) 68%,
        rgba(60, 1, 186, 0.17) 100%
      );
    }

    ::slotted(h1) {
      font-size: 20px;
      line-height: 32px;
      margin-block-start: 0.5em;
      margin-block-end: 0.5em;
    }

    ::slotted(h3) {
      color: #181818;
      font-weight: 400;
      font-size: 14px;
      line-height: 17px;
      margin-block-start: 0.5em;
      margin-block-end: 0.5em;
    }

    ::slotted(.transparent) {
      opacity: 0.6;
    }

    ::slotted(.mb-3rem) {
      margin-bottom: 3rem;
    }
  `;

  render(): TemplateResult {
    return html`<slot></slot>`;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'ic-root': RootElement;
  }
}
