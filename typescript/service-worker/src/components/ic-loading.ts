import { LitElement, html, css, TemplateResult } from 'lit';
import { customElement } from 'lit/decorators.js';

@customElement('ic-loading')
export class LoadingElement extends LitElement {
  static styles = css`
    @keyframes rotate {
      from {
        transform: rotate(0deg);
      }
      to {
        transform: rotate(360deg);
      }
    }

    @-webkit-keyframes rotate {
      from {
        -webkit-transform: rotate(0deg);
      }
      to {
        -webkit-transform: rotate(360deg);
      }
    }

    :host {
      display: block;
      width: 80px;
      height: 80px;
      margin: 40px auto;
      border: solid 6px rgba(56, 24, 185, 1);
      border-radius: 50%;
      border-right-color: rgba(56, 24, 185, 0.25);
      border-bottom-color: rgba(56, 24, 185, 0.25);
      border-left-color: rgba(56, 24, 185, 0.25);
      -webkit-transition: all 0.5s ease-in;
      -webkit-animation-name: rotate;
      -webkit-animation-duration: 1.5s;
      -webkit-animation-iteration-count: infinite;
      -webkit-animation-timing-function: ease-in-out;

      transition: all 0.5s ease-in;
      animation-name: rotate;
      animation-duration: 1.5s;
      animation-iteration-count: infinite;
      animation-timing-function: ease-in-out;
    }
  `;

  render(): TemplateResult {
    return html``;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'ic-loading': LoadingElement;
  }
}
