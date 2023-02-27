import { TemplateResult, html, render } from 'lit';

export class BaseView {
  protected useRootView = true;

  protected addRoot(slot: TemplateResult): TemplateResult {
    return html`<ic-root>${slot}</ic-root>`;
  }

  async content(): Promise<TemplateResult> {
    return html``;
  }

  async beforeRender(): Promise<boolean> {
    return true;
  }

  async afterRender(): Promise<void> {
    return;
  }

  async render(): Promise<void> {
    const readyToRender = await this.beforeRender();
    if (!readyToRender) {
      return;
    }

    const content = await this.content();

    const element = document.getElementById('root');
    if (element) {
      render(this.addRoot(content), element);
    }

    await this.afterRender();
  }
}
