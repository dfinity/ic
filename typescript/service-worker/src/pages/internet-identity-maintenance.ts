import { html } from './html';

export const internetIdentityMaintenanceTemplate = (
  errorMessage: string
) => html`
  <html>
    <head>
      <meta charset="utf8" />
      <title>Internet Identity Maintenance</title>
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <link rel="icon" type="image/x-icon" href="/favicon.ico" />
      <style>
        html,
        body {
          padding: 0;
          margin: 0;
          height: 100%;
        }
        body {
          text-align: center;
          font-size: 16px;
          padding: 5em 1em 1em;
          box-sizing: border-box;
          font-family: sans-serif;
          display: flex;
          flex-flow: column nowrap;
          justify-content: space-between;
        }
      </style>
    </head>

    <body>
      <main>
        <h1>Internet Identity is under maintenance</h1>
        <p>
          Visit the
          <a href="https://forum.dfinity.org/">
            Internet Computer Developer Forum
          </a>
          for relevant announcements.
        </p>

        <p>Error details:</p>

        <code> ${errorMessage} </code>
      </main>
    </body>
  </html>
`;
