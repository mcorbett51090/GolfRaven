/**
 * Minimal confirm/unsubscribe HTML pages. Deliberately no CSS/JS: the
 * confirm action is a plain `<form method="post">` so a GET never
 * confirms (task requirement — email link scanners that GET the link
 * don't trigger it) and no `script-src`/`style-src` CSP allowance is
 * needed (see responses.ts htmlResponse: `default-src 'none'`).
 */

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(title)}</title>
  </head>
  <body>
    ${body}
  </body>
</html>`;
}

export function confirmPromptPage(actionUrl: string): string {
  return page(
    "Confirm your GolfRaven signup",
    `<h1>Confirm your signup</h1>
     <p>Click the button below to confirm you'd like GolfRaven launch updates.</p>
     <form method="post" action="${escapeHtml(actionUrl)}">
       <button type="submit">Confirm my signup</button>
     </form>`,
  );
}

export function confirmInvalidPage(): string {
  return page(
    "Link expired",
    `<h1>This link is invalid or has expired</h1>
     <p>Confirmation links work once and expire after 48 hours. If you still want to sign up, submit the form on the GolfRaven site again.</p>`,
  );
}

export function confirmSuccessPage(): string {
  return page(
    "You're confirmed",
    `<h1>You're confirmed</h1>
     <p>Thanks — you're on the list. We'll email you when GolfRaven launches.</p>`,
  );
}

export function unsubscribePromptPage(actionUrl: string): string {
  return page(
    "Unsubscribe from GolfRaven",
    `<h1>Unsubscribe</h1>
     <p>Click the button below to stop receiving GolfRaven emails.</p>
     <form method="post" action="${escapeHtml(actionUrl)}">
       <button type="submit">Unsubscribe</button>
     </form>`,
  );
}

export function unsubscribeInvalidPage(): string {
  return page(
    "Link invalid",
    `<h1>This link is invalid</h1>
     <p>We couldn't find a matching signup for this link.</p>`,
  );
}

export function unsubscribeSuccessPage(): string {
  return page(
    "You're unsubscribed",
    `<h1>You're unsubscribed</h1>
     <p>You won't receive any more GolfRaven emails at this address.</p>`,
  );
}
