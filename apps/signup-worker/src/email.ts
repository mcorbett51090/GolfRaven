/**
 * Resend email send + the confirmation-email template.
 *
 * The low-level `sendViaResend` send path and its "success only after
 * Resend accepts" guarantee are adapted from the owner's production
 * Worker (raven-site-kit/secure-upload/worker/src/email.ts): `ok` requires
 * a 2xx AND a provider message id. A 2xx with no id is treated as a
 * failure — reporting "sent" when we can't prove it is exactly the
 * failure mode that guarantee exists to prevent, and it holds here too.
 *
 * Every email carries `List-Unsubscribe` (a real https URL) and
 * `List-Unsubscribe-Post: List-Unsubscribe=One-Click` (RFC 8058), per
 * gate-review S6/README "How signups work".
 */

import type { Env } from "./config";

const RESEND_API_URL = "https://api.resend.com/emails";

export interface EmailMessage {
  from: string;
  to: string[];
  subject: string;
  html: string;
  headers?: Record<string, string>;
}

export type SendResult = { ok: true; providerId: string } | { ok: false; error: string };

/**
 * The Resend JSON body. Exported for the byte-identity test, same reasoning
 * as the reference module: key order and shape are the observable contract.
 */
export function resendBody(msg: EmailMessage): Record<string, unknown> {
  const body: Record<string, unknown> = { from: msg.from };
  body.to = msg.to;
  body.subject = msg.subject;
  body.html = msg.html;
  if (msg.headers) body.headers = msg.headers;
  return body;
}

async function sendViaResend(env: Env, msg: EmailMessage): Promise<SendResult> {
  let res: Response;
  try {
    res = await fetch(RESEND_API_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(resendBody(msg)),
    });
  } catch {
    return { ok: false, error: "network-error-calling-resend" };
  }

  const data = (await res.json().catch(() => null)) as { id?: string; message?: string } | null;
  if (res.ok && data && typeof data.id === "string" && data.id.length > 0) {
    return { ok: true, providerId: data.id };
  }
  return { ok: false, error: data?.message ?? `resend-http-${res.status}` };
}

/** Sends through Resend (the only configured provider — see README). */
export async function sendEmail(env: Env, msg: EmailMessage): Promise<SendResult> {
  return sendViaResend(env, msg);
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Builds the double-opt-in confirmation email. `confirmUrl` and
 * `unsubscribeUrl` are already-built absolute https URLs (see index.ts).
 */
export function buildConfirmationEmail(params: {
  fromEmail: string;
  to: string;
  confirmUrl: string;
  unsubscribeUrl: string;
}): EmailMessage {
  const { fromEmail, to, confirmUrl, unsubscribeUrl } = params;
  const safeConfirm = escapeHtml(confirmUrl);
  const safeUnsub = escapeHtml(unsubscribeUrl);
  return {
    from: fromEmail,
    to: [to],
    subject: "Confirm your GolfRaven signup",
    html: `<!doctype html>
<html>
  <body style="font-family: sans-serif; max-width: 480px; margin: 0 auto; padding: 24px;">
    <h1 style="font-size: 20px;">Confirm your email</h1>
    <p>Click below to confirm you'd like GolfRaven launch updates. This link expires in 48 hours and works once.</p>
    <p><a href="${safeConfirm}" style="display:inline-block;padding:12px 20px;background:#0a5c36;color:#fff;text-decoration:none;border-radius:6px;">Confirm my signup</a></p>
    <p style="color:#666;font-size:13px;">If the button doesn't work, paste this link into your browser:<br>${safeConfirm}</p>
    <hr style="border:none;border-top:1px solid #ddd;margin:24px 0;">
    <p style="color:#999;font-size:12px;">Didn't sign up? Ignore this email, or <a href="${safeUnsub}">unsubscribe</a>.</p>
  </body>
</html>`,
    headers: {
      "List-Unsubscribe": `<${unsubscribeUrl}>`,
      "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
    },
  };
}

/** Sends the confirmation email. Returns the real SendResult — see the module header note. */
export async function sendConfirmationEmail(
  env: Env,
  params: { to: string; confirmUrl: string; unsubscribeUrl: string },
): Promise<SendResult> {
  const msg = buildConfirmationEmail({ fromEmail: env.RESEND_FROM_EMAIL, ...params });
  return sendEmail(env, msg);
}
