"""
Email service for sending verification emails using Gmail SMTP
Bypasses Supabase's email rate limits
"""
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional


# ---------------------------------------------------------------------------
# Shared brand constants
# ---------------------------------------------------------------------------
BRAND_NAME   = "EloRag"
BRAND_COLOR  = "#4F46E5"          # indigo-600
BRAND_DARK   = "#3730A3"          # indigo-800  (hover / accents)
BRAND_LIGHT  = "#EEF2FF"          # indigo-50   (background tint)
BRAND_TEXT   = "#1E1B4B"          # very dark indigo for headings

_BASE_STYLES = f"""
    /* ── reset ── */
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
        font-family: 'Segoe UI', Arial, sans-serif;
        background-color: #f1f5f9;
        color: #374151;
        line-height: 1.7;
        padding: 32px 16px;
    }}
    /* ── wrapper ── */
    .wrapper {{
        max-width: 580px;
        margin: 0 auto;
        background: #ffffff;
        border-radius: 12px;
        overflow: hidden;
        box-shadow: 0 4px 24px rgba(0,0,0,.10);
    }}
    /* ── header ── */
    .header {{
        background: linear-gradient(135deg, {BRAND_COLOR} 0%, {BRAND_DARK} 100%);
        padding: 32px 40px 28px;
        text-align: center;
    }}
    .header .logo-text {{
        font-size: 28px;
        font-weight: 800;
        color: #ffffff;
        letter-spacing: -0.5px;
    }}
    .header .logo-dot {{
        color: #a5b4fc;
    }}
    .header .tagline {{
        font-size: 12px;
        color: #c7d2fe;
        margin-top: 4px;
        letter-spacing: 1.5px;
        text-transform: uppercase;
    }}
    /* ── content ── */
    .content {{
        padding: 36px 40px;
    }}
    .content h2 {{
        font-size: 20px;
        font-weight: 700;
        color: {BRAND_TEXT};
        margin-bottom: 12px;
    }}
    .content p {{
        font-size: 15px;
        color: #4b5563;
        margin-bottom: 14px;
    }}
    /* ── badge ── */
    .badge {{
        display: inline-block;
        padding: 5px 16px;
        background-color: {BRAND_LIGHT};
        color: {BRAND_COLOR};
        border: 1px solid #c7d2fe;
        border-radius: 999px;
        font-weight: 700;
        font-size: 14px;
        margin: 4px 0 16px;
    }}
    /* ── CTA button ── */
    .btn-wrap {{ text-align: center; margin: 28px 0 20px; }}
    .btn {{
        display: inline-block;
        padding: 14px 36px;
        background: linear-gradient(135deg, {BRAND_COLOR} 0%, {BRAND_DARK} 100%);
        color: #ffffff !important;
        text-decoration: none;
        border-radius: 8px;
        font-size: 15px;
        font-weight: 700;
        letter-spacing: 0.3px;
    }}
    /* ── url fallback ── */
    .url-box {{
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 6px;
        padding: 12px 16px;
        font-size: 12px;
        color: #64748b;
        word-break: break-all;
        margin-bottom: 20px;
    }}
    /* ── divider ── */
    .divider {{
        height: 1px;
        background: #e5e7eb;
        margin: 24px 0;
    }}
    /* ── info box ── */
    .info-box {{
        background: {BRAND_LIGHT};
        border-left: 4px solid {BRAND_COLOR};
        border-radius: 0 6px 6px 0;
        padding: 14px 18px;
        font-size: 14px;
        color: {BRAND_TEXT};
        margin-bottom: 20px;
    }}
    /* ── footer ── */
    .footer {{
        background: #f8fafc;
        border-top: 1px solid #e5e7eb;
        padding: 20px 40px;
        text-align: center;
        font-size: 12px;
        color: #9ca3af;
        line-height: 1.8;
    }}
    .footer a {{ color: #6366f1; text-decoration: none; }}
"""

def _html_wrapper(header_icon: str, header_title: str, body_html: str, footer_note: str = "") -> str:
    """Wrap body HTML in the shared EloRag branded shell."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>{BRAND_NAME}</title>
  <style>{_BASE_STYLES}</style>
</head>
<body>
  <div class="wrapper">

    <!-- HEADER -->
    <div class="header">
      <div class="logo-text">{BRAND_NAME}<span class="logo-dot">.</span></div>
      <div class="tagline">Governance · RAG · Multi-Tenant</div>
    </div>

    <!-- BODY -->
    <div class="content">
      <h2>{header_icon}&nbsp; {header_title}</h2>
      {body_html}
    </div>

    <!-- FOOTER -->
    <div class="footer">
      {footer_note if footer_note else f"&copy; {BRAND_NAME}. All rights reserved."}
      <br/>
      <span>If you did not expect this email, you can safely ignore it.</span>
    </div>

  </div>
</body>
</html>"""


class EmailService:
    def __init__(
        self,
        mail_from: str,
        password: str,
        smtp_server: str = "mail.elorag.com",
        smtp_port: int = 465,
        use_ssl: bool = True,
    ):
        self.mail_from   = mail_from
        self.password    = password
        self.smtp_server = smtp_server
        self.smtp_port   = smtp_port
        self.use_ssl     = use_ssl

    # ------------------------------------------------------------------
    # Core sender
    # ------------------------------------------------------------------
    def send_email(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: Optional[str] = None
    ) -> bool:
        """Send an email via SMTP (SSL or STARTTLS based on config)."""
        try:
            message = MIMEMultipart('alternative')
            message['From']    = f"{BRAND_NAME} <{self.mail_from}>"
            message['To']      = to_email
            message['Subject'] = subject

            if text_body:
                message.attach(MIMEText(text_body, 'plain'))
            message.attach(MIMEText(html_body, 'html'))

            if self.use_ssl:
                with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port) as server:
                    server.login(self.mail_from, self.password)
                    server.send_message(message)
            else:
                with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                    server.starttls()
                    server.login(self.mail_from, self.password)
                    server.send_message(message)

            return True

        except Exception as e:
            import traceback
            print(f"[{BRAND_NAME}] Failed to send email to {to_email}: {str(e)}")
            traceback.print_exc()
            return False

    # ------------------------------------------------------------------
    # 1. Email Verification
    # ------------------------------------------------------------------
    def send_verification_email(self, to_email: str, verification_url: str) -> bool:
        """Send email verification link after registration."""
        subject = f"Verify your {BRAND_NAME} account"

        body = f"""
        <p>Welcome to <strong>{BRAND_NAME}</strong>! We're excited to have you on board.</p>
        <p>Please verify your email address to activate your account:</p>
        <div class="btn-wrap">
          <a href="{verification_url}" class="btn">✉ Verify Email Address</a>
        </div>
        <p style="font-size:13px;color:#6b7280;text-align:center;">Or paste this link in your browser:</p>
        <div class="url-box">{verification_url}</div>
        <div class="info-box">⏱ This link expires in <strong>24 hours</strong>.</div>
        """

        text = f"""{BRAND_NAME} — Email Verification

Welcome! Please verify your email to activate your account.

{verification_url}

This link expires in 24 hours.
If you didn't register, ignore this email."""

        return self.send_email(
            to_email, subject,
            _html_wrapper("✉", "Verify Your Email", body),
            text
        )

    # ------------------------------------------------------------------
    # 2. Welcome / Account Activated
    # ------------------------------------------------------------------
    def send_welcome_email(self, to_email: str, user_name: Optional[str] = None) -> bool:
        """Send welcome email after successful email verification."""
        subject = f"Welcome to {BRAND_NAME} — You're all set!"
        greeting = f"Hi {user_name}" if user_name else "Hi there"

        body = f"""
        <p>{greeting}, and welcome to <strong>{BRAND_NAME}</strong>! 🎉</p>
        <p>Your email has been successfully verified and your account is now fully active.</p>
        <div class="divider"></div>
        <p>You can now sign in and start exploring everything {BRAND_NAME} has to offer — from governed document workflows to your organisation's private RAG pipeline.</p>
        <div class="info-box">
          🚀 Head to your dashboard to get started.
        </div>
        """

        text = f"""{BRAND_NAME} — Welcome!

{greeting}!

Your email has been verified and your {BRAND_NAME} account is now active.
Sign in to get started.
"""

        return self.send_email(
            to_email, subject,
            _html_wrapper("🎉", "Account Verified!", body),
            text
        )

    # ------------------------------------------------------------------
    # 3. Password Reset
    # ------------------------------------------------------------------
    def send_password_reset_email(self, to_email: str, reset_url: str) -> bool:
        """Send password reset link."""
        subject = f"{BRAND_NAME} — Reset your password"

        body = f"""
        <p>We received a request to reset the password for your <strong>{BRAND_NAME}</strong> account.</p>
        <p>Click the button below to choose a new password:</p>
        <div class="btn-wrap">
          <a href="{reset_url}" class="btn">🔑 Reset Password</a>
        </div>
        <p style="font-size:13px;color:#6b7280;text-align:center;">Or paste this link in your browser:</p>
        <div class="url-box">{reset_url}</div>
        <div class="info-box">⏱ This link expires in <strong>1 hour</strong>.</div>
        <div class="divider"></div>
        <p style="font-size:13px;color:#9ca3af;">If you did not request a password reset, your account is safe — no changes have been made.</p>
        """

        text = f"""{BRAND_NAME} — Password Reset

We received a request to reset your password.

{reset_url}

This link expires in 1 hour.
If you didn't request this, ignore this email."""

        return self.send_email(
            to_email, subject,
            _html_wrapper("🔑", "Password Reset Request", body),
            text
        )

    # ------------------------------------------------------------------
    # 4. Tenant Invitation
    # ------------------------------------------------------------------
    def send_invite_email(
        self,
        to_email: str,
        invite_url: str,
        role: str,
        tenant_name: str,
        inviter_email: str
    ) -> bool:
        """Send a tenant invitation email to a new user."""
        role_labels = {
            'editor':   'Editor (Uploader)',
            'reviewer': 'Reviewer (Approver)',
            'user':     'End User',
        }
        role_label = role_labels.get(role, role.title())

        subject = f"You're invited to join {tenant_name} on {BRAND_NAME}"

        body = f"""
        <p>
          <strong>{inviter_email}</strong> has invited you to join
          <strong>{tenant_name}</strong> on <strong>{BRAND_NAME}</strong>.
        </p>
        <p>Your assigned role:</p>
        <p><span class="badge">🏷 {role_label}</span></p>
        <p>Click the button below to accept your invitation and set up your account:</p>
        <div class="btn-wrap">
          <a href="{invite_url}" class="btn">✅ Accept Invitation</a>
        </div>
        <p style="font-size:13px;color:#6b7280;text-align:center;">Or paste this link in your browser:</p>
        <div class="url-box">{invite_url}</div>
        <div class="info-box">⏱ This invitation expires in <strong>72 hours</strong>.</div>
        """

        text = f"""{BRAND_NAME} — You've Been Invited

{inviter_email} has invited you to join {tenant_name} as: {role_label}

Accept your invitation:
{invite_url}

This link expires in 72 hours.
If you were not expecting this, ignore this email."""

        return self.send_email(
            to_email, subject,
            _html_wrapper("📨", f"You've Been Invited to {tenant_name}", body),
            text
        )

    # ------------------------------------------------------------------
    # 5. Role Assignment Confirmation
    # ------------------------------------------------------------------
    def send_role_assignment_email(
        self,
        to_email: str,
        role: str,
        tenant_name: str,
        user_name: Optional[str] = None
    ) -> bool:
        """Notify a user that their account is active after accepting an invite."""
        greeting = f"Hi {user_name}" if user_name else "Hi there"
        subject  = f"Welcome to {tenant_name} on {BRAND_NAME} — You're in!"

        body = f"""
        <p>{greeting}, welcome to <strong>{BRAND_NAME}</strong>! 🎉</p>
        <p>Your account in <strong>{tenant_name}</strong> is now active.</p>
        <p>You have been assigned the role:</p>
        <p><span class="badge">🏷 {role.title()}</span></p>
        <div class="divider"></div>
        <p>You can now sign in and start collaborating with your team on {BRAND_NAME}.</p>
        <div class="info-box">
          🚀 Sign in to access your <strong>{tenant_name}</strong> workspace.
        </div>
        """

        text = f"""{BRAND_NAME} — Account Activated

{greeting}!

Your account in {tenant_name} is now active.
Your role: {role.title()}

Sign in to get started on {BRAND_NAME}.
"""

        return self.send_email(
            to_email, subject,
            _html_wrapper("🎉", "Your Account is Ready!", body),
            text
        )
