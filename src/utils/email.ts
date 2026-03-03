import nodemailer from 'nodemailer'

// ── Create transporter ────────────────────────────────────────
// WHY: Transporter is the email sender configuration
//      We use Gmail with App Password for simplicity
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false, // Use STARTTLS
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
})

// ── Send password reset email ─────────────────────────────────
export const sendPasswordResetEmail = async (
  email: string,
  name: string,
  resetToken: string
) => {
  const frontendURL = process.env.FRONTEND_URL || 'http://localhost:8080'
  const resetLink = `${frontendURL}/reset-password?token=${resetToken}`

  const mailOptions = {
    from: process.env.EMAIL_FROM,
    to: email,
    subject: 'Reset Your SkillBridge Password',
    html: `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin:0; padding:0; background-color:#f4f4f5; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;">
          <div style="max-width:600px; margin:40px auto; background:white; border-radius:16px; overflow:hidden; box-shadow:0 4px 24px rgba(0,0,0,0.08);">
            
            <!-- Header -->
            <div style="background: linear-gradient(135deg, #6366f1, #8b5cf6); padding:40px 32px; text-align:center;">
              <h1 style="color:white; margin:0; font-size:28px; font-weight:800; letter-spacing:-0.5px;">
                SkillBridge
              </h1>
              <p style="color:rgba(255,255,255,0.8); margin:8px 0 0; font-size:14px;">
                AI-Powered Freelance Platform
              </p>
            </div>

            <!-- Body -->
            <div style="padding:40px 32px;">
              <h2 style="color:#111827; font-size:22px; font-weight:700; margin:0 0 8px;">
                Password Reset Request
              </h2>
              <p style="color:#6b7280; font-size:15px; line-height:1.6; margin:0 0 24px;">
                Hi <strong>${name}</strong>, we received a request to reset your password.
                Click the button below to create a new one.
              </p>

              <!-- Button -->
              <div style="text-align:center; margin:32px 0;">
                <a 
                  href="${resetLink}"
                  style="display:inline-block; background:linear-gradient(135deg, #6366f1, #8b5cf6); color:white; text-decoration:none; padding:14px 32px; border-radius:10px; font-size:16px; font-weight:600; letter-spacing:0.3px;"
                >
                  Reset My Password
                </a>
              </div>

              <!-- Warning -->
              <div style="background:#fef3c7; border:1px solid #fcd34d; border-radius:10px; padding:16px; margin:24px 0;">
                <p style="color:#92400e; font-size:13px; margin:0; line-height:1.5;">
                  ⚠️ This link expires in <strong>1 hour</strong>. 
                  If you did not request this, please ignore this email — 
                  your account is safe.
                </p>
              </div>

              <!-- Link fallback -->
              <p style="color:#9ca3af; font-size:12px; line-height:1.6; margin:24px 0 0;">
                If the button doesn't work, copy and paste this link:<br/>
                <a href="${resetLink}" style="color:#6366f1; word-break:break-all;">
                  ${resetLink}
                </a>
              </p>
            </div>

            <!-- Footer -->
            <div style="background:#f9fafb; padding:24px 32px; text-align:center; border-top:1px solid #e5e7eb;">
              <p style="color:#9ca3af; font-size:12px; margin:0;">
                © ${new Date().getFullYear()} SkillBridge. All rights reserved.
              </p>
            </div>

          </div>
        </body>
      </html>
    `,
  }

  await transporter.sendMail(mailOptions)
}