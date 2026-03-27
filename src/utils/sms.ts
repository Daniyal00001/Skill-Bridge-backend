import twilio from 'twilio';

const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const twilioPhoneNumber = process.env.TWILIO_PHONE_NUMBER;

const client = twilio(accountSid, authToken);

/**
 * Sends an SMS OTP using Twilio
 * @param to - Recipient phone number (with country code, e.g., +923001234567)
 * @param otp - The 6-digit OTP code
 */
export const sendSmsOtp = async (to: string, otp: string) => {
  try {
    if (!accountSid || !authToken || !twilioPhoneNumber) {
      console.warn('[Twilio] Credentials missing. Logging OTP to console instead.');
      console.log(`[SIM OTP] To: ${to} | OTP: ${otp}`);
      return;
    }

    const message = await client.messages.create({
      body: `Your SkillBridge verification code is: ${otp}. Valid for 10 minutes.`,
      from: twilioPhoneNumber,
      to: to
    });

    console.log(`[Twilio] SMS sent successfully. SID: ${message.sid}`);
  } catch (error) {
    console.error('[Twilio] Error sending SMS:', error);
    throw new Error('Failed to send verification SMS');
  }
};
