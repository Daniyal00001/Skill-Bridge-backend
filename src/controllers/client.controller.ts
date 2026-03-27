import { Request, Response } from "express";
import { prisma } from "../config/prisma";
import { sendOtpEmail } from "../utils/email";
import crypto from "crypto";

// ── helpers ──────────────────────────────────────────────────
const genOtp = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

const otpExpiry = () => new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

// ── GET /client/profile ───────────────────────────────────────
export const getMyProfile = async (req: Request, res: Response) => {
  try {
    const userId = req.user?.userId;
    if (!userId) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    const clientProfile = await prisma.clientProfile.findUnique({
      where: { userId },
      include: {
        user: {
          select: {
            name: true,
            email: true,
            pendingEmail: true,
            isEmailVerified: true,
            isPaymentVerified: true,
            isIdVerified: true,
            profileImage: true,
            phoneNumber: true,
            googleId: true,
          },
        },
      },
    });

    if (!clientProfile) {
      return res
        .status(404)
        .json({ success: false, message: "Client profile not found" });
    }

    // Calculate metrics for profile display
    const clientId = clientProfile.id;
    const [totalProjects, hiredProjectsCount, totalSpentRes] =
      await Promise.all([
        prisma.project.count({ where: { clientProfileId: clientId } }),
        prisma.project.count({
          where: { clientProfileId: clientId, contract: { isNot: null } },
        }),
        prisma.payment.aggregate({
          where: {
            contract: { project: { clientProfileId: clientId } },
            status: "RELEASED",
          },
          _sum: { amount: true },
        }),
      ]);

    const totalSpent = totalSpentRes._sum.amount || 0;
    const hireRate =
      totalProjects > 0
        ? Math.round((hiredProjectsCount / totalProjects) * 100)
        : 0;

    return res.status(200).json({
      success: true,
      profile: {
        ...clientProfile,
        metrics: {
          totalProjects,
          hireRate,
          totalSpent,
        },
      },
    });
  } catch (error) {
    console.error("Error fetching client profile:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
};

// ── PUT /client/profile ───────────────────────────────────────
export const updateMyProfile = async (req: Request, res: Response) => {
  try {
    const userId = req.user?.userId;
    if (!userId) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    const {
      fullName,
      bio,
      location,
      region,
      hiringPreference,
      budgetRange,
      preferredExpLevel,
      commMethod,
      availability,
      language,
      locationPref,
      hiringMethod,
      preferredRegion,
      spokenLanguages,
      hourlyBudgetMin,
      hourlyBudgetMax,
      profileImage,
      phoneNumber,
    } = req.body;

    const updatedProfile = await prisma.clientProfile.update({
      where: { userId },
      data: {
        fullName,
        bio,
        location,
        region,
        hiringPreference: hiringPreference || null,
        budgetRange: budgetRange || null,
        preferredExpLevel: preferredExpLevel || null,
        commMethod: commMethod || null,
        availability: availability || null,
        language: language || null,
        locationPref: locationPref || null,
        hiringMethod: hiringMethod || null,
        preferredRegion: preferredRegion || null,
        spokenLanguages: Array.isArray(spokenLanguages) ? spokenLanguages : [],
        hourlyBudgetMin: hourlyBudgetMin !== "" && hourlyBudgetMin !== undefined ? Number(hourlyBudgetMin) : null,
        hourlyBudgetMax: hourlyBudgetMax !== "" && hourlyBudgetMax !== undefined ? Number(hourlyBudgetMax) : null,
      },
      include: {
        user: {
          select: {
            email: true,
            isEmailVerified: true,
            isPaymentVerified: true,
            isIdVerified: true,
            profileImage: true,
            phoneNumber: true,
          },
        },
      },
    });

    if (profileImage !== undefined || phoneNumber !== undefined) {
      await prisma.user.update({
        where: { id: userId },
        data: {
          ...(profileImage !== undefined && { profileImage }),
          ...(phoneNumber !== undefined && { phoneNumber }),
        },
      });
      if (profileImage !== undefined) updatedProfile.user.profileImage = profileImage;
      if (phoneNumber !== undefined) updatedProfile.user.phoneNumber = phoneNumber;
    }

    return res.status(200).json({
      success: true,
      message: "Profile updated successfully",
      data: updatedProfile,
    });
  } catch (error) {
    console.error("Error updating client profile:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
};

// ── POST /client/profile/request-email-change ─────────────────
export const requestEmailChange = async (req: Request, res: Response) => {
  try {
    const userId = req.user?.userId;
    if (!userId) return res.status(401).json({ success: false, message: "Unauthorized" });

    const { newEmail } = req.body;
    if (!newEmail) return res.status(400).json({ success: false, message: "New email is required" });

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    // Check email not already taken
    const existing = await prisma.user.findFirst({ where: { email: newEmail, id: { not: userId } } });
    if (existing) return res.status(409).json({ success: false, message: "Email is already in use" });

    const otp = genOtp();
    await prisma.user.update({
      where: { id: userId },
      data: { pendingEmail: newEmail, emailOtp: otp, emailOtpExpiry: otpExpiry() },
    });

    await sendOtpEmail(newEmail, user.name, otp);

    return res.status(200).json({ success: true, message: `OTP sent to ${newEmail}` });
  } catch (error) {
    console.error("Error requesting email change:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

// ── POST /client/profile/verify-email-change ─────────────────
export const verifyEmailChange = async (req: Request, res: Response) => {
  try {
    const userId = req.user?.userId;
    if (!userId) return res.status(401).json({ success: false, message: "Unauthorized" });

    const { otp } = req.body;
    if (!otp) return res.status(400).json({ success: false, message: "OTP is required" });

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.pendingEmail || !user.emailOtp || !user.emailOtpExpiry) {
      return res.status(400).json({ success: false, message: "No pending email change found" });
    }

    if (user.emailOtp !== otp) {
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    }

    if (new Date() > user.emailOtpExpiry) {
      return res.status(400).json({ success: false, message: "OTP has expired" });
    }

    await prisma.user.update({
      where: { id: userId },
      data: {
        email: user.pendingEmail,
        isEmailVerified: true,
        pendingEmail: null,
        emailOtp: null,
        emailOtpExpiry: null,
      },
    });

    return res.status(200).json({ success: true, message: "Email updated and verified successfully" });
  } catch (error) {
    console.error("Error verifying email change:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

// ── POST /client/profile/request-phone-otp ───────────────────
export const requestPhoneOtp = async (req: Request, res: Response) => {
  try {
    const userId = req.user?.userId;
    if (!userId) return res.status(401).json({ success: false, message: "Unauthorized" });

    const { phoneNumber } = req.body;
    if (!phoneNumber) return res.status(400).json({ success: false, message: "Phone number is required" });

    const otp = genOtp();
    await prisma.user.update({
      where: { id: userId },
      data: { phoneNumber, phoneOtp: otp, phoneOtpExpiry: otpExpiry() },
    });

    // WhatsApp placeholder — log OTP to console (plug in Twilio/Meta later)
    console.log(`[WhatsApp OTP] To: ${phoneNumber} | OTP: ${otp}`);

    return res.status(200).json({ success: true, message: `OTP sent to WhatsApp: ${phoneNumber}` });
  } catch (error) {
    console.error("Error requesting phone OTP:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

// ── POST /client/profile/verify-phone-otp ────────────────────
export const verifyPhoneOtp = async (req: Request, res: Response) => {
  try {
    const userId = req.user?.userId;
    if (!userId) return res.status(401).json({ success: false, message: "Unauthorized" });

    const { otp } = req.body;
    if (!otp) return res.status(400).json({ success: false, message: "OTP is required" });

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.phoneOtp || !user.phoneOtpExpiry) {
      return res.status(400).json({ success: false, message: "No pending phone verification found" });
    }

    if (user.phoneOtp !== otp) {
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    }

    if (new Date() > user.phoneOtpExpiry) {
      return res.status(400).json({ success: false, message: "OTP has expired" });
    }

    await prisma.user.update({
      where: { id: userId },
      data: { phoneOtp: null, phoneOtpExpiry: null },
    });

    return res.status(200).json({ success: true, message: "Phone number verified successfully" });
  } catch (error) {
    console.error("Error verifying phone OTP:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};
