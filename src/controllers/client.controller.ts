import { Request, Response } from "express";
import { prisma } from "../config/prisma";
import { sendOtpEmail } from "../utils/email";
import { sendSmsOtp } from "../utils/sms";
import crypto from "crypto";
import { uploadToCloudinary, deleteFromCloudinary } from "../utils/uploadToCloudinary";

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
            // @ts-ignore
            isPhoneVerified: true,
            isPaymentVerified: true,
            isIdVerified: true,
            idVerificationStatus: true,
            idRejectionReason: true,
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
            // @ts-ignore
            isPhoneVerified: true,
            isPaymentVerified: true,
            isIdVerified: true,
            idVerificationStatus: true,
            idRejectionReason: true,
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
      // @ts-ignore
      if (profileImage !== undefined) updatedProfile.user.profileImage = profileImage;
      // @ts-ignore
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

    // International Standard Regex
    const phoneRegex = /^\+?[1-9]\d{1,14}$/;
    if (!phoneRegex.test(phoneNumber)) {
      return res.status(400).json({ success: false, message: "Invalid phone number format. Use international standard (e.g., +923001234567)" });
    }

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    // 5-minute resend cooldown
    // @ts-ignore
    if (user.phoneOtpLastSent) {
      const fiveMinsAgo = new Date(Date.now() - 5 * 60 * 1000);
      // @ts-ignore
      if (user.phoneOtpLastSent > fiveMinsAgo) {
        // @ts-ignore
        const remainingSeconds = Math.ceil((user.phoneOtpLastSent.getTime() + 5 * 60 * 1000 - Date.now()) / 1000);
        return res.status(429).json({ 
          success: false, 
          message: `Please wait ${remainingSeconds} seconds before requesting a new OTP` 
        });
      }
    }

    // Already Verified Check
    // @ts-ignore
    if (user.phoneNumber === phoneNumber && user.isPhoneVerified) {
      return res.status(400).json({ success: false, message: "This phone number is already verified for your account." });
    }

    // Duplicate Check (Other users)
    const otherUser = await prisma.user.findFirst({
      where: { 
        phoneNumber, 
        // @ts-ignore
        isPhoneVerified: true,
        id: { not: userId } 
      }
    });
    if (otherUser) {
      return res.status(409).json({ success: false, message: "This phone number is already in use by another verified user." });
    }

    const otp = genOtp();
    await prisma.user.update({
      where: { id: userId },
      data: { 
        phoneNumber, 
        phoneOtp: otp, 
        phoneOtpExpiry: otpExpiry(),
        // @ts-ignore
        phoneOtpLastSent: new Date(),
        // Reset verified status if changing to a new number
        // (If it reached here, it's either a different number or wasn't verified)
        // @ts-ignore
        isPhoneVerified: false 
      },
    });

    // Send real SMS via Twilio
    await sendSmsOtp(phoneNumber, otp);

    return res.status(200).json({ success: true, message: `OTP sent to ${phoneNumber}` });
  } catch (error) {
    console.error("Error requesting phone OTP:", error);
    return res.status(500).json({ success: false, message: error instanceof Error ? error.message : "Internal server error" });
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
      data: { 
        // @ts-ignore
        isPhoneVerified: true,
        phoneOtp: null, 
        phoneOtpExpiry: null 
      },
    });

    return res.status(200).json({ success: true, message: "Phone number verified successfully" });
  } catch (error) {
    console.error("Error verifying phone OTP:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

// ── POST /client/profile/upload-id ────────────────────────────
export const uploadIdDocument = async (req: Request, res: Response) => {
  try {
    const userId = req.user?.userId;
    if (!userId) return res.status(401).json({ success: false, message: "Unauthorized" });

    const files = req.files as { [fieldname: string]: Express.Multer.File[] } | undefined;
    if (!files || !files["idDocument"] || !files["idDocument"][0]) {
      return res.status(400).json({ success: false, message: "No ID document provided" });
    }

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    // Delete old one if exists
    if (user.idDocumentUrl) {
      await deleteFromCloudinary(user.idDocumentUrl);
    }

    const idUrl = await uploadToCloudinary(files["idDocument"][0].buffer, files["idDocument"][0].originalname, files["idDocument"][0].mimetype);
    await prisma.user.update({
      where: { id: userId },
      data: { idDocumentUrl: idUrl, idVerificationStatus: "PENDING" }, 
    });

    return res.status(200).json({
      success: true,
      message: "ID Document uploaded successfully",
      data: { idDocumentUrl: idUrl, idVerificationStatus: "PENDING" }
    });
  } catch (error) {
    console.error("Error uploading ID document:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};
