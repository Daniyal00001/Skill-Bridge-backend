import { Request, Response } from 'express'
import { prisma } from '../config/prisma'

export const getMyProfile = async (req: Request, res: Response) => {
  try {
    const userId = req.user?.userId;
    if (!userId) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    const clientProfile = await prisma.clientProfile.findUnique({
      where: { userId },
            location: true,
            region: true,
            timezone: true,
            hiringPreference: true,
            budgetRange: true,
            preferredExpLevel: true,
            commMethod: true,
            availability: true,
            user: {
              select: {
                name: true,
                email: true,
                isEmailVerified: true,
                isPaymentVerified: true,
                isIdVerified: true,
                profileImage: true,
                phoneNumber: true,
              }
            }
    });

    if (!clientProfile) {
      return res.status(404).json({ success: false, message: 'Client profile not found' });
    }

    return res.status(200).json({
      success: true,
      data: clientProfile
    });
  } catch (error) {
    console.error('Error fetching client profile:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

export const updateMyProfile = async (req: Request, res: Response) => {
  try {
    const userId = req.user?.userId;
    if (!userId) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    const {
      fullName,
      company,
      companyType,
      industry,
      bio,
      website,
      location,
      timezone,
      hiringPreference,
      budgetRange,
      preferredExpLevel,
      commMethod,
      availability,
      region,
      phoneNumber,
      profileImage // Optional: update the user's profile image
    } = req.body;

    const updatedProfile = await prisma.clientProfile.update({
      where: { userId },
      data: {
        fullName,
        company,
        companyType,
        industry,
        bio,
        website,
        location,
        timezone,
        hiringPreference,
        budgetRange,
        preferredExpLevel,
        commMethod,
        availability,
        region,
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
          }
        }
      }
    });

    if (profileImage !== undefined || phoneNumber !== undefined) {
      await prisma.user.update({
        where: { id: userId },
        data: { 
          ...(profileImage !== undefined && { profileImage }),
          ...(phoneNumber !== undefined && { phoneNumber }),
        }
      });
      // Update the response with the new data
      if (profileImage !== undefined) updatedProfile.user.profileImage = profileImage;
      if (phoneNumber !== undefined) updatedProfile.user.phoneNumber = phoneNumber;
    }

    return res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      data: updatedProfile
    });

  } catch (error) {
    console.error('Error updating client profile:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};
