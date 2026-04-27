import { Request, Response } from "express";
import { prisma } from "../config/prisma";
import * as notificationService from "../services/notification.service";
import { uploadMultipleToCloudinary } from "../utils/uploadToCloudinary";
import { Prisma, Role } from "@prisma/client";
import { inviteFreelancerSchema } from "../utils/validators";
import { sanitize } from "../utils/sanitize";

/**
 * @desc    Get all freelancers with advanced filtering and pagination
 * @route   GET /api/freelancers
 * @access  Private
 */
export const getAllFreelancers = async (req: Request, res: Response) => {
  try {
    const {
      search,
      skills,
      minRate,
      maxRate,
      experienceLevel,
      availability,
      isIdVerified,
      page = 1,
      limit = 25,
      sortBy = "createdAt",
      sortOrder = "desc",
    } = req.query;

    const pageNumber = parseInt(page as string) || 1;
    const limitNumber = parseInt(limit as string) || 25;
    const skip = (pageNumber - 1) * limitNumber;

    const where: Prisma.FreelancerProfileWhereInput = {
      user: { isBanned: false },
    };

    if (isIdVerified === "true") {
      where.user = { ...((where.user as any) || {}), isIdVerified: true };
    }


    // Search filter (Name, Tagline, Bio)
    if (search) {
      where.OR = [
        { fullName: { contains: search as string, mode: "insensitive" } },
        { tagline: { contains: search as string, mode: "insensitive" } },
        { bio: { contains: search as string, mode: "insensitive" } },
      ];
    }

    // Skills filter
    if (skills) {
      const skillList = (skills as string).split(",").map((s) => s.trim());
      where.skills = {
        some: {
          skill: {
            name: { in: skillList, mode: "insensitive" },
          },
        },
      };
    }

    // Rate filter
    if (minRate || maxRate) {
      where.hourlyRate = {};
      if (minRate) where.hourlyRate.gte = parseFloat(minRate as string);
      if (maxRate) where.hourlyRate.lte = parseFloat(maxRate as string);
    }

    // Experience Level filter
    if (experienceLevel) {
      where.experienceLevel = experienceLevel as any;
    }

    // Availability filter
    if (availability) {
      where.availability = availability as any;
    }

    // Sorting
    const orderBy: any = {};
    if (sortBy === "hourlyRate") {
      orderBy.hourlyRate = sortOrder === "asc" ? "asc" : "desc";
    } else {
      orderBy.user = {
        createdAt: sortOrder === "asc" ? "asc" : "desc",
      };
    }

    const [freelancers, totalCount] = await Promise.all([
      prisma.freelancerProfile.findMany({
        where,
        include: {
          user: {
            select: {
              profileImage: true,
              isEmailVerified: true,
              isIdVerified: true,
              idVerificationStatus: true,
              lastActiveAt: true,
            },
          },
          skills: {
            include: { skill: true },
          },
        },
        orderBy,
        skip,
        take: limitNumber,
      }),
      prisma.freelancerProfile.count({ where }),
    ]);

    const totalPages = Math.ceil(totalCount / limitNumber);

    return res.status(200).json({
      success: true,
      message: "Freelancers fetched successfully",
      data: {
        freelancers,
        pagination: {
          total: totalCount,
          page: pageNumber,
          limit: limitNumber,
          totalPages,
        },
      },
    });
  } catch (error) {
    console.error("Get all freelancers error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
};

/**
 * @desc    Get single freelancer profile — full detail for profile page
 * @route   GET /api/freelancers/:id
 * @access  Private
 *
 * Returns:
 *   - Full FreelancerProfile fields (bio, tagline, hourlyRate, experienceLevel,
 *     availability, responseTime, languages, github, linkedin, portfolio, website,
 *     profileCompletion, skillTokenBalance, averageRating, totalReviews, etc.)
 *   - user  { name, email, profileImage, isEmailVerified, isIdVerified,
 *             isPaymentVerified, createdAt, lastActiveAt }
 *   - skills[]         — with proficiencyLevel + skill.name/category
 *   - portfolioItems[] — title, description, imageUrl, projectUrl, techStack, completedAt
 *   - certificates[]   — title, issuingOrganization, issueDate, expiryDate, credentialUrl
 *   - educations[]     — school, degree, year
 *   - gigs[]           — title, description, fileUrl
 *   - reviews[]        — revealed reviews received, newest first (max 20)
 *   - recentProjects[] — up to 5 completed/accepted projects with title + budget
 */
export const getFreelancerById = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;

    const freelancer = await prisma.freelancerProfile.findUnique({
      where: { id },
      include: {
        // ── Core user fields ──────────────────────────────────
        user: {
          select: {
            name: true,
            email: true,
            profileImage: true,
            isEmailVerified: true,
            isIdVerified: true,
            isPaymentVerified: true,
            createdAt: true,
            lastActiveAt: true,
            // Revealed reviews received by this freelancer
            reviewsReceived: {
              where: { isRevealed: true },
              orderBy: { revealedAt: "desc" },
              take: 20,
              include: {
                giver: {
                  select: {
                    name: true,
                    profileImage: true,
                  },
                },
              },
            },
          },
        },

        // ── Skills with proficiency ───────────────────────────
        skills: {
          include: {
            skill: {
              select: {
                id: true,
                name: true,
                category: true,
              },
            },
          },
          orderBy: { proficiencyLevel: "desc" }, // highest proficiency first
        },

        // ── Portfolio ─────────────────────────────────────────
        portfolioItems: {
          orderBy: { completedAt: "desc" },
        },

        // ── Certificates ──────────────────────────────────────
        certificates: {
          orderBy: { issueDate: "desc" },
        },

        // ── Education ─────────────────────────────────────────
        educations: true,

        // ── Service packages / gigs ───────────────────────────
        gigs: {
          orderBy: { createdAt: "desc" },
        },

        // ── Accepted proposals → recent projects ─────────────
        proposals: {
          where: { status: "ACCEPTED" },
          orderBy: { updatedAt: "desc" },
          take: 5,
          include: {
            project: {
              select: {
                id: true,
                title: true,
                budget: true,
                budgetType: true,
              },
            },
          },
        },
      },
    });

    if (!freelancer) {
      return res.status(404).json({
        success: false,
        message: "Freelancer profile not found",
      });
    }

    // ── Destructure reviewsReceived out of user ───────────────
    const { reviewsReceived, ...userWithoutReviews } = freelancer.user as any;

    // ── Flatten accepted proposals → recentProjects ───────────
    const recentProjects = (freelancer.proposals || []).map((p: any) => p.project);

    // ── Build the final response shape ───────────────────────
    const data = {
      ...freelancer,
      user: {
        ...userWithoutReviews,
      },
      reviews: reviewsReceived || [],
      recentProjects,
      // Remove raw proposals array from response (already mapped above)
      proposals: undefined,
    };

    return res.status(200).json({
      success: true,
      data,
    });
  } catch (error) {
    console.error("Get freelancer by ID error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
};

/**
 * @desc    Invite a freelancer to a project
 * @route   POST /api/freelancers/:id/invite
 * @access  Private (Role: CLIENT)
 */
export const inviteFreelancer = async (req: Request, res: Response) => {
  try {
    const freelancerProfileId = req.params.id as string;
    const { projectId, message, milestones, revisionsAllowed, budget } =
      req.body;
    const userId = (req as any).user?.userId;

    // Parse milestones if sent as FormData string
    let parsedMilestones = milestones;
    if (typeof milestones === "string") {
      try {
        parsedMilestones = JSON.parse(milestones);
      } catch {
        parsedMilestones = null;
      }
    }

    const parsed = inviteFreelancerSchema.safeParse({
      projectId,
      message,
      budget: budget ? Number(budget) : null,
      revisionsAllowed: revisionsAllowed ? Number(revisionsAllowed) : 3,
      milestones: parsedMilestones,
    });

    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        message: parsed.error.errors[0]?.message || "Invalid invitation data.",
      });
    }

    const validatedData = parsed.data;

    // Verify client profile
    const clientProfile = await prisma.clientProfile.findUnique({
      where: { userId },
    });

    if (!clientProfile) {
      return res.status(403).json({
        success: false,
        message: "Only clients can invite freelancers",
      });
    }

    // Check project ownership
    const project = await prisma.project.findUnique({
      where: { id: projectId },
    });

    if (!project || project.clientProfileId !== clientProfile.id) {
      return res.status(403).json({
        success: false,
        message: "You can only invite to your own projects",
      });
    }

    // Check if freelancer exists
    const freelancer = await prisma.freelancerProfile.findUnique({
      where: { id: freelancerProfileId },
    });

    if (!freelancer) {
      return res.status(404).json({
        success: false,
        message: "Freelancer not found",
      });
    }

    // Check for existing invitation
    const existingInvite = await prisma.invitation.findUnique({
      where: {
        projectId_freelancerProfileId: {
          projectId,
          freelancerProfileId,
        },
      },
    });

    if (existingInvite) {
      return res.status(400).json({
        success: false,
        message: "Freelancer is already invited to this project",
      });
    }

    // Handle uploaded files
    let attachmentUrls: string[] = [];
    if (req.files && Array.isArray(req.files) && req.files.length > 0) {
      attachmentUrls = await uploadMultipleToCloudinary(
        req.files as Express.Multer.File[],
      );
    }

    // Create invitation
    const invitation = await prisma.invitation.create({
      data: {
        projectId: validatedData.projectId,
        freelancerProfileId,
        clientProfileId: clientProfile.id,
        message: sanitize(validatedData.message),
        milestones: validatedData.milestones,
        revisionsAllowed: validatedData.revisionsAllowed,
        budget: validatedData.budget,
        attachments: attachmentUrls,
      } as any,
    });

    // Notify freelancer
    await notificationService.createNotification({
      userId: freelancer.userId,
      type: "INVITATION_RECEIVED",
      title: "New Project Invitation",
      body: `${clientProfile.fullName} invited you to work on: ${project.title}`,
      link: `/freelancer/invitations/${invitation.id}`,
    });

    // Post system message to existing chat room if one exists
    const chatRoom = await prisma.chatRoom.findFirst({
      where: {
        clientProfileId: clientProfile.id,
        freelancerProfileId,
      },
      orderBy: { createdAt: "desc" },
    });

    if (chatRoom) {
      try {
        const io = req.app.get("io");
        const systemMsg = await prisma.message.create({
          data: {
            chatRoomId: chatRoom.id,
            senderId: userId,
            content: `📄 **Contract Invitation Sent**\nProject: ${project.title}\nBudget: $${budget || project.budget || "To be discussed"}\n\n[View Invitation Details](/freelancer/invitations/${invitation.id})`,
            type: "SYSTEM",
          },
          include: {
            sender: {
              select: { id: true, name: true, profileImage: true, role: true },
            },
          },
        });

        if (io) {
          io.to(chatRoom.id).emit("new_message", systemMsg);
          io.to(`user:${freelancer.userId}`).emit("new_message", systemMsg);
        }
      } catch (msgErr) {
        console.error("[Invite] Failed to post chat message:", msgErr);
      }
    }

    return res.status(201).json({
      success: true,
      message: "Invitation sent successfully",
      data: invitation,
    });
  } catch (error) {
    console.error("Invite freelancer error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
};

/**
 * @desc    Initiate or retrieve a recruitment chat room between client and freelancer
 * @route   POST /api/freelancers/:id/message
 * @access  Private (Role: CLIENT)
 */
export const initiateChat = async (req: Request, res: Response) => {
  try {
    const freelancerProfileId = req.params.id as string;
    const { projectId } = req.body || {};
    const userId = (req as any).user?.userId;

    const clientProfile = await prisma.clientProfile.findUnique({
      where: { userId },
    });

    if (!clientProfile) {
      return res.status(403).json({
        success: false,
        message: "Only clients can initiate recruitment chats",
      });
    }

    const freelancer = await prisma.freelancerProfile.findUnique({
      where: { id: freelancerProfileId },
    });

    if (!freelancer) {
      return res.status(404).json({
        success: false,
        message: "Freelancer not found",
      });
    }

    // Look for an existing non-contract room between the two
    const existingRooms = await prisma.chatRoom.findMany({
      where: {
        freelancerProfileId,
        clientProfileId: clientProfile.id,
        contractId: null,
      },
    });

    let chatRoom = existingRooms.length > 0 ? existingRooms[0] : null;

    if (chatRoom) {
      // Restore soft-deleted room
      if (chatRoom.clientDeleted || chatRoom.freelancerDeleted) {
        chatRoom = await prisma.chatRoom.update({
          where: { id: chatRoom.id },
          data: { clientDeleted: false, freelancerDeleted: false },
        });
      }
    } else {
      chatRoom = await prisma.chatRoom.create({
        data: {
          freelancerProfileId,
          clientProfileId: clientProfile.id,
          projectId: projectId || null,
        },
      });
    }

    return res.status(200).json({
      success: true,
      data: chatRoom,
    });
  } catch (error) {
    console.error("Initiate chat error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
};

/**
 * @desc    Get single gig details
 * @route   GET /api/freelancers/gigs/:id
 * @access  Private
 */
export const getGigById = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;

    const gig = await prisma.gig.findUnique({
      where: { id },
      include: {
        freelancerProfile: {
          include: {
            user: {
              select: {
                name: true,
                profileImage: true,
              },
            },
          },
        },
      },
    });

    if (!gig) {
      return res.status(404).json({
        success: false,
        message: "Gig not found",
      });
    }

    return res.status(200).json({
      success: true,
      data: gig,
    });
  } catch (error) {
    console.error("Get gig by ID error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
};
