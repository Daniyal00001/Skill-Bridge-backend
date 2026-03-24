import { Router } from "express";
import { getMetadata, getSkills } from "../controllers/metadata.controller";

const router = Router();

router.get("/", getMetadata);
router.get("/skills", getSkills);

export default router;
