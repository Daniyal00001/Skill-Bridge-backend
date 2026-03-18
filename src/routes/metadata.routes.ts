import { Router } from "express";
import { getMetadata } from "../controllers/metadata.controller";

const router = Router();

router.get("/", getMetadata);

export default router;
