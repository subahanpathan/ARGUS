import { Router, type IRouter } from "express";
import healthRouter from "./health";
import processRouter from "./process";
import telemetryRouter from "./telemetry";
import networkRouter from "./network";
import iconRouter from "./icon";
import fileRouter from "./file";
import detectionsRouter from "./detections";
import intelligenceRouter from "./intelligence";
import quarantineRouter from "./quarantine";
import reportsRouter from "./reports";

const router: IRouter = Router();

router.use(healthRouter);
router.use(processRouter);
router.use(telemetryRouter);
router.use(networkRouter);
router.use(iconRouter);
router.use(fileRouter);
router.use(detectionsRouter);
router.use(intelligenceRouter);
router.use(quarantineRouter);
router.use(reportsRouter);

export default router;
