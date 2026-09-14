import { Router, type IRouter } from "express";
import healthRouter from "./health";
import processRouter from "./process";
import telemetryRouter from "./telemetry";
import networkRouter from "./network";
import iconRouter from "./icon";
import fileRouter from "./file";
import detectionsRouter from "./detections";

const router: IRouter = Router();

router.use(healthRouter);
router.use(processRouter);
router.use(telemetryRouter);
router.use(networkRouter);
router.use(iconRouter);
router.use(fileRouter);
router.use(detectionsRouter);

export default router;
