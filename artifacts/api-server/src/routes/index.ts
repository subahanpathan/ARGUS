import { Router, type IRouter } from "express";
import healthRouter from "./health";
import processRouter from "./process";
import telemetryRouter from "./telemetry";
import networkRouter from "./network";
import iconRouter from "./icon";
import fileRouter from "./file";
import detectionsRouter from "./detections";
import authRouter from "./auth";
import monitoringRouter from "./monitoring";
import recoveryRouter from "./recovery";

const router: IRouter = Router();

router.use(healthRouter);
router.use(processRouter);
router.use(telemetryRouter);
router.use(networkRouter);
router.use(iconRouter);
router.use(fileRouter);
router.use(detectionsRouter);
router.use(authRouter);
router.use(monitoringRouter);
router.use(recoveryRouter);

export default router;
