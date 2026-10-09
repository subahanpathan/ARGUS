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
import intelligenceRouter from "./intelligence";
import quarantineRouter from "./quarantine";
import reportsRouter from "./reports";
import attackTracesRouter from "./attack-traces";
import incidentsRouter from "./incidents";
import desktopDownloadRouter from "./desktop-download";
import predictionsRouter from "./predictions";
import adaptiveDefenseRouter from "./adaptive-defense";
import simulationsRouter from "./simulations";
import benchmarkRouter from "./benchmark";

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
router.use(intelligenceRouter);
router.use(quarantineRouter);
router.use(reportsRouter);
router.use(attackTracesRouter);
router.use(incidentsRouter);
router.use(desktopDownloadRouter);
router.use(predictionsRouter);
router.use(adaptiveDefenseRouter);
router.use(simulationsRouter);
router.use(benchmarkRouter);

export default router;

