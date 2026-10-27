import { COOKIE_NAME } from "@shared/const";
import { TRPCError } from "@trpc/server";
import { z } from "zod";
import { getSessionCookieOptions } from "./_core/cookies";
import { protectedProcedure } from "./_core/trpc";
import { systemRouter } from "./_core/systemRouter";
import { publicProcedure, router } from "./_core/trpc";
import {
  createAnalysisRun,
  getOrCreateOrganizationForUser,
  getOrganizationForUser,
  insertAlerts,
  listAlerts,
  listAnalysisRuns,
} from "./db";
import {
  PROTOTYPE_DECISION_THRESHOLD,
  PROTOTYPE_MODEL_VERSION,
  REQUIRED_INPUT_COLUMNS,
  runPrototypeInference,
} from "./inference";

export const appRouter = router({
    // if you need to use socket.io, read and register route in server/_core/index.ts, all api should start with '/api/' so that the gateway can route correctly
  system: systemRouter,
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return {
        success: true,
      } as const;
    }),
  }),

  workspace: router({
    context: protectedProcedure.query(async ({ ctx }) => {
      const organization = await getOrCreateOrganizationForUser(ctx.user.id, ctx.user.name);
      return {
        organization,
        modelVersion: PROTOTYPE_MODEL_VERSION,
        decisionThreshold: PROTOTYPE_DECISION_THRESHOLD,
        requiredInputColumns: REQUIRED_INPUT_COLUMNS,
        inferenceMode: "prototype-adapter" as const,
      };
    }),
  }),

  dashboard: router({
    summary: protectedProcedure.query(async ({ ctx }) => {
      const membership = await getOrganizationForUser(ctx.user.id);
      if (!membership) {
        return { runCount: 0, rowsAnalyzed: 0, attacksDetected: 0, alertsStored: 0 };
      }
      const [runs, recentAlerts] = await Promise.all([
        listAnalysisRuns(membership.organization.id, 100),
        listAlerts(membership.organization.id, 100),
      ]);
      return {
        runCount: runs.length,
        rowsAnalyzed: runs.reduce((total, run) => total + run.rowCount, 0),
        attacksDetected: runs.reduce((total, run) => total + run.attackCount, 0),
        alertsStored: recentAlerts.length,
      };
    }),
  }),

  analysis: router({
    list: protectedProcedure.query(async ({ ctx }) => {
      const membership = await getOrganizationForUser(ctx.user.id);
      return membership ? listAnalysisRuns(membership.organization.id) : [];
    }),
    alerts: protectedProcedure.query(async ({ ctx }) => {
      const membership = await getOrganizationForUser(ctx.user.id);
      return membership ? listAlerts(membership.organization.id) : [];
    }),
    run: protectedProcedure
      .input(
        z.object({
          fileName: z.string().min(1).max(255),
          csv: z.string().min(1).max(5_000_000),
        }),
      )
      .mutation(async ({ ctx, input }) => {
        const organization = await getOrCreateOrganizationForUser(ctx.user.id, ctx.user.name);
        let result;
        try {
          result = runPrototypeInference(input.csv);
        } catch (error) {
          throw new TRPCError({
            code: "BAD_REQUEST",
            message: error instanceof Error ? error.message : "Unable to analyze this CSV file.",
          });
        }

        const run = await createAnalysisRun({
          organizationId: organization.id,
          createdByUserId: ctx.user.id,
          fileName: input.fileName,
          modelVersion: result.modelVersion,
          decisionThreshold: result.decisionThreshold.toFixed(4),
          rowCount: result.rowCount,
          attackCount: result.attackCount,
          normalCount: result.normalCount,
          status: "completed",
        });

        if (!run) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Run was not saved." });

        const alertRows = result.predictions
          .filter(prediction => prediction.prediction === 1)
          .slice(0, 1000)
          .map(prediction => ({
            organizationId: organization.id,
            analysisRunId: run.id,
            rowNumber: prediction.rowNumber,
            prediction: prediction.prediction,
            predictionName: prediction.predictionName,
            probabilityAttack: prediction.probabilityAttack.toFixed(6),
            severity: prediction.severity,
            srcIp: prediction.srcIp,
            dstIp: prediction.dstIp,
            dstPort: prediction.dstPort,
            proto: prediction.proto,
            connState: prediction.connState,
          }));
        await insertAlerts(alertRows);

        return {
          run,
          ...result,
          storedAlertCount: alertRows.length,
          note:
            "This result uses the prototype adapter. Upload the verified joblib bundle to replace it with the trained ToN-IoT model.",
        };
      }),
  }),
});

export type AppRouter = typeof appRouter;
