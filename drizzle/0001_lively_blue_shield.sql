CREATE TABLE `alerts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`organizationId` int NOT NULL,
	`analysisRunId` int NOT NULL,
	`rowNumber` int NOT NULL,
	`prediction` int NOT NULL,
	`predictionName` enum('normal','attack') NOT NULL,
	`probabilityAttack` decimal(8,6) NOT NULL,
	`severity` enum('low','medium','high','critical') NOT NULL,
	`srcIp` varchar(64),
	`dstIp` varchar(64),
	`dstPort` int,
	`proto` varchar(32),
	`connState` varchar(32),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `alerts_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `analysis_runs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`organizationId` int NOT NULL,
	`createdByUserId` int NOT NULL,
	`fileName` varchar(255) NOT NULL,
	`modelVersion` varchar(120) NOT NULL,
	`decisionThreshold` decimal(5,4) NOT NULL,
	`rowCount` int NOT NULL DEFAULT 0,
	`attackCount` int NOT NULL DEFAULT 0,
	`normalCount` int NOT NULL DEFAULT 0,
	`status` enum('completed','failed') NOT NULL DEFAULT 'completed',
	`errorMessage` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `analysis_runs_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `organization_members` (
	`id` int AUTO_INCREMENT NOT NULL,
	`organizationId` int NOT NULL,
	`userId` int NOT NULL,
	`role` enum('owner','analyst','viewer') NOT NULL DEFAULT 'owner',
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `organization_members_id` PRIMARY KEY(`id`),
	CONSTRAINT `organization_members_org_user_unique` UNIQUE(`organizationId`,`userId`)
);
--> statement-breakpoint
CREATE TABLE `organizations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(160) NOT NULL,
	`slug` varchar(180) NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `organizations_id` PRIMARY KEY(`id`),
	CONSTRAINT `organizations_slug_unique` UNIQUE(`slug`)
);
--> statement-breakpoint
CREATE INDEX `alerts_run_idx` ON `alerts` (`analysisRunId`);--> statement-breakpoint
CREATE INDEX `alerts_org_created_idx` ON `alerts` (`organizationId`,`createdAt`);--> statement-breakpoint
CREATE INDEX `analysis_runs_org_created_idx` ON `analysis_runs` (`organizationId`,`createdAt`);--> statement-breakpoint
CREATE INDEX `organization_members_user_idx` ON `organization_members` (`userId`);