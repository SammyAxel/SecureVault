CREATE TABLE `file_shares` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`file_id` text NOT NULL,
	`recipient_id` integer NOT NULL,
	`encrypted_key` text NOT NULL,
	`created_at` integer,
	FOREIGN KEY (`file_id`) REFERENCES `files`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`recipient_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `files` (
	`id` text PRIMARY KEY NOT NULL,
	`filename` text NOT NULL,
	`owner_id` integer NOT NULL,
	`encrypted_key` text NOT NULL,
	`iv` text NOT NULL,
	`storage_path` text,
	`file_size` integer DEFAULT 0,
	`is_folder` integer DEFAULT false,
	`parent_id` text,
	`is_deleted` integer DEFAULT false,
	`deleted_at` integer,
	`created_at` integer,
	FOREIGN KEY (`owner_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`parent_id`) REFERENCES `files`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `public_shares` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`file_id` text NOT NULL,
	`token` text NOT NULL,
	`expires_at` integer NOT NULL,
	`created_at` integer,
	`access_count` integer DEFAULT 0,
	`max_access` integer,
	FOREIGN KEY (`file_id`) REFERENCES `files`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `sessions` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`token` text NOT NULL,
	`user_id` integer NOT NULL,
	`created_at` integer,
	`expires_at` integer NOT NULL,
	`device_info` text,
	`ip_address` text,
	`user_agent` text,
	`last_active` integer,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `users` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`username` text NOT NULL,
	`public_key_pem` text NOT NULL,
	`encryption_public_key_pem` text,
	`storage_used` integer DEFAULT 0,
	`storage_quota` integer DEFAULT 524288000,
	`is_admin` integer DEFAULT false,
	`is_suspended` integer DEFAULT false,
	`suspended_at` integer,
	`totp_secret` text,
	`totp_enabled` integer DEFAULT false,
	`backup_codes` text,
	`created_at` integer
);
--> statement-breakpoint
CREATE UNIQUE INDEX `public_shares_token_unique` ON `public_shares` (`token`);--> statement-breakpoint
CREATE UNIQUE INDEX `sessions_token_unique` ON `sessions` (`token`);--> statement-breakpoint
CREATE UNIQUE INDEX `users_username_unique` ON `users` (`username`);