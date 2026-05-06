CREATE TABLE `pending_challenges` (
	`id` text PRIMARY KEY NOT NULL,
	`challenge` text NOT NULL,
	`expires_at` integer NOT NULL,
	`device_link_pairing_id` text
);
--> statement-breakpoint
CREATE TABLE `pending_device_links` (
	`pairing_id` text PRIMARY KEY NOT NULL,
	`link_secret` text NOT NULL,
	`user_id` text NOT NULL,
	`username` text NOT NULL,
	`expires_at` integer NOT NULL,
	`completed_at` integer,
	`encrypted_keys` text,
	`encrypted_keys_iv` text,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `public_share_items` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`public_share_id` integer NOT NULL,
	`file_id` text NOT NULL,
	`wrapped_key` text NOT NULL,
	`wrapped_key_iv` text NOT NULL,
	FOREIGN KEY (`public_share_id`) REFERENCES `public_shares`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`file_id`) REFERENCES `files`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
ALTER TABLE `files` ADD `demo_session_id` integer;--> statement-breakpoint
ALTER TABLE `public_shares` ADD `kdf_alg` text;--> statement-breakpoint
ALTER TABLE `public_shares` ADD `kdf_params` text;--> statement-breakpoint
ALTER TABLE `public_shares` ADD `kdf_salt` text;--> statement-breakpoint
ALTER TABLE `public_shares` ADD `wrapped_key` text;--> statement-breakpoint
ALTER TABLE `public_shares` ADD `wrapped_key_iv` text;