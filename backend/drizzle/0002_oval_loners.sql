-- Breaking change: users.id and all FKs to users are TEXT (UUID v4), not INTEGER.
-- SQLite cannot safely migrate existing INTEGER PK/FK columns in place.
-- Delete the database file and blob storage, then start the app so migrate.ts creates the new schema.
SELECT 1;
