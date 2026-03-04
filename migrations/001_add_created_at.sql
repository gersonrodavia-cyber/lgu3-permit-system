-- Add created_at column to permit table if it doesn't exist
ALTER TABLE `permit`
ADD COLUMN IF NOT EXISTS `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP;
