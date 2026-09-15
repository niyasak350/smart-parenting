CREATE DATABASE IF NOT EXISTS smart_parenting CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE smart_parenting;

CREATE TABLE IF NOT EXISTS parents (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS children (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  parent_id BIGINT UNSIGNED NOT NULL,
  name VARCHAR(100) NOT NULL,
  birth_date DATE NULL,
  allergies TEXT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_children_parent FOREIGN KEY (parent_id) REFERENCES parents(id) ON DELETE CASCADE,
  INDEX idx_children_parent (parent_id)
);

CREATE TABLE IF NOT EXISTS growth_records (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  child_id BIGINT UNSIGNED NOT NULL,
  height_cm DECIMAL(5,2) NULL,
  weight_kg DECIMAL(5,2) NULL,
  recorded_on DATE NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_growth_child FOREIGN KEY (child_id) REFERENCES children(id) ON DELETE CASCADE,
  INDEX idx_growth_child_date (child_id, recorded_on)
);

CREATE TABLE IF NOT EXISTS mood_records (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  child_id BIGINT UNSIGNED NOT NULL,
  mood VARCHAR(30) NOT NULL,
  recorded_on DATE NOT NULL,
  note VARCHAR(500) NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_mood_child FOREIGN KEY (child_id) REFERENCES children(id) ON DELETE CASCADE,
  INDEX idx_mood_child_date (child_id, recorded_on)
);

CREATE TABLE IF NOT EXISTS nutrition_preferences (
  child_id BIGINT UNSIGNED PRIMARY KEY,
  age_group VARCHAR(30) NULL,
  food_preference VARCHAR(50) NULL,
  preference VARCHAR(50) NULL DEFAULT 'All foods',
  foods_to_avoid TEXT NULL,
  water_goal TINYINT UNSIGNED NOT NULL DEFAULT 6,
  CONSTRAINT fk_nutrition_child FOREIGN KEY (child_id) REFERENCES children(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vaccinations (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  child_id BIGINT UNSIGNED NOT NULL,
  vaccine_name VARCHAR(150) NOT NULL,
  due_date DATE NULL,
  status VARCHAR(30) NOT NULL DEFAULT 'upcoming',
  notes VARCHAR(500) NULL,
  CONSTRAINT fk_vaccine_child FOREIGN KEY (child_id) REFERENCES children(id) ON DELETE CASCADE,
  INDEX idx_vaccine_child_date (child_id, due_date)
);

CREATE TABLE IF NOT EXISTS mother_wellness (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  parent_id BIGINT UNSIGNED NOT NULL,
  record_date DATE NOT NULL,
  mood VARCHAR(30) NULL,
  sleep_hours DECIMAL(4,2) NULL,
  water_glasses TINYINT UNSIGNED NULL,
  self_care_count TINYINT UNSIGNED NULL,
  note VARCHAR(500) NULL,
  CONSTRAINT fk_wellness_parent FOREIGN KEY (parent_id) REFERENCES parents(id) ON DELETE CASCADE,
  UNIQUE KEY uq_wellness_parent_date (parent_id, record_date),
  INDEX idx_wellness_parent_date (parent_id, record_date)
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash CHAR(64) PRIMARY KEY,
  parent_id BIGINT UNSIGNED NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_session_parent FOREIGN KEY (parent_id) REFERENCES parents(id) ON DELETE CASCADE,
  INDEX idx_session_expiry (expires_at)
);
