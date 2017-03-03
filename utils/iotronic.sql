-- MySQL Script generated by MySQL Workbench
-- lun 04 apr 2016 15:41:37 CEST
-- Model: New Model    Version: 1.0
-- MySQL Workbench Forward Engineering

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL,ALLOW_INVALID_DATES';

-- -----------------------------------------------------
-- Schema iotronic
-- -----------------------------------------------------
DROP SCHEMA IF EXISTS `iotronic` ;

-- -----------------------------------------------------
-- Schema iotronic
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `iotronic` DEFAULT CHARACTER SET utf8 ;
USE `iotronic` ;

-- -----------------------------------------------------
-- Table `iotronic`.`conductors`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `iotronic`.`conductors` ;

CREATE TABLE IF NOT EXISTS `iotronic`.`conductors` (
  `created_at` DATETIME NULL DEFAULT NULL,
  `updated_at` DATETIME NULL DEFAULT NULL,
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `hostname` VARCHAR(255) NOT NULL,
  `online` TINYINT(1) NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `uniq_conductors0hostname` (`hostname` ASC))
ENGINE = InnoDB
AUTO_INCREMENT = 6
DEFAULT CHARACTER SET = utf8;

-- -----------------------------------------------------
-- Table `iotronic`.`wampagents`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `iotronic`.`wampagents` ;

CREATE TABLE IF NOT EXISTS `iotronic`.`wampagents` (
  `created_at` DATETIME NULL DEFAULT NULL,
  `updated_at` DATETIME NULL DEFAULT NULL,
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `hostname` VARCHAR(255) NOT NULL,
  `wsurl` VARCHAR(255) NOT NULL,
  `online` TINYINT(1) NULL DEFAULT NULL,
  `ragent` TINYINT(1) NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `uniq_wampagents0hostname` (`hostname` ASC))
ENGINE = InnoDB
AUTO_INCREMENT = 6
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `iotronic`.`nodes`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `iotronic`.`nodes` ;

CREATE TABLE IF NOT EXISTS `iotronic`.`nodes` (
  `created_at` DATETIME NULL DEFAULT NULL,
  `updated_at` DATETIME NULL DEFAULT NULL,
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `uuid` VARCHAR(36) NOT NULL,
  `code` VARCHAR(25) NOT NULL,
  `status` VARCHAR(15) NULL DEFAULT NULL,
  `name` VARCHAR(255) NULL DEFAULT NULL,
  `type` VARCHAR(255) NOT NULL,
  `agent` VARCHAR(255) NULL DEFAULT NULL,
  `owner` VARCHAR(36) NOT NULL,
  `project` VARCHAR(36) NOT NULL,
  `mobile` TINYINT(1) NOT NULL DEFAULT '0',
  `config` TEXT NULL DEFAULT NULL,
  `extra` TEXT NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `uuid` (`uuid` ASC),
  UNIQUE INDEX `code` (`code` ASC))
ENGINE = InnoDB
AUTO_INCREMENT = 132
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `iotronic`.`locations`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `iotronic`.`locations` ;

CREATE TABLE IF NOT EXISTS `iotronic`.`locations` (
  `created_at` DATETIME NULL DEFAULT NULL,
  `updated_at` DATETIME NULL DEFAULT NULL,
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `longitude` VARCHAR(18) NULL DEFAULT NULL,
  `latitude` VARCHAR(18) NULL DEFAULT NULL,
  `altitude` VARCHAR(18) NULL DEFAULT NULL,
  `node_id` INT(11) NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `node_id` (`node_id` ASC),
  CONSTRAINT `location_ibfk_1`
    FOREIGN KEY (`node_id`)
    REFERENCES `iotronic`.`nodes` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE)
ENGINE = InnoDB
AUTO_INCREMENT = 6
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `iotronic`.`sessions`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `iotronic`.`sessions` ;

CREATE TABLE IF NOT EXISTS `iotronic`.`sessions` (
  `created_at` DATETIME NULL DEFAULT NULL,
  `updated_at` DATETIME NULL DEFAULT NULL,
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `valid` TINYINT(1) NOT NULL DEFAULT '1',
  `session_id` VARCHAR(18) NOT NULL,
  `node_uuid` VARCHAR(36) NOT NULL,
  `node_id` INT(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `session_id` (`session_id` ASC),
  INDEX `session_node_id` (`node_id` ASC),
  CONSTRAINT `session_node_id`
    FOREIGN KEY (`node_id`)
    REFERENCES `iotronic`.`nodes` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE)
ENGINE = InnoDB
AUTO_INCREMENT = 10
DEFAULT CHARACTER SET = utf8;

-- -----------------------------------------------------
-- Table `iotronic`.`plugins`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `iotronic`.`plugins` ;

CREATE TABLE IF NOT EXISTS `iotronic`.`plugins` (
  `created_at` DATETIME NULL DEFAULT NULL,
  `updated_at` DATETIME NULL DEFAULT NULL,
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `uuid` VARCHAR(36) NOT NULL,
  `name` VARCHAR(255) NULL DEFAULT NULL,
  `config` TEXT NULL DEFAULT NULL,
  `extra` TEXT NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `uuid` (`uuid` ASC))
ENGINE = InnoDB
AUTO_INCREMENT = 132
DEFAULT CHARACTER SET = utf8;

-- -----------------------------------------------------
-- Table `iotronic`.`injected_plugins`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `iotronic`.`injected_plugins` ;

CREATE TABLE IF NOT EXISTS `iotronic`.`injected_plugins` (
  `created_at` DATETIME NULL DEFAULT NULL,
  `updated_at` DATETIME NULL DEFAULT NULL,
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `node_uuid` VARCHAR(36) NOT NULL,
  `node_id` INT(11) NOT NULL,
  `plugin_uuid` VARCHAR(36) NOT NULL,
  `plugin_id` INT(11) NOT NULL,
  `status` VARCHAR(15) NOT NULL DEFAULT 'injected',
  PRIMARY KEY (`id`),
  INDEX `node_id` (`node_id` ASC),
  CONSTRAINT `node_id`
    FOREIGN KEY (`node_id`)
    REFERENCES `iotronic`.`nodes` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  INDEX `plugin_id` (`plugin_id` ASC),
  CONSTRAINT `plugin_id`
    FOREIGN KEY (`plugin_id`)
    REFERENCES `iotronic`.`plugins` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE)
ENGINE = InnoDB
AUTO_INCREMENT = 132
DEFAULT CHARACTER SET = utf8;


SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;


-- insert testing nodes
INSERT INTO `nodes` VALUES
  ('2017-02-20 10:38:26',NULL,132,'f3961f7a-c937-4359-8848-fb64aa8eeaaa','12345','registered','node','server',NULL,'eee383360cc14c44b9bf21e1e003a4f3','4adfe95d49ad41398e00ecda80257d21',0,'{}','{}'),
  ('2017-02-20 10:38:45',NULL,133,'ba1efce9-cad9-4ae1-a5d1-d90a8d203d3b','yunyun','registered','yun22','yun',NULL,'eee383360cc14c44b9bf21e1e003a4f3','4adfe95d49ad41398e00ecda80257d21',0,'{}','{}'),
  ('2017-02-20 10:39:08',NULL,134,'65f9db36-9786-4803-b66f-51dcdb60066e','test','registered','test','server',NULL,'eee383360cc14c44b9bf21e1e003a4f3','4adfe95d49ad41398e00ecda80257d21',0,'{}','{}');
INSERT INTO `locations` VALUES
  ('2017-02-20 10:38:26',NULL,6,'2','1','3',132),
  ('2017-02-20 10:38:45',NULL,7,'2','1','3',133),
  ('2017-02-20 10:39:08',NULL,8,'2','1','3',134)