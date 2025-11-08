-- MySQL dump 10.13  Distrib 8.0.43, for Win64 (x86_64)
--
-- Host: 127.0.0.1    Database: hotel_oasis_db
-- ------------------------------------------------------
-- Server version	8.0.43

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `clientes`
--

DROP TABLE IF EXISTS `clientes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `clientes` (
  `id_cliente` bigint unsigned NOT NULL AUTO_INCREMENT,
  `nombre` varchar(100) NOT NULL,
  `apellido` varchar(100) NOT NULL,
  `tipo_documento` varchar(50) DEFAULT NULL,
  `documento` varchar(50) DEFAULT NULL,
  `telefono` varchar(30) DEFAULT NULL,
  `email` varchar(150) DEFAULT NULL,
  `direccion` text,
  `ciudad` varchar(50) DEFAULT NULL,
  `pais` varchar(50) DEFAULT NULL,
  `fecha_nacimiento` date DEFAULT NULL,
  `nacionalidad` varchar(50) DEFAULT NULL,
  `contrasena` varchar(255) NOT NULL DEFAULT '12345',
  `google_id` varchar(255) DEFAULT NULL,
  `facebook_id` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id_cliente`),
  UNIQUE KEY `id_cliente` (`id_cliente`),
  UNIQUE KEY `documento` (`documento`),
  UNIQUE KEY `email` (`email`),
  UNIQUE KEY `google_id` (`google_id`),
  UNIQUE KEY `facebook_id` (`facebook_id`)
) ENGINE=InnoDB AUTO_INCREMENT=16 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `clientes`
--

LOCK TABLES `clientes` WRITE;
/*!40000 ALTER TABLE `clientes` DISABLE KEYS */;
INSERT INTO `clientes` VALUES (1,'Carlos','Ram├¡rez','INE','A12345678','5551234567','carlos.ramirez@example.com','Calle Falsa 123','Ciudad de M├®xico','M├®xico','1990-05-12','Mexicana','12345',NULL,NULL),(2,'Mar├¡a','L├│pez','Pasaporte','P987654321','5559876543','maria.lopez@example.com','Av. Central 45','Guadalajara','M├®xico','1985-08-22','Mexicana','12345',NULL,NULL),(3,'Jorge','Mart├¡nez','INE','B98765432','5554567890','jorge.martinez@example.com','Calle Luna 7','Monterrey','M├®xico','1978-11-30','Mexicana','12345',NULL,NULL),(4,'Ana','G├│mez','Pasaporte','P123987456','5552223344','ana.gomez@example.com','Boulevard 10','Puebla','M├®xico','1995-02-14','Mexicana','12345',NULL,NULL),(5,'Luis','Fern├índez','INE','C56473829','5553334455','luis.fernandez@example.com','Calle Verde 22','Canc├║n','M├®xico','1988-07-07','Mexicana','12345',NULL,NULL),(6,'Juan','Perez',NULL,NULL,'555-1234','juan.perez@example.com',NULL,NULL,NULL,NULL,NULL,'12345',NULL,NULL),(7,'Angel Dario','GonzÃ¡les DomÃ­nguez',NULL,NULL,'9221834958','angeldariogonzalezdomingez54@gmail.com',NULL,NULL,NULL,NULL,NULL,'$2b$10$TkjHkPWd3uHhf.MK1P6ZV.uYEMVrxCF6y9WsiPxr48nWwnNQCpXbu',NULL,NULL),(8,'andres','gonzalez',NULL,NULL,'9241396791','amerika_@hotmail.com',NULL,NULL,NULL,NULL,NULL,'12345',NULL,NULL),(9,'OLGA VERONICA','f fdjjkfjfkjf',NULL,NULL,'jdsjdjdjdjdjdsjd','djjndjndjdjf@jdjdj.com',NULL,NULL,NULL,NULL,NULL,'12345',NULL,NULL),(10,'dario','aguilar gonzalez',NULL,NULL,'9231234050','angel@gaa.com',NULL,NULL,NULL,NULL,NULL,'12345',NULL,NULL),(11,'Angel Dario','Gonzalez',NULL,NULL,NULL,'anngel@dario.com',NULL,NULL,NULL,NULL,NULL,'$2b$10$xVM2WNZmCWcJ/4upnOYYGe3sr6P.Tnlnj6OGkEFdUoq2Ru2lYDSKe',NULL,NULL),(12,'Randal Steven','Aguilar Tomas',NULL,NULL,NULL,'tomas@aguilar.comm',NULL,NULL,NULL,NULL,NULL,'$2b$10$qMgYHVnklT3PgWWrMNjwR.2tiNJtyiRzfdDNH/DkBVDtAbs9.3L9e',NULL,NULL),(14,'Randal','Tomas',NULL,NULL,NULL,'tomate@aguilar.com',NULL,NULL,NULL,NULL,NULL,'$2b$10$LaC2fwgsaDNyf9h4jrV9bO0orQJalr0f9LcpS1paZvKtzK1lR9QWy',NULL,NULL),(15,'Angel Daniel','Santiago Apostol',NULL,NULL,NULL,'Chapulin@daniel.com',NULL,NULL,NULL,NULL,NULL,'$2b$10$BbY4lR3PoO/SBmqXHULZ6eAT5HoutUYTcZHNHQUqI3jYGQzYm5b1W',NULL,NULL);
/*!40000 ALTER TABLE `clientes` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `habitacion`
--

DROP TABLE IF EXISTS `habitacion`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `habitacion` (
  `id_habitacion` bigint unsigned NOT NULL AUTO_INCREMENT,
  `numero` varchar(10) NOT NULL,
  `id_tipo` bigint unsigned DEFAULT NULL,
  `piso` int DEFAULT NULL,
  `capacidad` int DEFAULT NULL,
  `descripcion` text,
  `estado` varchar(20) DEFAULT 'Disponible',
  `fecha_ultimo_mantenimiento` date DEFAULT NULL,
  `estado_limpieza` varchar(20) DEFAULT 'Limpia',
  PRIMARY KEY (`id_habitacion`),
  UNIQUE KEY `id_habitacion` (`id_habitacion`),
  UNIQUE KEY `numero` (`numero`),
  KEY `idx_habitacion_numero` (`numero`),
  KEY `fk_habitacion_tipo` (`id_tipo`),
  CONSTRAINT `fk_habitacion_tipo` FOREIGN KEY (`id_tipo`) REFERENCES `tipos_habitacion` (`id_tipo`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=33 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `habitacion`
--

LOCK TABLES `habitacion` WRITE;
/*!40000 ALTER TABLE `habitacion` DISABLE KEYS */;
INSERT INTO `habitacion` VALUES (7,'101',1,1,1,NULL,'Disponible',NULL,'Limpia'),(8,'102',2,1,2,NULL,'Ocupada',NULL,'Limpia'),(9,'103',2,1,2,NULL,'Disponible',NULL,'Limpia'),(10,'104',3,1,2,NULL,'Disponible',NULL,'Limpia'),(11,'105',3,1,2,NULL,'Disponible',NULL,'Limpia'),(12,'106',4,1,4,NULL,'Disponible',NULL,'Limpia'),(13,'107',4,1,4,NULL,'Disponible',NULL,'Limpia'),(14,'201',1,2,1,NULL,'Disponible',NULL,'Limpia'),(15,'202',1,2,1,NULL,'Disponible',NULL,'Limpia'),(16,'203',2,2,2,NULL,'Disponible',NULL,'Limpia'),(17,'204',2,2,2,NULL,'Disponible',NULL,'Limpia'),(18,'205',2,2,2,NULL,'Disponible',NULL,'Limpia'),(19,'206',3,2,2,NULL,'Disponible',NULL,'Limpia'),(20,'207',3,2,2,NULL,'Disponible',NULL,'Limpia'),(21,'208',5,2,3,NULL,'Disponible',NULL,'Limpia'),(22,'301',1,3,1,NULL,'Disponible',NULL,'Limpia'),(23,'302',2,3,2,NULL,'Disponible',NULL,'Limpia'),(24,'303',2,3,2,NULL,'Disponible',NULL,'Limpia'),(25,'304',2,3,2,NULL,'Disponible',NULL,'Limpia'),(26,'305',3,3,2,NULL,'Disponible',NULL,'Limpia'),(27,'306',3,3,2,NULL,'Disponible',NULL,'Limpia'),(28,'307',4,3,4,NULL,'Disponible',NULL,'Limpia'),(29,'308',4,3,4,NULL,'Disponible',NULL,'Limpia'),(30,'309',5,3,3,NULL,'Disponible',NULL,'Limpia'),(31,'310',6,3,5,NULL,'Disponible',NULL,'Limpia');
/*!40000 ALTER TABLE `habitacion` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `historial_reservas`
--

DROP TABLE IF EXISTS `historial_reservas`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `historial_reservas` (
  `id_historial` int NOT NULL AUTO_INCREMENT,
  `id_reserva` bigint unsigned NOT NULL,
  `estado_anterior` varchar(50) DEFAULT NULL,
  `estado_nuevo` varchar(50) NOT NULL,
  `fecha_cambio` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `modificado_por` varchar(100) NOT NULL,
  PRIMARY KEY (`id_historial`),
  KEY `id_reserva` (`id_reserva`),
  CONSTRAINT `historial_reservas_ibfk_1` FOREIGN KEY (`id_reserva`) REFERENCES `reservas` (`id_reserva`)
) ENGINE=InnoDB AUTO_INCREMENT=20 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `historial_reservas`
--

LOCK TABLES `historial_reservas` WRITE;
/*!40000 ALTER TABLE `historial_reservas` DISABLE KEYS */;
INSERT INTO `historial_reservas` VALUES (1,12,NULL,'Pendiente','2025-10-16 18:41:49','Cliente ID: 7'),(2,13,NULL,'Pendiente','2025-10-16 20:07:14','Cliente ID: 14'),(3,14,NULL,'Pendiente','2025-10-17 00:49:38','Cliente ID: 14'),(4,14,'Pendiente','Confirmada','2025-10-17 18:41:17','Recepcionista ID: 1'),(5,14,'Confirmada','Check-out','2025-10-17 18:41:34','Recepcionista ID: 1'),(6,14,'Check-out','Confirmada','2025-10-17 18:41:46','Recepcionista ID: 1'),(7,14,'Confirmada','Check-out','2025-10-17 18:51:30','Recepcionista ID: 1'),(8,3,'Cancelada','Check-out','2025-10-17 18:51:51','Recepcionista ID: 1'),(9,2,'Pendiente','Check-in','2025-10-17 18:52:11','Recepcionista ID: 1'),(10,12,'Pendiente','Confirmada','2025-10-17 18:54:00','Recepcionista ID: 1'),(11,6,'Pendiente','Confirmada','2025-10-17 22:29:14','Administrador ID: 2'),(12,11,'Pendiente','Confirmada','2025-10-18 00:25:19','Administrador ID: 2'),(13,14,'Check-out','Confirmada','2025-10-18 01:08:34','Recepcionista ID: 1'),(14,1,'Confirmada','Check-out','2025-10-18 03:39:55','Recepcionista ID: 1'),(15,8,'Pendiente','Confirmada','2025-10-20 01:53:23','Recepcionista ID: 1'),(16,7,'Pendiente','Confirmada','2025-10-20 01:53:33','Recepcionista ID: 1'),(17,15,NULL,'Pendiente','2025-10-20 02:48:27','Cliente ID: 7'),(18,15,'Pendiente','Confirmada','2025-10-20 02:48:57','Administrador ID: 2'),(19,16,NULL,'Pendiente','2025-10-22 20:02:33','Cliente ID: 15');
/*!40000 ALTER TABLE `historial_reservas` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `huespedes_adicionales`
--

DROP TABLE IF EXISTS `huespedes_adicionales`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `huespedes_adicionales` (
  `id_huesped_adicional` int NOT NULL AUTO_INCREMENT,
  `id_reserva` bigint unsigned NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `apellido` varchar(100) NOT NULL,
  `documento` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`id_huesped_adicional`),
  KEY `fk_huesped_reserva` (`id_reserva`),
  CONSTRAINT `fk_huesped_reserva` FOREIGN KEY (`id_reserva`) REFERENCES `reservas` (`id_reserva`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `huespedes_adicionales_ibfk_1` FOREIGN KEY (`id_reserva`) REFERENCES `reservas` (`id_reserva`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `huespedes_adicionales`
--

LOCK TABLES `huespedes_adicionales` WRITE;
/*!40000 ALTER TABLE `huespedes_adicionales` DISABLE KEYS */;
/*!40000 ALTER TABLE `huespedes_adicionales` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `pagos`
--

DROP TABLE IF EXISTS `pagos`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `pagos` (
  `id_pago` bigint unsigned NOT NULL AUTO_INCREMENT,
  `id_reserva` bigint unsigned DEFAULT NULL,
  `monto` decimal(10,2) NOT NULL,
  `fecha_pago` timestamp NULL DEFAULT NULL,
  `metodo_pago` varchar(50) DEFAULT NULL,
  `referencia_pago` varchar(100) DEFAULT NULL,
  `estado_pago` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`id_pago`),
  UNIQUE KEY `id_pago` (`id_pago`),
  KEY `fk_pago_reserva` (`id_reserva`),
  CONSTRAINT `fk_pago_reserva` FOREIGN KEY (`id_reserva`) REFERENCES `reservas` (`id_reserva`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `pagos`
--

LOCK TABLES `pagos` WRITE;
/*!40000 ALTER TABLE `pagos` DISABLE KEYS */;
INSERT INTO `pagos` VALUES (1,1,1000.00,'2025-10-05 20:30:00','Tarjeta de cr├®dito','TXN-2025-0001','Completado'),(2,2,500.00,'2025-10-09 17:00:00','Efectivo',NULL,'Pendiente'),(3,4,1600.00,'2025-10-18 15:15:00','Tarjeta de d├®bito','TXN-2025-0004','Completado');
/*!40000 ALTER TABLE `pagos` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `personal`
--

DROP TABLE IF EXISTS `personal`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `personal` (
  `id_personal` bigint unsigned NOT NULL AUTO_INCREMENT,
  `nombre` varchar(100) NOT NULL,
  `apellido` varchar(100) NOT NULL,
  `puesto` varchar(50) NOT NULL,
  `correo` varchar(150) DEFAULT NULL,
  `direccion` text,
  `telefono` varchar(30) DEFAULT NULL,
  `fecha_contratacion` date DEFAULT NULL,
  `salario` decimal(10,2) DEFAULT NULL,
  `activo` tinyint(1) DEFAULT '1',
  `contrasena` varchar(255) NOT NULL,
  PRIMARY KEY (`id_personal`),
  UNIQUE KEY `id_personal` (`id_personal`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `personal`
--

LOCK TABLES `personal` WRITE;
/*!40000 ALTER TABLE `personal` DISABLE KEYS */;
INSERT INTO `personal` VALUES (1,'Laura','Garcia','Recepcionista','laura.garcia@hotel.com','Calle Trabajo 5','5551112233','2022-03-01',12000.00,1,'$2b$12$hu56rBGU3t4AfbCzXdm5w.DHcd3AZUxXOI4QISWcPbfbCCZbSA6h.'),(2,'Andress','Santos','Administrador','andres.santos@hotel.com','Av. Admin 10','5554445566','2020-06-15',25000.00,1,'$2a$12$IsaF9Fo8UC5kpo/3cOFlheL7gYUiegIJqlvS2pBh2U5rGgYYKGLBm'),(3,'Paola','Mendoza','Limpieza','paola.mendoza@hotel.com','Calle Limpia 8','5557778899','2023-01-20',9000.00,1,''),(4,'Miguel','Ruiz','Mantenimiento','miguel.ruiz@hotel.com','Calle Repara 12','5556667788','2019-09-10',14000.00,0,''),(5,'Andres','Zenteno','Administrador','andy@zente.com',NULL,NULL,NULL,NULL,1,'$2b$12$ogItOFeuedl1JsiH72EQ/.BkFmJNLm.osQoiYrYMu72TpyfDmB/ia'),(6,'Stevn','Tomas','Mantenimiento','steven@tomas.com',NULL,NULL,NULL,NULL,1,'$2b$12$84nrVCHd6C7ztIRHGW77tuMY.GhkoBvDi2ZEs7CoIBVwnuy1pZbFu');
/*!40000 ALTER TABLE `personal` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `reservas`
--

DROP TABLE IF EXISTS `reservas`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `reservas` (
  `id_reserva` bigint unsigned NOT NULL AUTO_INCREMENT,
  `codigo_reserva` varchar(20) DEFAULT NULL,
  `id_cliente` bigint unsigned DEFAULT NULL,
  `id_habitacion` bigint unsigned DEFAULT NULL,
  `fecha_reserva` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `fecha_inicio` date NOT NULL,
  `fecha_fin` date NOT NULL,
  `num_huespedes` int DEFAULT '1',
  `estado` varchar(20) DEFAULT 'Pendiente',
  `observaciones` text,
  `precio_por_noche` decimal(10,2) NOT NULL,
  PRIMARY KEY (`id_reserva`),
  UNIQUE KEY `id_reserva` (`id_reserva`),
  UNIQUE KEY `codigo_reserva` (`codigo_reserva`),
  KEY `idx_reservas_codigo` (`codigo_reserva`),
  KEY `fk_reserva_cliente` (`id_cliente`),
  CONSTRAINT `fk_reserva_cliente` FOREIGN KEY (`id_cliente`) REFERENCES `clientes` (`id_cliente`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=17 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `reservas`
--

LOCK TABLES `reservas` WRITE;
/*!40000 ALTER TABLE `reservas` DISABLE KEYS */;
INSERT INTO `reservas` VALUES (1,'RES-0001',1,1,'2025-09-20 16:00:00','2025-10-05','2025-10-07',1,'Check-out','Llegada tarde',0.00),(2,'RES-0002',2,2,'2025-09-25 15:30:00','2025-10-10','2025-10-15',2,'Check-in',NULL,0.00),(3,'RES-0003',3,4,'2025-09-10 18:15:00','2025-11-01','2025-11-05',3,'Check-out','Cancelada por el cliente',0.00),(4,'RES-0004',4,3,'2025-09-30 14:00:00','2025-10-20','2025-10-22',2,'Confirmada','Pide cuna',0.00),(5,'RES-0005',5,6,'2025-09-29 22:45:00','2025-12-01','2025-12-07',2,'Pendiente',NULL,0.00),(6,'RES-1759603256071',6,4,'2025-10-04 18:40:56','2025-11-25','2025-11-28',2,'Confirmada',NULL,0.00),(7,'RES-1760065187264',7,3,'2025-10-10 02:59:47','2025-10-12','2025-10-14',2,'Confirmada',NULL,0.00),(8,'RES-1760065236285',7,3,'2025-10-10 03:00:36','2025-10-09','2025-10-10',2,'Confirmada',NULL,0.00),(9,'RES-1760070680573',8,4,'2025-10-10 04:31:20','2025-10-09','2025-10-11',2,'Pendiente',NULL,0.00),(10,'RES-1760415042718',9,3,'2025-10-14 04:10:42','2025-10-14','2025-10-15',2,'Pendiente',NULL,0.00),(11,'RES-1760415530451',10,3,'2025-10-14 04:18:50','2025-10-14','2025-10-15',2,'Confirmada',NULL,0.00),(12,'RES-1760640109515',7,6,'2025-10-16 18:41:49','2025-10-16','2025-10-17',2,'Confirmada',NULL,800.00),(13,'RES-1760645234172',14,3,'2025-10-16 20:07:14','2025-10-16','2025-10-17',2,'Pendiente',NULL,800.00),(14,'RES-1760662178619',14,4,'2025-10-17 00:49:38','2025-10-16','2025-10-17',2,'Confirmada',NULL,1500.00),(15,'RES-1760928507859',7,8,'2025-10-20 02:48:27','2025-10-19','2025-10-20',2,'Confirmada',NULL,300.00),(16,'RES-1761163353489',15,9,'2025-10-22 20:02:33','2025-10-22','2025-10-25',2,'Pendiente',NULL,300.00);
/*!40000 ALTER TABLE `reservas` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tipos_habitacion`
--

DROP TABLE IF EXISTS `tipos_habitacion`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `tipos_habitacion` (
  `id_tipo` bigint unsigned NOT NULL AUTO_INCREMENT,
  `nombre` varchar(50) NOT NULL,
  `descripcion` text,
  `max_personas` int DEFAULT NULL,
  `camas` varchar(100) DEFAULT NULL,
  `area_m2` decimal(6,2) DEFAULT NULL,
  `servicios` text,
  `precio_base` decimal(10,2) NOT NULL DEFAULT '0.00',
  `imagen_url` text,
  PRIMARY KEY (`id_tipo`),
  UNIQUE KEY `id_tipo` (`id_tipo`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tipos_habitacion`
--

LOCK TABLES `tipos_habitacion` WRITE;
/*!40000 ALTER TABLE `tipos_habitacion` DISABLE KEYS */;
INSERT INTO `tipos_habitacion` VALUES (1,'Sencillo','Habitación acogedora con una cama individual, ideal para una persona.',1,'1 cama individual',NULL,NULL,240.00,'https://cf.bstatic.com/xdata/images/hotel/max1024x768/351361832.jpg?k=1691dadefd97a1d56fb611b15f32119dde011f680a92c8f80cbae7c8e0a60f82&o=;https://imgcy.trivago.com/c_limit,d_dummy.jpeg,f_auto,h_1020,q_auto,w_2000/partner-images/38/0c/fb3aeb72905126a938f920210254fd285b8b85c25670cf960c5c3ae27883.jpeg;https://imgcy.trivago.com/c_limit,d_dummy.jpeg,f_auto,h_1020,q_auto,w_2000/hotelier-images/32/da/b12e2edbb60c9d8e8f79fdcc980c9dcc85476c7629130c643fcd8b85ef92.jpeg;https://imgcy.trivago.com/c_limit,d_dummy.jpeg,f_auto,h_1020,q_auto,w_2000/partner-images/ae/bc/f206d629c6a99d6973732b8565c3ed7f1937355f16debae2931073326ac0.jpeg;https://imgcy.trivago.com/c_limit,d_dummy.jpeg,f_auto,h_1020,q_auto,w_2000/partner-images/a7/f4/e4086b163cd87ded51553ce51d29835558517150c23c4c165ecd67c70e0e.jpeg'),(2,'Matrimonial','Habitación con una cómoda cama matrimonial para dos personas.',2,'1 cama matrimonial',NULL,NULL,300.00,'https://imgcy.trivago.com/c_limit,d_dummy.jpeg,f_auto,h_1020,q_auto,w_2000/hotelier-images/e4/18/ed8e2ab848c094d7cb710ecb5d6ec97dc35bf0c08797317b8f7f6ad5e33c.jpeg;https://imgcy.trivago.com/c_limit,d_dummy.jpeg,f_auto,h_1020,q_auto,w_2000/hotelier-images/97/36/68c3e0b16e517e7e99659d3925c471effac54c92a27375a0ecd1410c900e.jpeg;https://imgcy.trivago.com/c_limit,d_dummy.jpeg,f_auto,h_1020,q_auto,w_2000/partner-images/ff/8a/49d1500968bdcbdf8d50dfcaae072bd8d4158f4b43a5767b4877a2c40123.jpeg;https://imgcy.trivago.com/c_limit,d_dummy.jpeg,f_auto,h_1020,q_auto,w_2000/hotelier-images/3e/b5/7fa5b8ab1e06a8a3a74a0be0e4e5510445b2b9e007bda53829730966a76b.jpeg;https://imgcy.trivago.com/c_limit,d_dummy.jpeg,f_auto,h_1020,q_auto,w_2000/hotelier-images/11/7f/d627be6c101ab159aeccc41be1c299556d0fbad02767afb312aa80a5afe7.jpeg'),(3,'Doble Individual','Habitación con dos camas individuales.',2,'2 camas individuales',NULL,NULL,330.00,'https://imgcy.trivago.com/c_limit,d_dummy.jpeg,f_auto,h_1020,q_auto,w_2000/hotelier-images/6b/07/d5ed42256883b506c3fa483f1eea5592f8b6e3814362a34253f471fca336.jpeg;https://imgcy.trivago.com/c_limit,d_dummy.jpeg,f_auto,h_1020,q_auto,w_2000/hotelier-images/dc/79/805791e597023b8ce17c3801acf7cf44390b6e97be6242cef6835f9923e6.jpeg;https://imgcy.trivago.com/c_limit,d_dummy.jpeg,f_auto,h_1020,q_auto,w_2000/hotelier-images/37/e4/0848f816091cb0f663048ffde335983f17da13114823f08ecd9e146f88e3.jpeg;https://imgcy.trivago.com/c_limit,d_dummy.jpeg,f_auto,h_1020,q_auto,w_2000/hotelier-images/b7/1d/dfb4aa104d24d7a1e22d907f820b892ca03feadfc8e2fdf616ec5d847076.jpeg'),(4,'Doble Matrimonial','Habitación espaciosa con dos camas matrimoniales, ideal para familias.',4,'2 camas matrimoniales',NULL,NULL,410.00,'https://imgcy.trivago.com/c_limit,d_dummy.jpeg,f_auto,h_1020,q_auto,w_2000/partner-images/5a/5c/230702c366ee60ba3398f0018008f2a6bcb52d7e2f4aba996bf89673775e.jpeg;https://imgcy.trivago.com/c_limit,d_dummy.jpeg,f_auto,h_1020,q_auto,w_2000/partner-images/c6/a7/aa14d1beb55e7874734001135bd670cf65565f0b9c3a365366e821bce788.jpeg;https://imgcy.trivago.com/c_limit,d_dummy.jpeg,f_auto,h_1020,q_auto,w_2000/partner-images/9c/f0/12861a19ba95205192e7244fad2efd1dfbe518999c800857daec026132d0.jpeg;https://imgcy.trivago.com/c_limit,d_dummy.jpeg,f_auto,h_1020,q_auto,w_2000/partner-images/72/9d/65ec82290f0ab02abbd65247ab62e4575f2d214b75f0cb9fcceee5546e91.jpeg'),(5,'Triple Individual','Habitación equipada con tres camas individuales para grupos.',3,'3 camas individuales',NULL,NULL,410.00,'https://hotelstayblue.com/wp-content/uploads/2021/09/hab-tres-camas-web.jpg;https://hotelstayblue.com/wp-content/uploads/2021/09/TRIPLE-TRES-CAMAS-scaled.jpg;https://cdn.easy-rez.com/production/hotels/048fe9f25b875f78f8cba622f7167a68/uploads/.rooms/th_0236526001530798210.jpg;https://media-cdn.tripadvisor.com/media/photo-f/05/72/1f/ea/centroamericano-hotel.jpg;https://previews.123rf.com/images/rilueda/rilueda1603/rilueda160300107/53242552-interior-of-a-hotel-room-with-three-beds.jpg'),(6,'Cinco Camas','Nuestra habitación más grande, con cinco camas individuales para grupos numerosos.',5,'5 camas individuales',NULL,NULL,610.00,'https://live.staticflickr.com/2747/4312926566_47f13b9af3_b.jpg;https://media-cdn.tripadvisor.com/media/photo-s/09/e3/f9/15/habitacion-multiple.jpg;https://posadasancristobalcuernavaca.com/hospedaje/wp-content/uploads/2021/02/hab06007.jpg;httpss://posadasancristobalcuernavaca.com/hospedaje/wp-content/uploads/2021/02/hab06006.jpg');
/*!40000 ALTER TABLE `tipos_habitacion` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-11-05 18:41:34
