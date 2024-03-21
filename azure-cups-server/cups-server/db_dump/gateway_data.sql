-- phpMyAdmin SQL Dump
-- version 5.2.0
-- https://www.phpmyadmin.net/
--
-- Host: localhost
-- Generation Time: Aug 10, 2022 at 07:37 AM
-- Server version: 10.4.24-MariaDB
-- PHP Version: 8.1.6

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `cups_server`
--

-- --------------------------------------------------------

--
-- Table structure for table `gateway_data`
--

CREATE TABLE `gateway_data` (
  `id` int(11) NOT NULL,
  `gateway_name` varchar(20) NOT NULL,
  `cups_cred` text NOT NULL,
  `tc_cred` text NOT NULL,
  `tcUri` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `gateway_data`
--

INSERT INTO `gateway_data` (`id`, `gateway_name`, `cups_cred`, `tc_cred`, `tcUri`) VALUES
(1, '8002:9cff:fe08:7c18', 'Bearer 4PPxT9FjpRI+FvxGp1JTMpgbF4meJ1k3jB/I9ucR9R9VXWx4bVUxnkeBAGtCJqQ53OP64uCIwBOMbeeq1Zn5QNDyhhudpeIuTDH/Yx3aOQF9AHQs/7eSNKKyHGpGcH4JaPXrKDIF6ag3ZCJ0oykruqYGViQcmxa1FBITo+kJ', 'MHcCAQEEIEQ+VlTv1Z1IE96wNcgEfWo4KRePHImRXzE3Z10tieQSoAoGCCqGSM49AwEHoUQDQgAEtqHMkDBlhoMYDYKEDAHYdrZMDKc20OGYABHF7/MLAzyetKTSu2MW5EJ6PUQW4WY84ttvrfZzg2iDfP4IGL0lOQ==', 1);

--
-- Indexes for dumped tables
--

--
-- Indexes for table `gateway_data`
--
ALTER TABLE `gateway_data`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `gateway_data`
--
ALTER TABLE `gateway_data`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
