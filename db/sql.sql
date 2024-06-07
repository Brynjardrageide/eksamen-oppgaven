CREATE TABLE IF NOT EXISTS `roles` (
  `role_id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `role_name` TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS `user` (
  `userid` INTEGER PRIMARY KEY AUTOINCREMENT,
  `username` TEXT NOT NULL,
  `email` TEXT NOT NULL,
  `password` TEXT NOT NULL,
  `first_name` TEXT NOT NULL,
  `last_name` TEXT NOT NULL,
  `phone` TEXT NOT NULL,
  `adresse` TEXT NOT NULL,
  `role_id` INTEGER,
  FOREIGN KEY (`role_id`) REFERENCES `roles` (`role_id`)
);