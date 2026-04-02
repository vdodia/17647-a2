-- Bookstore schema initialization
-- Run automatically by MySQL docker image on first start

DROP TABLE IF EXISTS books;
CREATE TABLE IF NOT EXISTS books (
    ISBN        VARCHAR(20)     PRIMARY KEY,
    title       VARCHAR(255)    NOT NULL,
    Author      VARCHAR(255)    NOT NULL,
    description TEXT            NOT NULL,
    genre       VARCHAR(100)    NOT NULL,
    price       DECIMAL(10, 2)  NOT NULL,
    quantity    INT             NOT NULL,
    summary     TEXT
);

DROP TABLE IF EXISTS customers;
CREATE TABLE IF NOT EXISTS customers (
    id          INT             AUTO_INCREMENT PRIMARY KEY,
    userId      VARCHAR(255)    UNIQUE NOT NULL,
    name        VARCHAR(255)    NOT NULL,
    phone       VARCHAR(50)     NOT NULL,
    address     VARCHAR(255)    NOT NULL,
    address2    VARCHAR(255),
    city        VARCHAR(100)    NOT NULL,
    state       CHAR(2)         NOT NULL,
    zipcode     VARCHAR(10)     NOT NULL
);
