# Nami

#### Database( MySQL )
```mysql
CREATE SCHEMA `app` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin ;
CREATE USER 'app'@'%' IDENTIFIED BY '1234qwer';
GRANT ALL PRIVILEGES ON `app`.* TO 'app'@'%' WITH GRANT OPTION;
```
```mysql
# table schema
CREATE TABLE `app`.`table1` (
  `id` BIGINT NOT NULL AUTO_INCREMENT,
  `gmt_created` TIMESTAMP(6) NULL,
  `gmt_modified` TIMESTAMP(6) NULL,
  `create_user` VARCHAR(45) NULL,
  `modify_user` VARCHAR(45) NULL,
  `value` INT NULL DEFAULT 0,
  PRIMARY KEY (`id`));

CREATE TABLE `app`.`table2` (
  `id` BIGINT NOT NULL AUTO_INCREMENT,
  `gmt_created` TIMESTAMP(6) NULL,
  `gmt_modified` TIMESTAMP(6) NULL,
  `create_user` VARCHAR(45) NULL,
  `table1_id` BIGINT NULL,
  `value` INT NULL DEFAULT 0,
  PRIMARY KEY (`id`));

```

#### Launch(dev)
```shell
python3.6 -u server.py --service=app1 --port=8262 --mode=dev --log_to_stderr
```

#### Swagger API definition(auto)
```html
http://{service_domain}:{port}/doc
```
