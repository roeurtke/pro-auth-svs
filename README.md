## Set up and configuration

1. Clone the repository:
   ```
   git clone <repository-url>
   ```

2. Start Docker:
   ```
   By running command or open docker desktop
   ```

3. Run command to create network:
   ```
   docker network create core-network
   ```

4. Pull PostgreSQL image:
   ```
   docker run --name postgres --network core-network -e POSTGRES_USER={username} -e POSTGRES_PASSWORD={password} -e POSTGRES_DB=authdb -p 5432:5432 -d postgres:latest
   EX: docker run --name postgres --network core-network -e POSTGRES_USER=test -e POSTGRES_PASSWORD=123456 -e POSTGRES_DB=authdb -p 5432:5432 -d postgres:latest
   ```

5. Pull pgAdmin image and register server:
   ```
   docker run --name pgadmin4 --network core-network -e PGADMIN_DEFAULT_EMAIL={email} -e PGADMIN_DEFAULT_PASSWORD={password} -p 5050:80 -d dpage/pgadmin4
   EX: docker run --name pgadmin4 --network core-network -e PGADMIN_DEFAULT_EMAIL=admin@example.com -e PGADMIN_DEFAULT_PASSWORD=admin -p 5050:80 -d dpage/pgadmin4

   Open pgAdmin:
        $BROWSER http://localhost:5050
        Login (admin@admin.com / root)
        Servers → Register → Server...
        General: Name = Core Services (any name)

    Connection:
        Host name/address = postgres
        Port = 5432
        Maintenance database = postgres
        Username = {username}
        Password = {password}
        Save
   ```
6. Build docker:
   ```
   Open auth project in VScode
   Install extension: Dev Containers
   Type command: Ctrl+Shift+P
   Run: "Dev Containers: Reopen in Container"
   ```

7. Run project:
   ```
   Run command:
      mvn clean install -DskipTests
      In application.properties file
         - Update: app.db.init=true
      mvn spring-boot:run
   ```

8. Swagger UI:
   ```
   Link: http://localhost:8080/swagger-ui/index.html
   ```

## User activity

The service records authentication events, user-management audit events, and API request metadata in `tbl_user_activity`. Authenticated requests also update `tbl_user.last_active_at`.

Users with `USER_READ` permission can query the paginated activity history at `GET /api/v1/auth_svs/user_mod/activity`. Use the optional `userId`, `page`, and `size` query parameters to filter the results.