# Stage 1: Build the extension
FROM maven:3.9.6-eclipse-temurin-17 AS extension-builder

WORKDIR /opt/keycloak-extension-source

# Copy the source files
COPY pom.xml .
COPY src ./src

# Remove the custom build directory from pom.xml so Maven uses the default 'target/'
# then build the package
RUN sed -i '/<directory>${project.basedir}<\/directory>/d' pom.xml && \
    mvn clean package -DskipTests

# Stage 2: Build the Keycloak image with the extension and themes
FROM quay.io/keycloak/keycloak:22.0.5

# Copy the built JAR from the extension-builder stage
COPY --from=extension-builder /opt/keycloak-extension-source/target/keycloak-openid2-steam.jar /opt/keycloak/providers/

# Copy the Steam theme
COPY keycloak/themes/steam /opt/keycloak/themes/steam

# Run the Keycloak build command to optimize the server with the new provider
RUN /opt/keycloak/bin/kc.sh build --db=dev-file

# Expose the default Keycloak port
EXPOSE 8080

# For development, start with dev mode
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start-dev"]
