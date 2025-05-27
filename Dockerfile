FROM bitnami/keycloak:latest

USER root

# Tạo cấu trúc thư mục cho theme
RUN mkdir -p /opt/bitnami/keycloak/themes/my-theme/login/resources/css \
    && mkdir -p /opt/bitnami/keycloak/themes/my-theme/login

# Sao chép các file theme
COPY theme.properties /opt/bitnami/keycloak/themes/my-theme/
COPY cccd-phone-form.ftl /opt/bitnami/keycloak/themes/my-theme/login/

# Cấu hình permissions
RUN chown -R 1001:1001 /opt/bitnami/keycloak/themes/my-theme

USER 1001