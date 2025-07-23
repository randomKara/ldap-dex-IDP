FROM httpd:2.4.63@sha256:437b9f7d469dd606fa6d2a5f9a3be55fe3af7e0c66e0329da8c14b291ae0d31c

# Install mod_auth_openidc
RUN apt-get update \
  && apt-get install -y --no-install-recommends wget ca-certificates libcjose0 libhiredis0.14 apache2-api-20120211 apache2-bin libldap-2.5-0 libssl3 libldap-common \
  && apt-get check \
  && wget https://github.com/OpenIDC/mod_auth_openidc/releases/download/v2.4.16.6/libapache2-mod-auth-openidc_2.4.16.6-1.bookworm_amd64.deb \
  && dpkg -i libapache2-mod-auth-openidc_2.4.16.6-1.bookworm_amd64.deb \
  && ln -s /usr/lib/apache2/modules/mod_auth_openidc.so /usr/local/apache2/modules/mod_auth_openidc.so \
  && rm -rf /var/lib/apt/lists/* \
  && apt-get clean

# Copy configuration files
COPY proxy.conf /usr/local/apache2/conf/httpd.conf
COPY oidc.conf /usr/local/apache2/conf/extra/oidc.conf

# Enable mod_auth_openidc
RUN echo "\n\nLoadModule auth_openidc_module modules/mod_auth_openidc.so\n\nInclude conf/extra/oidc.conf\n" >> /usr/local/apache2/conf/httpd.conf

EXPOSE 80

CMD ["httpd-foreground"] 