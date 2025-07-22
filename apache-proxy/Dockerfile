FROM httpd:2.4-alpine

# Enable required modules
RUN sed -i 's/#LoadModule rewrite_module modules\/mod_rewrite.so/LoadModule rewrite_module modules\/mod_rewrite.so/' /usr/local/apache2/conf/httpd.conf && \
    sed -i 's/#LoadModule proxy_module modules\/mod_proxy.so/LoadModule proxy_module modules\/mod_proxy.so/' /usr/local/apache2/conf/httpd.conf && \
    sed -i 's/#LoadModule proxy_http_module modules\/mod_proxy_http.so/LoadModule proxy_http_module modules\/mod_proxy_http.so/' /usr/local/apache2/conf/httpd.conf && \
    sed -i 's/#LoadModule headers_module modules\/mod_headers.so/LoadModule headers_module modules\/mod_headers.so/' /usr/local/apache2/conf/httpd.conf && \
    sed -i 's/#LoadModule log_config_module modules\/mod_log_config.so/LoadModule log_config_module modules\/mod_log_config.so/' /usr/local/apache2/conf/httpd.conf && \
    sed -i 's/#LoadModule status_module modules\/mod_status.so/LoadModule status_module modules\/mod_status.so/' /usr/local/apache2/conf/httpd.conf && \
    sed -i 's/#LoadModule unixd_module modules\/mod_unixd.so/LoadModule unixd_module modules\/mod_unixd.so/' /usr/local/apache2/conf/httpd.conf

# Copy custom configuration
COPY apache.conf /usr/local/apache2/conf/httpd.conf

EXPOSE 80 443

CMD ["httpd-foreground"] 