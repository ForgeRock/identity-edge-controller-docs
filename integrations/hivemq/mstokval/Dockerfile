FROM openjdk:11

ADD resources/MicroserviceTokenValidation-1.0.1.zip /opt/
RUN unzip /opt/MicroserviceTokenValidation-1.0.1.zip -d /opt/\
    && rm -f /opt/MicroserviceTokenValidation-1.0.1.zip

ADD configuration/config.json /opt/token-validation/config/

CMD ["/opt/token-validation/bin/start.sh","/opt/token-validation"]
