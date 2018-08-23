ARG BUILD_FROM
FROM $BUILD_FROM

ENV LANG C.UTF-8

# Copy data for add-on
COPY run.sh IP150-MQTTv2.py ParadoxMap.py config.ini requirements.txt /

RUN apk add --no-cache python &&\
    python -m ensurepip &&\
    pip3 install -r requirements.txt

RUN chmod a+x /run.sh

CMD [ "/run.sh" ]