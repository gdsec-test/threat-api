FROM 764525110978.dkr.ecr.us-west-2.amazonaws.com/debian:11

# APP_FOLDER should contain already built golang application, see build.sh
# Below env variables should be provided via build args `docker build --build-arg APP_FOLDER=${APP_FOLDER}`

ARG APP_FOLDER
ENV APP_FOLDER=$APP_FOLDER
ARG APPLICATION_NAME
ENV APPLICATION_NAME=$APPLICATION_NAME

USER root
COPY ${APP_FOLDER} /${APP_FOLDER}

WORKDIR /${APP_FOLDER}

RUN chmod +x ${APPLICATION_NAME}

USER nobody

CMD ./${APPLICATION_NAME}
