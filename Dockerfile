FROM golang:1.12.7-alpine3.9

RUN apk update && \
    apk add gcc musl-dev
