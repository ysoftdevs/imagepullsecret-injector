FROM golang:1.19.0 AS builder

WORKDIR /go/src/github.com/ysoftdevs/imagepullsecret-injector
COPY . .
RUN make vendor build

FROM alpine:3.16.2 as base
COPY --from=builder /go/src/github.com/ysoftdevs/imagepullsecret-injector/build/_output/bin/imagepullsecret-injector /usr/local/bin/imagepullsecret-injector

RUN addgroup -S imagepullsecret-injector-group && adduser -S imagepullsecret-injector-user -G imagepullsecret-injector-group
USER imagepullsecret-injector-user

ENTRYPOINT ["imagepullsecret-injector"]
