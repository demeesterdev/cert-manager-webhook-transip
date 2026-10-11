FROM --platform=$BUILDPLATFORM golang:1.24.3-alpine3.21 AS build_deps

RUN apk add --no-cache git

WORKDIR /workspace

COPY go.mod .
COPY go.sum .

RUN go mod download

FROM build_deps AS build

ARG TARGETOS
ARG TARGETARCH

COPY . .

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o webhook -ldflags '-w -extldflags "-static"' .

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

COPY --from=build /workspace/webhook /usr/local/bin/webhook

ENTRYPOINT ["webhook"]
