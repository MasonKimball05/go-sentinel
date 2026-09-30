# Container for cmd/checkup, the public site security checkup (deployed to Cloud Run).
# The sentinel CLI itself doesn't need a container.

FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
# Static binary: no libc needed in the runtime image.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /checkup ./cmd/checkup

# Distroless: no shell or package manager, runs as a non-root user.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /checkup /checkup
USER nonroot:nonroot
ENTRYPOINT ["/checkup"]
