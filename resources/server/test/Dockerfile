FROM golang:1.8-stretch

WORKDIR $GOPATH/src/github.com/betalotest/auth

ADD main.go .
ADD server/ server/
ADD templates/ templates/
ADD resources/server/prod/conf.yml resources/server/prod/conf.yml

RUN go get -d -v ./...

ENTRYPOINT ["go", "test", "-v", "-race", "./..."]
