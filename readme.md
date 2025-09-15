# jwt-auth

JWT authentication and password hashing utilities.

## Install

```sh
go get github.com/DrWeltschmerz/jwt-auth@v1.2.0
```

## Features

- Bcrypt password hasher (`authjwt.BcryptHasher`)
- JWT token utilities

## Usage

```go
import "github.com/DrWeltschmerz/jwt-auth/pkg/authjwt"

hasher := authjwt.NewBcryptHasher()
hash, err := hasher.Hash("password")
ok := hasher.Verify(hash, "password")
```

Use the hasher with [users-core](https://github.com/DrWeltschmerz/users-core) service for secure password storage.

See end-to-end usage in [users-tests](https://github.com/DrWeltschmerz/users-tests).

---