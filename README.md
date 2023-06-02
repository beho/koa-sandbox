# Koa sandbox

## Install & run

Install node.js deps with `npm ci` and run with `node app.js`.

## Authentication

User authenticates on `/login` with `{username: "", password: ""}`. It reurns `{ token: "" }` on success. Token is to be passed in `Authorization` request header with bearer scheme, i.e. `Authorization: Bearer <token>`.

