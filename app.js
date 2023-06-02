'use strict';

const Koa = require('koa');
const Router = require('@koa/router');
const { koaBody } = require('koa-body');
const fs = require('fs');
const crypto = require('crypto');
const app = new Koa();
const router = new Router();

// FIX: no tests are written
// - auth
// - state management
// - endpoint access

// FIX: TLS termination on proxy or configure TLS for node

// FIX: missing healthcheck

// FIX: appropriate logging

// FIX: emit metrics


// Authentication/authorization

// Never store plaintext passwords. Use some appropriate hashing algorithm.
// See e.g.
// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
//
// To allow configurability config file/persistent storage would be more
// appropriate (depends on use case).
const users = {
    admin: { username: 'admin', role: 'admin', password: 'secret' },
    user: { username: 'user', role: 'user', password: 'secret' },
};

// TODO: refactor - wrap all auth/authorization into object or use some package
// change this implementation for storage methods
const userForCredentials = function(username, password) {
    const user = users[username];
    if(user?.password !== password) {
        return null;
    }

    return user;
};

const authenticate = function(username, token) {
    const user = users[username];
    return user?.token === token
        ? user
        : null;
};

// State management
const stateFilePath = './state.json';

// TODO refactor - wrap state management into object
const defaultState = {
    numberOfCalls: 0,
    lastMessage: null
};

// file is not locked when app is running so there is space for race conditions
// or tampering with state
// it could also be used to ensure that only single instance of app is runnning
const initState = function() {
    try
    {
        return JSON.parse(fs.readFileSync(stateFilePath));
    }
    catch
    {
        return Object.assign({}, defaultState);
    }
};

const updateState = function(message) {
    state.numberOfCalls += 1;
    state.lastMessage = message;

    // not sure if file is fsynced to file system
    fs.writeFileSync(stateFilePath, JSON.stringify(state));
};

// global state
const state  = initState();

// Authentication middleware
app.use(async (ctx, next) => {
    const auth = ctx.request.headers['authorization'];
    
    if(auth != null) {
        // Parsing definitely needs testing but this should
        // be compliant with https://datatracker.ietf.org/doc/html/rfc7617
        const [scheme, digest] = auth.split(/\s/);

        if(scheme != 'Bearer') {
            const [username, token]  = Buffer.from(digest, 'base64').toString('utf-8').split(':');
            ctx.user = authenticate(username, token);
        }
    }

    await next();    
});

router.post('/login', koaBody(), async (ctx, _next) => {
    const { username, password } = ctx.request.body;

    const user = userForCredentials(username, password);
    if (user == null) {
        ctx.status = 401;

        console.warn('Failed login attempt');
        return;
    }

    // This is stateful auth. So it requires accessing user storage on each request.
    // Stateless auth might be more appropriate depending on context.
    // User can have only single token so authenticating
    // from multiple devices works but logging out of one causes unauthorized
    // access on the rest of devices. Again, this might or might not be a problem.
    if (user.token == null) {
        // not sure about appropriate token length
        user.token = crypto.randomBytes(8).toString('hex');
    }

    const digest = Buffer.from(user.username + ':' + user.token).toString('base64');
    
    ctx.body = {
        token: digest
    };
    ctx.status = 200;

    console.log('Authenticated user ' + username);
});

router.post('/logout', koaBody(), async (ctx, _next) => {
    if (!ctx.user) {
        // handling of unauthorized access should be extracted and reused
        // logging of unathorized acess is missing in all endpoints
        ctx.status = 403;
        return;
    }
    
    ctx.user.token = null;
    ctx.status = 200;

    console.log('User ' + ctx.user.username + 'logged out');
});

router.post('/message', koaBody(), async (ctx, _next) => {
    if (!ctx.user) {
        ctx.status = 403;
        return;
    }
    
    // Body should be validated using some kind of schema.
    
    updateState(ctx.request.body);

    ctx.status = 204;
});

router.get('/stats', async (ctx, _next) =>{
    if(!ctx.user || ctx.user.role !== 'admin') {
        ctx.status = 403;
        return;
    }

    ctx.body = state;
});

app.use(router.routes()).use(router.allowedMethods());

app.listen(3000);
