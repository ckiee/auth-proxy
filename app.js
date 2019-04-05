const express = require("express");
const app = express();
const port = process.env.PORT || 3000;
require("log-node")();
const log = require("log"); 
const bcrypt = require("bcrypt");
const LocalStrategy = require("passport-local");
const proxy = require("express-http-proxy");
const proxyURL = process.env.PROXY_URL;
const proxyName = process.env.PROXY_NAME;
const cookieSecret = process.env.COOKIE_SECRET;
if (!cookieSecret || !proxyURL || !proxyName || !process.env.AUTH_PAIRS) {
    log.error(
        "COOKIE_SECRET,PROXY_URL,PROXY_NAME,AUTH_PAIRS have to be set to a random string."
        );
        process.exit(1);
}
const authPairs = pairs2Obj(process.env.AUTH_PAIRS);
const session = require("express-session");
const passport = require("passport");
const RDBStore = require("session-rethinkdb")(session);
const dbOpts = {
    db: process.env.db || `authproxy`,
};
if (process.env.DB_ADDR) dbOpts.servers = [{ host: process.env.DB_ADDR.split(":")[0], port: parseInt(process.env.DB_ADDR.split(":")[1], 10) }]
const r = require(`rethinkdbdash`)(dbOpts); // Connect to RethinkDB
function pairs2Obj(str = "") {
    const obj = {};
    str.split("\n").map(a => a.split(":")).forEach(e => {
        obj[e[0]]=e[1];
    });
    return obj;
}

app.set("view engine", "ejs");
app.use(require("cookie-parser")());
app.use(require("body-parser").urlencoded({extended: true}));
const store = new RDBStore(r);
app.use(session({ store, secret: cookieSecret, resave: true, saveUninitialized: true, name: "authproxy_"+proxyName }));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(
    async (username, password, done) => {
        if (!authPairs[username]) return done(null, false);
        if (await bcrypt.compare(password, authPairs[username])) {
            done(null, {}); // empty obj, we have no real user
        } else done(null, false);
    }
));

passport.serializeUser(function (user, done) {
    done(null, user);
});

passport.deserializeUser(function (id, done) {
    done(null, id);
});

app.use(async (req, res, next) => {
    if (req.isAuthenticated()) {
        proxy(proxyURL)(req, res, next);
    } else next();
});

app.use(express.static("assets"));

app.post("/login",
    passport.authenticate("local", { failWithError: true }),
    function (req, res) {
        res.redirect("/");
    });

app.get("/", async (req, res) => {
    res.render("index", { proxyName });
});

app.listen(port, () => log(`Listening on port ${port}`));