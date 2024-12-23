import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import dotenv from "dotenv";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const app = express();
const port = 3000;
const saltRounds = 10;

// File path helpers
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Database Connection
const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
});
db.connect();

// Session Configuration
app.use(
    session({
        secret: "your_secret_key",
        resave: false,
        saveUninitialized: true,
        cookie: { maxAge: 24 * 60 * 60 * 1000 }, // 1 day
    })
);

// Passport Initialization
app.use(passport.initialize());
app.use(passport.session());

// Middleware to log session and user
app.use((req, res, next) => {
    console.log("Session:", req.session);
    console.log("User:", req.user);
    next();
});

// Middleware to make user available in templates
app.use((req, res, next) => {
    if (req.isAuthenticated()) {
        db.query("SELECT * FROM users WHERE id = $1", [req.user.id], (err, results) => {
            if (err) {
                console.error("Error fetching user:", err);
                return res.status(500).send("Internal Server Error");
            }
            req.user = results.rows[0] || null;
            next();
        });
    } else {
        res.locals.user = req.session.user || null;
        next();
    }
});

// File Upload Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, "uploads/images/");
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
        cb(null, file.fieldname + "-" + uniqueSuffix + "-" + file.originalname);
    },
});
const upload = multer({ storage });


// App Configuration
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

// Authentication Middleware
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated() && req.user) {
        return next();
    }
    res.redirect("/login");
}

// Passport Configuration
passport.use(
    new Strategy(async (username, password, done) => {
        try {
            const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
            if (result.rows.length > 0) {
                const user = result.rows[0];
                bcrypt.compare(password, user.password, (err, isValid) => {
                    if (err) return done(err);
                    return isValid ? done(null, user) : done(null, false);
                });
            } else {
                return done(null, false);
            }
        } catch (err) {
            console.error("Login error:", err);
            return done(err);
        }
    })
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) =>
    db.query("SELECT * FROM users WHERE id = $1", [id], (err, result) => {
        if (err) return done(err);
        done(null, result.rows[0]);
    })
);

// Routes
app.get("/", (req, res) => {
    res.render("home", { user: req.session.user || null });
});


app.get("/artists", (req, res) => {
    db.query("SELECT * FROM artists", (err, result) => {
        if (err) return res.status(500).send("Error fetching artists");
        res.render("artists", { artists: result.rows });
    });
});

app.get("/bands", (req, res) => {
    db.query("SELECT * FROM bands", (err, result) => {
        if (err) return res.status(500).send("Error fetching bands");
        res.render("bands", { bands: result.rows });
    });
});

app.get("/events", isAuthenticated, (req, res) => {
    db.query("SELECT * FROM events ORDER BY id DESC", (err, result) => {
        if (err) return res.status(500).send("Error fetching events");
        res.render("events", { events: result.rows, user: req.user });
    });
});

app.get("/add-event", isAuthenticated, (req, res) => {
    res.render("add-event", { user: req.user });
});

app.post("/add-event", isAuthenticated, upload.single("image"), (req, res) => {
    const { title, description, date } = req.body;
    const image = req.file ? req.file.filename : null;
    db.query(
        "INSERT INTO events (title, description, date, image) VALUES ($1, $2, $3, $4)",
        [title, description, date, image],
        (err) => {
            if (err) return res.status(500).send("Error adding event");
            res.redirect("/events");
        }
    );
});

app.get("/login", (req, res) => res.render("login"));

app.post("/login", passport.authenticate("local", { successRedirect: "/", failureRedirect: "/login" }));

app.get("/register", (req, res) => res.render("register"));

app.post(
    "/register",
    upload.fields([
        { name: "profile_picture", maxCount: 1 },
        { name: "video", maxCount: 1 },
        { name: "audio", maxCount: 1 },
    ]),
    async (req, res) => {
        const { email, password, name, role, description, instrument } = req.body;
        const profile_picture = req.files?.profile_picture?.[0]?.filename || null;
        const video = req.files?.video?.[0]?.filename || null;
        const audio = req.files?.audio?.[0]?.filename || null;

        try {
            const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
            if (result.rows.length > 0) return res.redirect("/login");

            const hashedPassword = await bcrypt.hash(password, saltRounds);
            await db.query(
                "INSERT INTO users (email, password, name, role, description, profile_picture, video, audio, instrument) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                [email, hashedPassword, name, role, description, profile_picture, video, audio, instrument]
            );
            res.redirect("/profile");
        } catch (err) {
            console.error("Error registering user:", err);
            res.status(500).send("Internal Server Error");
        }
    }
);

app.get("/profile", isAuthenticated, (req, res) => {
    db.query("SELECT * FROM users WHERE id = $1", [req.user.id], (err, result) => {
        if (err) return res.status(500).send("Error fetching profile");
        res.render("profile", { user: result.rows[0] });
    });
});

app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) return res.status(500).send("Error logging out");
        req.session.destroy((sessionErr) => {
            if (sessionErr) console.error(sessionErr);
            res.redirect("/login");
        });
    });
});

// Start the Server
app.listen(port, () => console.log(`Server running at http://localhost:${port}`));
