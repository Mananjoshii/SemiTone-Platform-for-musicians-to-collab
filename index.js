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
        secret: process.env.SECRET || "your_secret_key",
        resave: false,
        saveUninitialized: false,
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
        db.query('SELECT * FROM users WHERE id = $1', [req.user.id], (err, results) => {
            if (err) {
                console.error('Error fetching user:', err);
                return res.status(500).send('Internal Server Error');
            }
            if (results.rows.length > 0) {
                req.user = results.rows[0];
            } else {
                req.user = null;
            }
            next();
        });
    } else {
        req.user = null;
        next();
    }
});

// Multer Storage Configuration
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

// Passport Configuration
passport.use(
    "local",
    new Strategy(async (username, password, done) => {
        try {
            const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
            if (result.rows.length > 0) {
                const user = result.rows[0];
                bcrypt.compare(password, user.password, (err, isValid) => {
                    if (err) {
                        return done(err);
                    }
                    return isValid ? done(null, user) : done(null, false);
                });
            } else {
                return done(null, false);
            }
        } catch (err) {
            console.error("Error during login verification:", err);
            return done(err);
        }
    })
);

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    db.query("SELECT * FROM users WHERE id = $1", [id], (err, result) => {
        if (err) {
            return done(err);
        }
        done(null, result.rows[0]);
    });
});

// Routes
app.get("/", (req, res) => {
    res.render("home");
});
app.get('/artists', (req, res) => {
    // Assuming you have a database function or query to fetch artists
    db.query('SELECT * FROM artists', (err, result) => {
        if (err) {
            console.error('Error fetching artists:', err);
            return res.status(500).send('Internal Server Error');
        }

        // Pass the data to the view
        res.render('artists', { artists: result.rows });
    });
});
app.get('/bands', (req, res) => {
    // Assuming you have a database function or query to fetch bands
    db.query('SELECT * FROM bands', (err, result) => {
        if (err) {
            console.error('Error fetching bands:', err);
            return res.status(500).send('Internal Server Error');
        }

        // Pass the data to the view
        res.render('bands', { bands: result.rows });
    });
});





app.get("/events", (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect("/login");
    }
    console.log("User isAuthorized:", req.user?.isAuthorized); // Debugging line
    db.query("SELECT * FROM events ORDER BY id DESC", (err, result) => {
        if (err) {
            console.error("Error fetching events:", err);
            return res.status(500).send("Internal Server Error");
        }
        res.render("events.ejs", { events: result.rows, user: req.user });
    });
});


app.get("/add-event", (req, res) => {
    if (!req.user || !req.user.isAuthorized) {
        return res.status(403).send("Access denied.");
    }
    res.render("add-event", { user: req.user });
});

app.post("/add-event", upload.single("image"), (req, res) => {
    if (!req.user || !req.user.isAuthorized) {
        return res.status(403).send("Access denied.");
    }

    const { title, description } = req.body;
    const image_url = `/uploads/images/${req.file.filename}`;

    db.query(
        "INSERT INTO events (title, description, image_url, user_id) VALUES ($1, $2, $3, $4)",
        [title, description, image_url, req.user.id],
        (err) => {
            if (err) {
                console.error("Error inserting event:", err);
                return res.status(500).send("Internal Server Error");
            }
            res.redirect("/events");
        }
    );
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.post(
    "/login",
    passport.authenticate("local", {
        failureRedirect: "/login",
        failureFlash: true,
    }),
    (req, res) => {
        res.redirect("/events");
    }
);

app.get("/register", (req, res) => {
    res.render("register");
});

app.post("/register", upload.fields([
    { name: "profile_picture", maxCount: 1 },
    { name: "video", maxCount: 1 },
    { name: "audio", maxCount: 1 },
]), async (req, res) => {
    const { username: email, password, name, role, description, instrument } = req.body;
    const profile_picture = req.files?.profile_picture?.[0]?.filename || null;
    const video = req.files?.video?.[0]?.filename || null;
    const audio = req.files?.audio?.[0]?.filename || null;

    try {
        const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

        if (checkResult.rows.length > 0) {
            res.redirect("/login");
        } else {
            const hashedPassword = await bcrypt.hash(password, saltRounds);
            const result = await db.query(
                "INSERT INTO users (email, password, name, role, description, profile_picture, video, audio, instrument) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *",
                [email, hashedPassword, name, role, description, profile_picture, video, audio, instrument]
            );

            const user = result.rows[0];
            req.login(user, (err) => {
                if (err) {
                    console.error("Error logging in user:", err);
                    return res.status(500).send("Internal Server Error");
                }
                res.redirect("/profile");
            });
        }
    } catch (err) {
        console.error("Error registering user:", err);
        res.status(500).send("Internal Server Error");
    }
});

app.get("/profile", (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect("/login");
    }

    const userId = req.user.id;

    db.query("SELECT * FROM users WHERE id = $1", [userId], (err, result) => {
        if (err) {
            console.error("Error fetching user:", err);
            return res.status(500).send("Internal Server Error");
        }
        const user = result.rows[0];
        res.render("profile", { user });
    });
});

app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error("Error logging out:", err);
            return res.status(500).send("Internal Server Error");
        }
        res.redirect("/");
    });
});

// Start the Server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
