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
        const destinationPath = file.fieldname === "video" ? "uploads/videos/"
            : file.fieldname === "audio" ? "uploads/audio/"
                : "uploads/images/";
        cb(null, destinationPath); // Set folder based on field name
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
        cb(null, file.fieldname + "-" + uniqueSuffix + "-" + file.originalname);
    },
});
const upload = multer({ storage });


// App Configuration
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
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
passport.deserializeUser(async (id, done) => {
    try {
        const result = await db.query('SELECT * FROM users WHERE id = $1', [id]);
        if (result.rows.length > 0) {
            done(null, result.rows[0]); // Pass the user object to the request
        } else {
            done(new Error('User not found'));
        }
    } catch (err) {
        done(err);
    }
});

// Routes
app.get("/", (req, res) => {
    // Ensure the user is logged in
    if (!req.user || !req.user.id) {
        return res.redirect("/login"); // Redirect to login if no user session
    }

    // Fetch user profile from database
    db.query("SELECT * FROM users WHERE id = $1", [req.user.id], (err, result) => {
        if (err) {
            console.error("Error fetching profile:", err);
            return res.status(500).send("Internal Server Error");
        }

        // Render the home view with user data
        const user = result.rows[0];
        res.render("home", { user });
    });
});

app.get("/profile", isAuthenticated, (req, res) => {
    db.query("SELECT * FROM users WHERE id = $1", [req.user.id], (err, result) => {
        if (err) return res.status(500).send("Error fetching profile");
        res.render("profile_musician", { user: result.rows[0] });
    });
});
app.get("/search", async (req, res) => {
    const { query } = req.query;
    try {
        if (!query) {
            return res.status(400).send("Search query is required.");
        }

        const sqlQuery = `
            SELECT id, name, profile_picture, description 
            FROM users 
            WHERE role = 'musician' AND name ILIKE $1
        `;

        const result = await db.query(sqlQuery, [`%${query}%`]);

        if (result.rows.length === 0) {
            return res.render("search-results", { profiles: [], message: "No musicians found matching your query." });
        }

        res.render("search-results", { profiles: result.rows, message: null });
    } catch (err) {
        console.error("Search route error:", err); // Log the error details
        res.status(500).send("Internal Server Error");
    }
});





app.get("/artists",(req, res) => {
    db.query("SELECT * FROM artists", (err, result) => {
        if (err) {
            console.error("Error fetching artists:", err);
            return res.status(500).send("Error fetching artists");
        }
        res.render("artists", { artists: result.rows });
    });
});


// // Route for artist profile
// app.get("/artist/:id", (req, res) => {
//     const artistId = req.params.id;

//     db.query("SELECT * FROM artists WHERE id = $1", [artistId], (err, result) => {
//         if (err) return res.status(500).send("Error fetching artist profile");

//         if (result.rows.length === 0) {
//             return res.status(404).send("Artist not found");
//         }

//         res.render("artist-profile", { artist: result.rows[0] });
//     });
// });

app.get("/profile/:id", (req, res) => {
    const artistId = req.params.id;

    db.query("SELECT * FROM artists WHERE id = $1", [artistId], (err, result) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).send("Internal Server Error");
        }

        if (result.rows.length === 0) {
            console.error("Artist not found in the database.");
            return res.status(404).send("Artist not found");
        }

        // Pass the artist data as `user` to match the template
        res.render("profile_musician", { user: result.rows[0] });
    });
});




app.get("/api/artist/:id", (req, res) => {
    const artistId = req.params.id;

    db.query("SELECT * FROM artists WHERE id = $1", [artistId], (err, result) => {
        if (err) return res.status(500).json({ error: "Error fetching artist details" });

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Artist not found" });
        }

        res.json(result.rows[0]);
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
app.get("/about",  (req, res) => {
    res.render("about");
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

        // Check for required fields
        if (!email || !password || !name || !role || !instrument) {
            return res.status(400).send("All fields are required.");
        }

        const profile_picture = req.files?.profile_picture?.[0]?.filename || null;
        const video = req.files?.video?.[0]?.filename || null;
        const audio = req.files?.audio?.[0]?.filename || null;

        try {
            // Check if the email already exists
            const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

            if (checkResult.rows.length > 0) {
                return res.redirect("/login");  // If email exists, redirect to login
            }

            // Hash the password using bcrypt
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            // Insert user into the database
            const result = await db.query(
                `INSERT INTO users 
                (email, password, name, role, description, profile_picture, video, audio, instrument) 
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) 
                RETURNING *`,
                [
                    email,
                    hashedPassword,
                    name,
                    role,
                    description,
                    profile_picture,
                    video,
                    audio,
                    instrument,
                ]
            );

            const user = result.rows[0];

            // Log the user in and redirect to profile
            req.login(user, (err) => {
                if (err) {
                    console.error("Error logging in user:", err);
                    return res.status(500).send("Internal Server Error");
                } else {
                    res.redirect("/profile_musician");
                }
            });
        } catch (err) {
            console.error("Error registering user:", err);
            res.status(500).send("Internal Server Error");
        }
    }
);



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
