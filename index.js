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
import nodemailer from "nodemailer";

dotenv.config();

const app = express();
const port = 3000;
const saltRounds = 10;

// File path helpers
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

// Database Connection
const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
});
db.connect();

const transporter = nodemailer.createTransport({
    service: "gmail", // You can use Gmail or other email services
    auth: {
        user: "joshimanan074@gmail.com", // Replace with your email
        pass: process.env.MAIL_PASS // Use your Gmail app password
    }
});

// POST route to handle contact form submission
app.post("/send-email", (req, res) => {
    const { name, email, message } = req.body;

    // Validate input (optional)
    if (!name || !email || !message) {
        return res.status(400).send("All fields are required.");
    }

    const mailOptions = {
        from: email,
        to: "joshimanan074@gmail.com",
        subject: `Contact Form Submission from ${name}`,
        text: `You received a new message from your contact form:\n\nName: ${name}\nEmail: ${email}\nMessage:\n${message}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error("Error sending email:", error);
            return res.status(500).send("Failed to send email.");
        }
        console.log("Email sent:", info.response);
        res.send("Email sent successfully!");
    });
});

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


// app.get('/band/:bandId', async (req, res) => {
//     const { bandId } = req.params;

//     try {
//         // Fetch band details
//         const bandQuery = `
//         SELECT id, name, email, description, genre, profile_picture
//         FROM users
//         WHERE role = 'band_member' AND id = $1
//       `;
//         const bandResult = await db.query(bandQuery, [bandId]);

//         if (bandResult.rowCount === 0) {
//             return res.status(404).send("Band not found");
//         }

//         const band = bandResult.rows[0];

//         // Fetch band members
//         const membersQuery = `
//         SELECT id, name, instrument, profile_picture
//         FROM users
//         WHERE band_id = $1 AND role = 'musician'
//       `;
//         const membersResult = await db.query(membersQuery, [bandId]);

//         const members = membersResult.rows;

//         // Fetch band posts
//         const postsQuery = `
//         SELECT id, title, description, type, file
//         FROM band_posts
//         WHERE user_id = $1
//       `;
//         const postsResult = await db.query(postsQuery, [bandId]);

//         const posts = postsResult.rows;

//         // Render the EJS template
//         res.render('band_profile', {
//             band,
//             members,
//             posts,
//         });
//     } catch (error) {
//         console.error('Error fetching band data:', error.message);
//         res.status(500).send("Internal server error");
//     }
// });


app.get("/search", async (req, res) => {
    const { query } = req.query;
    try {
        if (!query) {
            return res.status(400).send("Search query is required.");
        }

        const sqlQuery = `
        SELECT id, name, profile_picture, description 
        FROM users 
        WHERE (role = 'musician' OR role = 'band_member') AND name ILIKE $1;
        
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

app.get("/artists", (req, res) => {
    db.query("SELECT * FROM users WHERE role='musician'", (err, result) => {
        if (err) {
            console.error("Error fetching artists:", err);
            return res.status(500).send("Error fetching artists");
        }
        res.render("artists", { artists: result.rows });
    });
});

app.get("/profile/:id", async (req, res) => {
    const userId = req.params.id;

    try {
        const userResult = await db.query("SELECT * FROM users WHERE id = $1", [userId]);

        if (userResult.rows.length === 0) {
            console.error("User not found.");
            return res.status(404).send("User not found");
        }

        const user = userResult.rows[0];

        if (user.role === "musician") {
            // Render musician profile and pass musicianId and userId
            return res.render("profile_musician", { user, musicianId: user.id, userId });
        } else if (user.role === "band_member") {
            // Fetch the associated band details for the band_member
            const bandResult = await db.query("SELECT * FROM bands WHERE id = $1", [user.band_id]);

            if (bandResult.rows.length === 0) {
                console.error("Band not found.");
                return res.status(404).send("Band not found");
            }

            const band = bandResult.rows[0];

            // Fetch band members
            const membersResult = await db.query(
                "SELECT id, name, instrument, profile_picture FROM users WHERE band_id = $1 AND role = 'band_member'",
                [user.band_id]
            );

            // Fetch band posts
            // const postsResult = await db.query(
            //     "SELECT id, title, description, type, file FROM band_posts WHERE band_id = $1",
            //     [user.band_id]
            // );

            return res.render("profile_band", {
                user,
                band: { ...band, members: membersResult.rows, posts: postsResult.rows },
                musicianId: user.band_id,  // Passing band_id as musicianId for the band member
                userId
            });
        } else {
            return res.status(400).send("Invalid user role");
        }
    } catch (error) {
        console.error("Error fetching user profile:", error);
        res.status(500).send("Internal Server Error");
    }
});


app.get("/api/artist/:id", (req, res) => {
    const userId = req.params.id;

    db.query("SELECT * FROM users WHERE id = $1 AND role = 'musician'", [userId], (err, result) => {
        if (err) {
            console.error("Error fetching artist details:", err);
            return res.status(500).json({ error: "Internal Server Error" });
        }

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
app.get("/about", (req, res) => {
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

app.post(
    "/login",
    passport.authenticate("local", { failureRedirect: "/login" }),
    (req, res) => {
        // Redirect based on user role
        if (req.user.role === "band_member") {
            res.redirect(`/band/${req.user.id}`); // Redirect to Band Profile
        } else if (req.user.role === "musician") {
            res.redirect(`/profile/${req.user.id}`); // Redirect to Musician Profile
        } else {
            res.redirect("/"); // Default fallback
        }
    }
);


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
                return res.redirect("/login");
            }

            // Hash the password
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            // Insert the user into the database
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

            // Log the user in and redirect based on the role
            req.login(user, (err) => {
                if (err) {
                    console.error("Error logging in user:", err);
                    return res.status(500).send("Internal Server Error");
                } else {
                    if (role === "musician") {
                        res.redirect(`/profile/${user.id}`);
                    } else if (role === "band_member") {
                        res.redirect(`/profile/${user.id}`); // Redirect to band profile
                    } else {
                        res.redirect("/"); // Default fallback
                    }
                }
            });
        } catch (err) {
            console.error("Error registering user:", err);
            res.status(500).send("Internal Server Error");
        }
    }
);


app.get('/band/:id', async (req, res) => {
    const bandId = req.params.id;

    try {
        // Fetch band details
        const bandQuery = `SELECT * FROM bands WHERE id = $1`;
        const bandResult = await db.query(bandQuery, [bandId]);

        if (bandResult.rows.length === 0) {
            return res.status(404).send('Band not found');
        }

        const band = bandResult.rows[0];

        // Fetch band members
        const membersQuery = `
            SELECT id, name, instrument, profile_picture
            FROM users
            WHERE band_id = $1 AND role = 'band_member'
        `;
        const membersResult = await db.query(membersQuery, [bandId]);
        res.render('band_profile', {
            band,
            members: membersResult.rows,
        });
    } catch (err) {
        console.error('Error fetching band data:', err);
        res.status(500).send('Internal server error');
    }
});


// Upload Band Profile Picture
app.post('/band/:id/upload', upload.single('profile_picture'), async (req, res) => {
    const bandId = req.params.id;
    const profilePicture = req.file.filename;

    try {
        const updateQuery = `
            UPDATE bands
            SET profile_picture = $1
            WHERE id = $2
        `;
        await db.query(updateQuery, [profilePicture, bandId]);
        res.redirect(`/band/${bandId}`);
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
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

// Fetch average rating for a musician
app.get('/ratings/:musician_id', async (req, res) => {
    const { musician_id } = req.params;

    try {
        const result = await db.query(
            `SELECT AVG(rating)::NUMERIC(3, 2) AS average_rating, COUNT(*) AS total_reviews 
             FROM ratings WHERE musician_id = $1`,
            [musician_id]
        );
        res.status(200).send(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Fetch all reviews for a musician
app.get("/ratings/:musicianId/reviews", async (req, res) => {
    const musicianId = req.params.musicianId;

    try {
        const reviewsResult = await db.query("SELECT r.rating, r.comment, u.name AS username FROM ratings r JOIN users u ON r.user_id = u.id WHERE r.musician_id = $1", [musicianId]);

        if (reviewsResult.rows.length === 0) {
            return res.json([]); // No reviews found
        }

        res.json(reviewsResult.rows);
    } catch (error) {
        console.error("Error fetching reviews:", error);
        res.status(500).send("Internal Server Error");
    }
});


    app.post('/ratings', async (req, res) => {
        const { musicianId, user_id, rating, comment } = req.body;

        if (!musicianId || !user_id) {
            return res.status(400).json({ error: 'Musician ID and User ID are required' });
        }

        try {
            const query = `
        INSERT INTO ratings (musician_id, user_id, rating, comment)
        VALUES ($1, $2, $3, $4)
      `;
            await db.query(query, [musician_id, user_id, rating, comment]);
            res.status(200).json({ message: 'Rating submitted successfully!' });
        } catch (error) {
            console.error('Error submitting rating:', error);
            res.status(500).json({ error: 'Error submitting rating' });
        }
    });

    app.post('/send-friend-request', async (req, res) => {
        try {
            const { senderId, receiverId } = req.body;

            // Check for existing friendship
            const existingFriendship = await db.query(
                'SELECT * FROM friendships WHERE (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1)',
                [senderId, receiverId]
            );

            if (existingFriendship.rows.length > 0) {
                return res.status(400).json({ error: 'Friendship already exists' });
            }

            await db.query(
                'INSERT INTO friendships (user_id, friend_id) VALUES ($1, $2)',
                [senderId, receiverId]
            );

            res.status(201).json({ message: 'Friend request sent' });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Failed to send friend request' });
        }
    });
    // Receive friend requests
    app.get('/friend-requests', async (req, res) => {
        try {
            const { userId } = req.query;

            const result = await db.query(
                'SELECT u.username, u.id FROM friendships f JOIN users u ON f.friend_id = u.id WHERE f.user_id = $1 AND f.status = $2',
                [userId, 'pending']
            );

            res.json(result.rows);
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Failed to fetch friend requests' });
        }
    });

    // Respond to friend request (accept/reject)
    app.put('/respond-to-request', async (req, res) => {
        try {
            const { requestId, status } = req.body;

            await db.query(
                'UPDATE friendships SET status = $1 WHERE id = $2',
                [status, requestId]
            );

            res.status(200).json({ message: `Friend request ${status}` });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Failed to respond to request' });
        }
    });

    // Get total number of friends
    app.get('/total-friends', async (req, res) => {
        try {
            const { userId } = req.query;

            const result = await db.query(
                `
          SELECT COUNT(*) FROM friendships 
          WHERE (user_id = $1 AND status = 'accepted') 
          OR (friend_id = $1 AND status = 'accepted')
        `,
                [userId]
            );

            res.json({ totalFriends: result.rows[0].count });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Failed to get total friends' });
        }
    });

    app.get("/register_band", isAuthenticated, (req, res) => {
        res.render("register_band", { user: req.user });
    });

    // Serve frontend EJS file (assuming a views directory)
    app.get('/send-friend-request', (req, res) => {
        res.render('connections.ejs'); // Replace with your actual EJS file name
    });

    app.get("/register_band", isAuthenticated, (req, res) => {
        res.render("register_band", { user: req.user });
    });

    // Handle the form submission for new member registration
    // Handle the form submission for new member registration
    app.post('/register-member', upload.single('profile_picture'), async (req, res) => {
        const { name, email, instrument } = req.body;
        const profile_picture = req.file ? req.file.filename : null;

        // Validate form data
        if (!name || !email || !instrument || !profile_picture) {
            return res.status(400).json({ message: 'All fields are required.' });
        }

        db.query(
            "INSERT INTO band_members (name, email, instrument, profile_picture) VALUES ($1, $2, $3, $4)",
            [name, email, instrument, profile_picture],
            (err) => {
                if (err) {
                    console.log(err.message);
                    return res.status(500).send("Error adding member");


                }

                // Redirect to the band profile page after successful insertion
                res.redirect('/bandProfile');  // Make sure to redirect to the correct route
            }
        );
    });

    app.get('/bandProfile', async (req, res) => {
        const query = 'SELECT * FROM band_members';
        try {
            const result = await db.query(query);
            res.render('bandProfile', { band: result.rows }); // Render the band_profile.ejs template
        } catch (error) {
            console.error(error);
            res.status(500).json({ message: 'Internal Server Error' });
        }
    });


    app.get('/api/band_members', async (req, res) => {
        const query = 'SELECT * FROM band_members';
        try {
            const result = await db.query(query);
            res.json(result.rows); // Send the list of band members as a JSON response
        } catch (error) {
            console.error(error);
            res.status(500).json({ message: 'Internal Server Error' });
        }
    });

    app.get('/band/:bandId', async (req, res) => {
        const { bandId } = req.params;

        try {
            // Fetch band details
            const bandQuery = `
            SELECT id, name, description, genre
            FROM users
            WHERE id = $1
        `;
            const bandResult = await db.query(bandQuery, [bandId]);

            if (bandResult.rowCount === 0) {
                return res.status(404).send("Band not found");
            }

            const band = bandResult.rows[0];

            // Fetch band members
            const membersQuery = `
        SELECT id, name, instrument, profile_picture
        FROM users
        WHERE band_id = $1 AND role = 'musician'
      `;
            const membersResult = await db.query(membersQuery, [bandId]);

            console.log(membersResult.rows)

            // Render the EJS template
            res.render('band_profile', { band, members: membersResult.rows });
        } catch (error) {
            console.error('Error fetching band data:', error.message);
            res.status(500).send("Internal server error");
        }
    });

    app.get("/bands", (req, res) => {
        db.query("SELECT * FROM bands", (err, result) => {
            if (err) return res.status(500).send("Error fetching bands");
            res.render("bands", { bands: result.rows });
        });
    });

    app.post("/add-post", upload.single("video"), async (req, res) => {
        const { title, description } = req.body;
        const video = req.file ? req.file.filename : null;
      
        if (!title || !description || !video) {
          return res.status(400).send("All fields are required.");
        }
      
        try {
          await db.query(
            "INSERT INTO posts (title, description, video) VALUES ($1, $2, $3)",
            [title, description, video]
          );
      
          // Redirect to posts page or success page
          res.redirect("/profile/:id"); // Make sure /posts is a valid route
        } catch (error) {
          console.error("Error saving post:", error);
          res.status(500).send("Internal Server Error");
        }
      });
      
      // Route to fetch and render posts
      app.get('/profile', async (req, res) => {
        try {
          const userId = req.user.id; // Assuming user is authenticated and `req.user` contains user info
          const query = `
            SELECT video, title, description 
            FROM posts
            WHERE user_id = $1
          `;
          const result = await db.query(query, [userId]);
      
          res.render('profile', { user: req.user, posts: result.rows }); // Render posts on profile page
        } catch (error) {
          console.error('Error fetching posts:', error.message);
          res.status(500).json({ message: 'Internal Server Error' });
        }
      });

      app.get("/add-post-form", (req, res) => {
        res.render("add_post_form"); // Make sure "add_post_form.ejs" is created in the views folder
      });
      

    // Start the Server
    app.listen(port, () => console.log(`Server running at http://localhost:${port}`));