// Route for login
app.post(
    "/login",
    passport.authenticate("local", { failureRedirect: "/login" }),
    (req, res) => {
        // Redirect to profile based on role
        const userRole = req.user.role;
        if (userRole === "musician" || userRole === "band_member" || userRole === "event") {
            res.redirect(`/profile/${req.user.id}`);
        } else {
            res.status(400).send("Invalid user role");
        }
    }
);

// Route for registration
app.post(
    "/register",
    async (req, res) => {
        const { name, email, password, role, description } = req.body;

        if (!name || !email || !password || !role) {
            return res.status(400).send("All fields are required.");
        }

        try {
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            const result = await db.query(
                `INSERT INTO users (name, email, password, role, description) VALUES ($1, $2, $3, $4, $5) RETURNING *`,
                [name, email, hashedPassword, role, description]
            );

            const user = result.rows[0];

            req.login(user, (err) => {
                if (err) {
                    console.error("Login error:", err);
                    return res.status(500).send("Error logging in user");
                }

                // Redirect to profile based on role
                if (role === "musician" || role === "band_member" || role === "event") {
                    res.redirect(`/profile/${user.id}`);
                } else {
                    res.status(400).send("Invalid user role");
                }
            });
        } catch (err) {
            console.error("Error registering user:", err);
            res.status(500).send("Internal Server Error");
        }
    }
);

// Route to render profile based on role
app.get("/profile/:id", async (req, res) => {
    const userId = req.params.id;

    try {
        const result = await db.query("SELECT * FROM users WHERE id = $1", [userId]);
        if (result.rows.length === 0) {
            return res.status(404).send("User not found");
        }

        const user = result.rows[0];

        if (user.role === "musician") {
            res.render("profile_musician", { user });
        } else if (user.role === "band_member") {
            // Fetch band-specific data for band_member
            const bandData = await db.query("SELECT * FROM bands WHERE id = $1", [user.band_id]);
            res.render("profile_band", { user, band: bandData.rows[0] });
        } else if (user.role === "event") {
            res.render("profile_event", { user });
        } else {
            res.status(400).send("Invalid role");
        }
    } catch (err) {
        console.error("Error fetching profile:", err);
        res.status(500).send("Internal Server Error");
    }
});
