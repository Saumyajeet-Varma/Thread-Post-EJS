const express = require("express");
const app = express();

require("dotenv").config();

const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const path = require("path");

const userModel = require("./models/user");
const postModel = require("./models/post");
const upload = require("./config/multerConfig");

app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(cookieParser());

// Middleware for protected routes
const isLoggedIn = (req, res, next) => {
    const token = req.cookies.token;

    if (!token) {
        return res.redirect("/login");
    }

    try {
        const data = jwt.verify(token, process.env.JWT_SECRET);
        req.user = data;
        next();
    } catch (error) {
        res.clearCookie("token").redirect("/login");
    }
};

// Routes (GET, POST)
app.get("/", (req, res) => {
    res.render("index");
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/logout", (req, res) => {
    res.clearCookie("token").redirect("/login");
});

app.get("/profile", isLoggedIn, async (req, res) => {
    try {
        const user = await userModel.findOne({ email: req.user.email }).populate("posts");
        res.render("profile", { user });
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    }
});

app.get("/profile/upload", isLoggedIn, (req, res) => {
    res.render("profileUpload");
});

app.get("/profile/image/:userImage", isLoggedIn, async (req, res) => {

    const user = await userModel.findOne({ email: req.user.email })

    res.render("profileImage", { user });
})

app.get("/createPost", (req, res) => {
    res.render("create");
});

app.get("/like/:postId", isLoggedIn, async (req, res) => {
    try {
        const post = await postModel.findById(req.params.postId).populate("user");
        if (post.likes.indexOf(req.user.userId) === -1) {
            post.likes.push(req.user.userId);
        } else {
            post.likes.splice(post.likes.indexOf(req.user.userId), 1);
        }
        await post.save();
        res.redirect("/profile");
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    }
});

app.get("/edit/:postId", isLoggedIn, async (req, res) => {
    try {
        const post = await postModel.findById(req.params.postId).populate("user");
        res.render("edit", { post });
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    }
});

app.post("/register", async (req, res) => {
    try {
        const { username, name, email, age, password } = req.body;

        const userExist = await userModel.findOne({ email });
        if (userExist) {
            return res.status(400).send("User already exists");
        }

        const hashedPassword = await bcrypt.hash(password, parseInt(process.env.HASH_ROUNDS || 10));
        const createdUser = await userModel.create({
            username,
            name,
            email,
            age,
            password: hashedPassword,
        });

        const token = jwt.sign(
            { email: createdUser.email, userId: createdUser._id },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRY }
        );

        res.status(201).cookie("token", token, { httpOnly: true }).redirect("/profile");
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    }
});

app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await userModel.findOne({ email });
        if (!user) {
            return res.status(404).send("User does not exist");
        }

        const isCorrectPassword = await bcrypt.compare(password, user.password);
        if (isCorrectPassword) {
            const token = jwt.sign(
                { email: user.email, userId: user._id },
                process.env.JWT_SECRET,
                { expiresIn: process.env.JWT_EXPIRY }
            );

            res.status(200).cookie("token", token, { httpOnly: true }).redirect("/profile");
        } else {
            res.status(401).send("Invalid credentials");
        }
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    }
});

app.post("/upload", isLoggedIn, upload.single("dp"), async (req, res) => {
    try {
        const user = await userModel.findOne({ email: req.user.email });
        user.dp = req.file.filename;
        await user.save();
        res.redirect("/profile");
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    }
});

app.post("/post", isLoggedIn, async (req, res) => {
    try {
        const user = await userModel.findOne({ email: req.user.email });
        const createdPost = await postModel.create({
            user: user._id,
            content: req.body.content,
        });

        user.posts.push(createdPost._id);
        await user.save();
        res.redirect("/profile");
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    }
});

app.post("/update/:postId", isLoggedIn, async (req, res) => {
    try {
        await postModel.findByIdAndUpdate(req.params.postId, { content: req.body.content });
        res.redirect("/profile");
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`\nServer running at http://localhost:${PORT}`);
});
