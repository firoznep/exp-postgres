require("dotenv").config();
const express = require("express");
const session = require("express-session");
const { v4: uuidv4 } = require("uuid");
const connectPgSimple = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");

const app = express();
const PORT = process.env.PORT || 3334;
const pool = new Pool({
  host: process.env.PG_HOST,
  user: process.env.PG_USER,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});

///// USE APP
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || uuidv4(),
    resave: false,
    saveUninitialized: false,
    name: "test_sid",
    cookie: { maxAge: 24 * 60 * 60 * 1000 },
    // cookie: { maxAge: 30 * 1000 },
    store: new connectPgSimple({
      pool: pool,
      tableName: "pgsimple",
      createTableIfMissing: true,
    }),
  })
);
app.use(passport.initialize());
app.use(passport.session());

///////////SERIALYZE & DESERIALYZE USER PASSPORT
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  // Here we retrieve the full user data using the stored ID
  pool.query("SELECT * FROM appusers WHERE id = $1", [id], (err, result) => {
    if (err) {
      return done(err);
    }
    done(null, result.rows[0]); // Store user data in req.user
  });
});

// passport.deserializeUser((user, done) => {
//   pool.query(
//     "select * from appusers where username = $1",
//     [user],
//     (err, user) => {
//       done(err, user);
//     }
//   );
// });

////////PASSPORT USE

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const result = await pool.query(
        "SELECT * FROM appusers WHERE username = $1",
        [username]
      );

      if (result.rows.length === 0) {
        return done(null, false, { message: "Incorrect Username!" });
      }

      const user = result.rows[0];

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return done(null, false, { message: "Incorrect password!" });
      }

      return done(null, user);
    } catch (error) {}
  })
);

/////////////// HELPER FUNCTIONS
const isLoggedIn = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  return res.redirect("/login");
};

///////// SET APP
app.set("view engine", "ejs");

////// GET ROUTER
app.get("/", (req, res) => {
  return res.redirect("/login");
});

app.get("/login", (req, res) => {
  const isAuth = req.isAuthenticated();
  if (isAuth) {
    return res.redirect("/dashboard");
  }
  return res.render("login");
});

app.get("/dashboard", isLoggedIn, async (req, res) => {
  let role = await req.user.role;
  // let role = (await req.user.role) === "admin" ? "admin" : null;
  return res.render("dashboard", {
    user: req.user,
    role,
  });
});

app.get("/createuser", isLoggedIn, async (req, res) => {
  let role = await req.user.role;
  console.log("from createuser: ", role);

  return res.render("createuser", {
    role,
    successMessage: null,
    errorMessage: null,
  });
});

app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    req.session.destroy();
    return res.redirect("/login");
  });
});

/////////// POST ROUTER
app.post(
  "/login",
  passport.authenticate("local", {
    failureRedirect: "/login",
    successRedirect: "/dashboard",
  })
);

app.post("/createuser", isLoggedIn, async (req, res) => {
  const { username, password, role } = req.body;

  try {
    if (req.user.role === "admin") {
      const hashedPass = await bcrypt.hash(password, 10);

      const user = await pool.query(
        "INSERT INTO appusers (username, password, role) VALUES ($1, $2, $3)",
        [username, hashedPass, role]
      );

      let successMessage = `User Created Successfully! User: ${username}`;
      console.log("Success Message:", successMessage); // Add this inside the `res.render`

      res.render("createuser", {
        successMessage,
        role: req.user.role,
      });
    }
  } catch (error) {
    console.log("Error from post createuser: ", error);
    return res
      .status(500)
      .render("createuser", { errorMessage: "Error Creating User" });
  }
});

app.listen(PORT, () => console.log(`App is running... on port: ${PORT}`));
