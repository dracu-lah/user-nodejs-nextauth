const express = require("express");
const mysql = require("mysql");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");

const app = express();
const port = process.env.PORT || 8000;

// Create MySQL connection pool
const pool = mysql.createPool({
  connectionLimit: 10,
  host: "localhost",
  user: "root",
  password: "",
  database: "auth_demo",
});

// Middleware
app.use(bodyParser.json());

// Routes
app.post("/auth/register", async (req, res) => {
  try {
    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);

    // Insert new user into database
    const query = `INSERT INTO users (username, password) VALUES (?, ?)`;
    const values = [req.body.username, hashedPassword];

    pool.query(query, values, (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).send("Internal server error");
      } else {
        res.status(201).send("User created");
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal server error");
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    // Find user by username
    const query = `SELECT * FROM users WHERE username = ?`;
    const values = [req.body.username];

    pool.query(query, values, async (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).send("Internal server error");
      } else {
        // Check if user exists
        if (results.length === 0) {
          return res.status(401).send("Invalid username or password");
        }

        // Check password
        const passwordMatch = await bcrypt.compare(
          req.body.password,
          results[0].password
        );

        if (!passwordMatch) {
          return res.status(401).send("Invalid username or password");
        }

        // Send username back to client
        const name = results[0].username;
        res.status(200).json({ message: "Login successful", name });
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal server error");
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
