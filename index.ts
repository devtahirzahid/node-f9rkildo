const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const joi = require("joi");
import { Request, Response } from "express";

const port = 3000;

const app = express();

app.use(express.json());

const allowedOrigins = ["http://localhost:4200"];

app.use(
  cors({
    origin: function (
      origin: string | undefined,
      callback: (err: Error | null, allow?: boolean) => void
    ) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      } else {
        const msg = "The CORS policy does not allow access from this origin.";
        return callback(new Error(msg), false);
      }
    },
    credentials: true,
  })
);

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

app.get("/", (req: Request, res: Response) => {
  return res.status(200).json({ success: "Backend is running 23" });
});

// Interfaces
interface UserDto {
  username: string;
  email: string;
  type: "user" | "admin";
  password: string;
}

interface UserEntry {
  email: string;
  type: "user" | "admin";
  salt: string;
  passwordhash: string;
}

const MEMORY_DB: Record<string, UserEntry> = {};

// Helper functions
function getUserByUsername(name: string): UserEntry | undefined {
  console.log("Memory DB:", MEMORY_DB);
  return MEMORY_DB[name];
}

function getUserByEmail(email: string): UserEntry | undefined {
  return Object.values(MEMORY_DB).find(
    (entry: UserEntry) => entry.email === email
  );
}

// Joi validation schema
const userSchema = joi.object({
  username: joi.string().min(3).max(24).required(),
  email: joi.string().email().required(),
  type: joi.string().valid("user", "admin").required(),
  password: joi
    .string()
    .min(5)
    .max(24)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*])/)
    .required(),
});

// Register route
app.post("/register", async (req: Request, res: Response) => {
  console.log("Received a register request with body:", req.body);

  const { error, value } = userSchema.validate(req.body);

  if (error) {
    console.log("Validation error:", error.details[0].message);
    return res.status(400).json({ error: error.details[0].message });
  }

  const { username, email, type, password }: UserDto = value;

  if (getUserByUsername(username)) {
    console.log("Username already exists:", username);
    return res.status(409).json({ error: "Username already exists" });
  }

  if (getUserByEmail(email)) {
    console.log("Email already exists:", email);
    return res.status(409).json({ error: "Email already exists" });
  }

  const salt = bcrypt.genSaltSync(10);
  const passwordhash = bcrypt.hashSync(password, salt);

  MEMORY_DB[username] = { email, type, salt, passwordhash };

  console.log("User registered successfully:", username);
  return res.status(201).json({ message: "User registered successfully" });
});

// Login route
app.post("/login", (req: Request, res: Response) => {
  const { username, password } = req.body;

  const user = getUserByUsername(username);

  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const isMatch = bcrypt.compareSync(password, user.passwordhash);

  if (!isMatch) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  return res.status(200).json({ message: "Login successful" });
});
