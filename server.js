const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();

// ==========================
// MIDDLEWARE
// ==========================
app.use(cors());
app.use(express.json());

// ==========================
// CONNECT DB
// ==========================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected ✅"))
  .catch(err => console.log("DB Error ❌", err));

// ==========================
// MODELS
// ==========================

// USER
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});
const User = mongoose.model("User", UserSchema);

// VAULT
const VaultSchema = new mongoose.Schema({
  userId: String,
  type: String,
  site: String,
  username: String,
  password: String,
  note: String,
  strength: String
});
const Vault = mongoose.model("Vault", VaultSchema);

// IDENTITY
const IdentitySchema = new mongoose.Schema({
  userId: String,
  type: String,
  name: String,
  number: String,
  ifsc: String,
  cvv: String
});
const Identity = mongoose.model("Identity", IdentitySchema);

// ==========================
// JWT MIDDLEWARE
// ==========================
function verifyToken(req, res, next) {
  const token = req.headers.authorization;

  if (!token) return res.status(401).send("Access Denied ❌");

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch {
    res.status(400).send("Invalid Token ❌");
  }
}

// ==========================
// AUTH ROUTES
// ==========================

// SIGNUP
app.post("/api/signup", async (req, res) => {
  try {
    const { email, password } = req.body;

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).send("User already exists ❌");

    const hashed = await bcrypt.hash(password, 10);
    await User.create({ email, password: hashed });

    res.send("User Created ✅");
  } catch (err) {
    res.status(500).send("Signup error ❌");
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).send("User not found ❌");

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).send("Wrong password ❌");

    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token });
  } catch (err) {
    res.status(500).send("Login error ❌");
  }
});

// ==========================
// VAULT ROUTES
// ==========================

// GET
app.get("/api/vault", verifyToken, async (req, res) => {
  const data = await Vault.find({ userId: req.user.id });
  res.json(data);
});

// ADD
app.post("/api/vault", verifyToken, async (req, res) => {
  const data = req.body;
  data.userId = req.user.id;

  await Vault.create(data);
  res.send("Saved ✅");
});

// DELETE
app.delete("/api/vault/:id", verifyToken, async (req, res) => {
  await Vault.findByIdAndDelete(req.params.id);
  res.send("Deleted ✅");
});

// ==========================
// IDENTITY ROUTES
// ==========================

// GET
app.get("/api/identity", verifyToken, async (req, res) => {
  const data = await Identity.find({ userId: req.user.id });
  res.json(data);
});

// ADD
app.post("/api/identity", verifyToken, async (req, res) => {
  const data = req.body;
  data.userId = req.user.id;

  await Identity.create(data);
  res.send("Identity Saved ✅");
});

// DELETE
app.delete("/api/identity/:id", verifyToken, async (req, res) => {
  await Identity.findByIdAndDelete(req.params.id);
  res.send("Identity Deleted ✅");
});

// ==========================
// ROOT ROUTE (IMPORTANT FOR RENDER)
// ==========================
app.get("/", (req, res) => {
  res.send("VaultSecure Backend Running 🚀");
});

// ==========================
// START SERVER
// ==========================
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} 🚀`);
});