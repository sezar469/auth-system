const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const otpGenerator = require("otp-generator");
const User = require("./models/User");

const app = express();
app.use(express.json());

// ======================
// TEMP STORAGE
// ======================
const otpStore = {};
const loginAttempts = {};
const captchaStore = {};

// ======================
// PASSWORD VALIDATION
// ======================
function validatePassword(password) {
  return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/.test(password);
}

// ======================
// CONNECT DATABASE
// ======================
mongoose.connect(process.env.MONGO_URI)
.then(() => console.log("MongoDB Connected ✔"))
.catch(err => console.log("DB Error:", err));

// ======================
// HOME
// ======================
app.get("/", (req, res) => {
  res.send("Auth System Running 🚀");
});

// ======================
// CAPTCHA
// ======================
app.get("/captcha", (req, res) => {
  const num1 = Math.floor(Math.random() * 10);
  const num2 = Math.floor(Math.random() * 10);

  const answer = num1 + num2;
  const captchaId = Date.now().toString();

  captchaStore[captchaId] = answer;

  res.json({
    captchaId,
    question: `What is ${num1} + ${num2}?`
  });
});

// ======================
// SIGNUP
// ======================
app.post("/signup", async (req, res) => {
  try {
    console.log("BODY:", req.body);

    const { email, phone, password, captchaId, captchaAnswer } = req.body;

    // ======================
    // CHECK BODY
    // ======================
    if (!req.body || Object.keys(req.body).length === 0) {
      return res.status(400).send("No data sent");
    }

    // ======================
    // CAPTCHA CHECK
    // ======================
    if (!captchaId || captchaAnswer === undefined) {
      return res.status(400).send("CAPTCHA required");
    }

    if (!captchaStore[captchaId]) {
      return res.status(400).send("Invalid CAPTCHA");
    }

    if (parseInt(captchaAnswer) !== captchaStore[captchaId]) {
      return res.status(400).send("Incorrect CAPTCHA");
    }

    delete captchaStore[captchaId];

    // ======================
    // INPUT VALIDATION
    // ======================
    if (!email && !phone) {
      return res.status(400).send("Email or phone required");
    }

    if (!password) {
      return res.status(400).send("Password is required");
    }

    if (!validatePassword(password)) {
      return res.status(400).send("Weak password");
    }

    // ======================
    // CHECK EXISTING USER
    // ======================
    const existingUser = await User.findOne({
      $or: [{ email }, { phone }]
    });

    if (existingUser) {
      return res.status(400).send("User already exists");
    }

    // ======================
    // CREATE USER
    // ======================
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      email,
      phone,
      password: hashedPassword
    });

    await user.save();

    res.status(201).send("User created successfully");

  } catch (err) {
    console.log("SIGNUP ERROR:", err);
    res.status(500).send(err.message);
  }
});
// ======================
// LOGIN (STEP 1)
// ======================
app.post("/login", async (req, res) => {
  try {
    const { email, phone, password, captchaId, captchaAnswer } = req.body;

    // CAPTCHA CHECK
    if (!captchaStore[captchaId]) {
      return res.status(400).send("Invalid CAPTCHA");
    }

    if (parseInt(captchaAnswer) !== captchaStore[captchaId]) {
      return res.status(400).send("Incorrect CAPTCHA");
    }

    delete captchaStore[captchaId];

    const user = await User.findOne({
      $or: [{ email }, { phone }]
    });

    if (!user) {
      return res.status(400).send("User not found");
    }

    // LOGIN ATTEMPTS
    if (!loginAttempts[user._id]) {
      loginAttempts[user._id] = { count: 0, lockUntil: null };
    }

    if (
      loginAttempts[user._id].lockUntil &&
      Date.now() < loginAttempts[user._id].lockUntil
    ) {
      return res.status(403).send("Account locked. Try later.");
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      loginAttempts[user._id].count++;

      if (loginAttempts[user._id].count >= 5) {
        loginAttempts[user._id].lockUntil = Date.now() + 10 * 60 * 1000;
        return res.status(403).send("Too many attempts. Locked 10 mins.");
      }

      return res.status(400).send("Incorrect password");
    }

    // RESET ATTEMPTS
    loginAttempts[user._id] = { count: 0, lockUntil: null };

    // GENERATE OTP
    const otp = otpGenerator.generate(6, {
      upperCaseAlphabets: false,
      lowerCaseAlphabets: false,
      specialChars: false
    });

    otpStore[user._id] = {
      otp,
      expires: Date.now() + 5 * 60 * 1000
    };

    console.log("OTP:", otp);

    res.json({
      message: "OTP sent",
      userId: user._id
    });

  } catch (err) {
    console.log(err);
    res.status(500).send("Server error");
  }
});

// ======================
// VERIFY OTP
// ======================
app.post("/verify-otp", (req, res) => {
  const { userId, otp } = req.body;

  const stored = otpStore[userId];

  if (!stored) return res.status(400).send("OTP not found");

  if (stored.otp !== otp) return res.status(400).send("Invalid OTP");

  if (Date.now() > stored.expires)
    return res.status(400).send("OTP expired");

  delete otpStore[userId];

  const token = jwt.sign(
    { userId },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.json({
    message: "Login successful",
    token
  });
});

// ======================
// AUTH MIDDLEWARE
// ======================
function authMiddleware(req, res, next) {
  const token = req.headers.authorization;

  if (!token) return res.status(401).send("No token");

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch {
    res.status(400).send("Invalid token");
  }
}

// ======================
// PROFILE
// ======================
app.get("/profile", authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.userId).select("-password");
  res.json(user);
});

// ======================
// START SERVER (IMPORTANT)
// ======================
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});