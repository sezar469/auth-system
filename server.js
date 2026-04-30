// ======================
// SIGNUP
// ======================
app.post("/signup", async (req, res) => {
  try {
    console.log("BODY:", req.body);

    const { email, phone, password, captchaId, captchaAnswer } = req.body;

    // CHECK BODY
    if (!req.body || Object.keys(req.body).length === 0) {
      return res.status(400).send("No data sent");
    }

    // CAPTCHA CHECK
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

    // INPUT VALIDATION
    if (!email && !phone) {
      return res.status(400).send("Email or phone required");
    }

    if (!password) {
      return res.status(400).send("Password is required");
    }

    if (!validatePassword(password)) {
      return res.status(400).send("Weak password");
    }

    // ✅ FIXED DUPLICATE CHECK
    let existingUser;

    if (email) {
      existingUser = await User.findOne({ email });
    }

    if (!existingUser && phone) {
      existingUser = await User.findOne({ phone });
    }

    if (existingUser) {
      return res.status(400).send("User already exists");
    }

    // CREATE USER
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