const User = require('../models/User')

// Register User
exports.registerUser = async (req, res) => {
  try {
    const { name, email, password, role } = req.body

    const user = await User.create({
      name,
      email,
      password,
      role
    })

    res.status(201).json(user)

  } catch (error) {
    res.status(500).json({ message: error.message })
  }
}

// Get Users
exports.getUsers = async (req, res) => {
  const users = await User.find()
  res.json(users)
}