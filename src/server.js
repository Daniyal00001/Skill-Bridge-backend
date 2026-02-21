require('dotenv').config()
const express = require('express')
const cors = require('cors')
const connectDB = require('./config/db')

const app = express()

// Connect Database
connectDB()

// Middlewares
app.use(cors())
app.use(express.json())

// Test Route
app.get('/', (req, res) => {
  res.send('SkillBridge API Running 🚀')
})

// Routes
app.use('/api/users', require('./routes/userRoutes'))




// Port
const PORT = process.env.PORT || 5000

// Server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} 🚀`)
})