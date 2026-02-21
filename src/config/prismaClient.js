const { PrismaClient } = require('@prisma/client')

/**
 * PrismaClient utility for Prisma 7.
 * In Prisma 7, the connection URL is passed to the constructor.
 */
const prisma = new PrismaClient({
  datasourceUrl: process.env.MONGO_URI,
})

module.exports = prisma
