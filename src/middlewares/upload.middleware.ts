import multer from 'multer'

const storage = multer.memoryStorage()

const fileFilter = (req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
  if (
    file.mimetype.startsWith('image/') ||
    file.mimetype === 'application/pdf' ||
    file.mimetype === 'application/msword' ||
    file.mimetype === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' ||
    file.mimetype === 'text/plain' ||
    file.mimetype === 'application/zip' ||
    file.mimetype === 'application/x-zip-compressed'
  ) {
    cb(null, true)
  } else {
    cb(new Error('Unsupported file type. Only images, PDFs, Word, TXT, and ZIP are allowed.'))
  }
}

export const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter,
})