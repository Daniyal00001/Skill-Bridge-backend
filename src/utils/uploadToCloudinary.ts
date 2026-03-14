import cloudinary from "../config/cloudinary"
import streamifier from "streamifier"

export const uploadToCloudinary = (fileBuffer: Buffer): Promise<string> => {
  return new Promise((resolve, reject) => {

    const stream = cloudinary.uploader.upload_stream(
      { folder: "project_attachments" },
      (error, result) => {
        if (error) return reject(error)
        if (result) return resolve(result.secure_url)
      }
    )

    streamifier.createReadStream(fileBuffer).pipe(stream)
  })
}