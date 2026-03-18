import cloudinary from "../config/cloudinary"
import streamifier from "streamifier"

export const uploadToCloudinary = (fileBuffer: Buffer, mimetype?: string): Promise<string> => {
  return new Promise((resolve, reject) => {
    const resourceType = mimetype === 'application/pdf' ? 'raw' : 'auto';

    const stream = cloudinary.uploader.upload_stream(
      { 
        folder: "project_attachments", 
        resource_type: resourceType,
        type: "upload",
        access_mode: "public"
      },
      (error, result) => {
        if (error) return reject(error)
        if (result && result.secure_url) return resolve(result.secure_url)
        reject(new Error("Failed to upload to Cloudinary"))
      }
    )

    streamifier.createReadStream(fileBuffer).pipe(stream)
  })
}

export const uploadMultipleToCloudinary = async (files: Express.Multer.File[]): Promise<string[]> => {
  if (!files || files.length === 0) return [];

  try {
    const uploadPromises = files.map((file) => uploadToCloudinary(file.buffer, file.mimetype));
    const secureUrls = await Promise.all(uploadPromises);
    return secureUrls;
  } catch (error) {
    console.error('Error uploading multiple files to Cloudinary:', error);
    throw new Error('File upload failed');
  }
}