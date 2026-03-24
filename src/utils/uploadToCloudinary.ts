import cloudinary from "../config/cloudinary"
import streamifier from "streamifier"

export const uploadToCloudinary = (fileBuffer: Buffer, originalName?: string, mimetype?: string): Promise<string> => {
  return new Promise((resolve, reject) => {
    // Determine resource type: images/videos/audio have specialized types; others are 'raw'
    let resourceType: 'image' | 'video' | 'raw' | 'auto' = 'auto';
    
    if (mimetype) {
      if (mimetype.startsWith('image/')) resourceType = 'image';
      else if (mimetype.startsWith('video/')) resourceType = 'video';
      else if (mimetype === 'application/pdf') resourceType = 'image'; // Cloudinary treats PDF as image for transformations
      else resourceType = 'raw';
    }

    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const fileNameWithoutExt = originalName ? originalName.split('.').slice(0, -1).join('.') : 'file';
    const extension = originalName ? `.${originalName.split('.').pop()}` : '';
    const publicId = `project_attachments/${fileNameWithoutExt}_${uniqueSuffix}${extension}`;

    const stream = cloudinary.uploader.upload_stream(
      { 
        public_id: publicId,
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
    const uploadPromises = files.map((file) => uploadToCloudinary(file.buffer, file.originalname, file.mimetype));
    const secureUrls = await Promise.all(uploadPromises);
    return secureUrls;
  } catch (error) {
    console.error('Error uploading multiple files to Cloudinary:', error);
    throw new Error('File upload failed');
  }
}

export const deleteFromCloudinary = async (url: string | null | undefined): Promise<void> => {
  if (!url) return;
  try {
    // Extract public_id from URL
    // Format: .../upload/v12345678/folder/public_id.ext
    const parts = url.split("/");
    const fileWithExt = parts.pop();
    if (!fileWithExt) return;
    
    const filePart = fileWithExt.split(".")[0]; // remove extension
    const folderPart = parts.pop();
    
    if (filePart && folderPart && folderPart !== 'upload' && folderPart !== 'image' && folderPart !== 'raw') {
      const publicId = `${folderPart}/${filePart}`;
      await cloudinary.uploader.destroy(publicId);
      console.log(`[Cloudinary] Deleted asset: ${publicId}`);
    } else if (filePart) {
      // No folder or folder is 'upload'/'image'
      await cloudinary.uploader.destroy(filePart);
      console.log(`[Cloudinary] Deleted asset: ${filePart}`);
    }
  } catch (error) {
    console.warn("[Cloudinary] Delete failed (non-fatal):", error);
  }
};