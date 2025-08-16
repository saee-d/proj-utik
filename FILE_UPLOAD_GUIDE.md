# Video Upload Implementation - Updated

## 🎥 **File Upload System Overview**

The video sharing platform now supports both **metadata-only** uploads and **actual file uploads** to Azure Blob Storage, matching your previous sophisticated implementation.

## 🚀 **Two Upload Endpoints**

### **1. Metadata Upload (Existing)**

```http
POST /api/videos
Content-Type: application/json
Authorization: Bearer {token}

{
  "title": "My Video",
  "description": "Description",
  "genre": "Entertainment",
  "ageRating": "PG",
  "fileUrl": "https://existing-url.com/video.mp4",
  "thumbnailUrl": "https://existing-url.com/thumb.jpg",
  "sizeMb": 10.5,
  "contentType": "video/mp4",
  "originalFilename": "video.mp4"
}
```

### **2. File Upload (New - Multipart)**

```http
POST /api/upload/video
Content-Type: multipart/form-data
Authorization: Bearer {token}

Form Data:
- video_file: [FILE] (Required)
- thumbnail_file: [FILE] (Optional)
- title: "Epic Dance Challenge" (Required)
- description: "Amazing moves!" (Optional)
- genre: "Dance" (Optional)
- ageRating: "PG" (Required - G|PG|PG-13|R|18+)
```

## 🔧 **Azure Blob Storage Integration**

### **Storage Functions Added:**

```python
def upload_video_to_blob(file_data: bytes, filename: str, content_type: str)
def upload_thumbnail_to_blob(file_data: bytes, filename: str, content_type: str)
def get_secure_blob_url(blob_name: str, container_name: str, expiry_hours: int = 24)
```

### **Container Structure:**

- **Videos:** `AZURE_STORAGE_CONTAINER` (default: "videos")
- **Thumbnails:** `AZURE_STORAGE_THUMBNAIL_CONTAINER` (default: "thumbnails")

### **File Processing:**

1. **Validation:** Checks `video/*` content type
2. **Upload:** Stores in Azure Blob with UUID filename
3. **Security:** Generates SAS tokens for secure access (24hr expiry)
4. **Metadata:** Saves file info to Cosmos DB

## 📊 **Enhanced Video Record Structure**

```json
{
  "id": "uuid",
  "creatorId": "user-uuid",
  "title": "Epic Dance Challenge #viral",
  "description": "Amazing dance moves!",
  "fileUrl": "https://...blob.../video.mp4?{sas-token}",
  "thumbnailUrl": "https://...blob.../thumb.jpg?{sas-token}",
  "genre": "Dance",
  "ageRating": "PG",
  "uploadDate": "2025-08-14T15:30:00.000Z",
  "viewCount": 0,
  "status": "ready",
  "sizeMb": 15.7,
  "originalUrl": "https://...blob.../video.mp4",
  "blobName": "uuid.mp4",
  "thumbnailBlobName": "uuid.jpg",
  "contentType": "video/mp4",
  "originalFilename": "epic_dance_challenge.mp4",
  "average_rating": null
}
```

## ⚙️ **Environment Variables Required**

```bash
# Azure Storage
AZURE_STORAGE_CONNECTION_STRING=DefaultEndpointsProtocol=https;AccountName=...
AZURE_STORAGE_CONTAINER=videos
AZURE_STORAGE_THUMBNAIL_CONTAINER=thumbnails

# Cosmos DB (existing)
COSMOS_DB_ENDPOINT=https://...
COSMOS_DB_KEY=...
COSMOS_DB_DATABASE=videosharing

# JWT (existing)
JWT_SECRET_KEY=your-secret-key
```

## 📱 **Frontend Integration Example**

### **JavaScript (FormData)**

```javascript
const uploadVideoFile = async (videoFile, thumbnailFile, metadata) => {
  const formData = new FormData();
  formData.append("video_file", videoFile);
  if (thumbnailFile) {
    formData.append("thumbnail_file", thumbnailFile);
  }
  formData.append("title", metadata.title);
  formData.append("description", metadata.description);
  formData.append("genre", metadata.genre);
  formData.append("ageRating", metadata.ageRating);

  const response = await fetch("/api/upload/video", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
    },
    body: formData,
  });

  return response.json();
};
```

### **React Hook Example**

```jsx
const useVideoUpload = () => {
  const [uploading, setUploading] = useState(false);

  const uploadVideo = async (file, metadata) => {
    setUploading(true);
    try {
      const result = await uploadVideoFile(file, null, metadata);
      console.log("Upload successful:", result);
      return result;
    } catch (error) {
      console.error("Upload failed:", error);
      throw error;
    } finally {
      setUploading(false);
    }
  };

  return { uploadVideo, uploading };
};
```

## 🧪 **Updated Postman Collections**

### **New Requests Added:**

1. **"Upload Video File (Multipart)"** - Local development
2. **"Upload Video File (Multipart) - Dance"** - Azure production

### **Features:**

- ✅ **File Selection:** Built-in file picker for video/thumbnail
- ✅ **Form Fields:** Pre-filled metadata examples
- ✅ **Test Scripts:** Automatic response validation
- ✅ **Variables:** Auto-saves video_id for further testing

### **Usage Instructions:**

1. **Authenticate:** Run login request first
2. **Select Files:** Choose video file (and optional thumbnail)
3. **Customize:** Update title, description, genre, ageRating
4. **Upload:** Submit request
5. **Test:** Use returned video_id for comments/ratings

## 🔒 **Security Features**

- **Authentication:** JWT token required for uploads
- **File Validation:** Content-type checking
- **SAS Tokens:** Time-limited secure URLs (24 hours)
- **Error Handling:** Comprehensive logging and error responses
- **Size Tracking:** Automatic file size calculation

## 🎯 **File Types Supported**

### **Videos:**

- .mp4, .mov, .avi, .mkv, .webm
- Content-Type: `video/*`

### **Thumbnails:**

- .jpg, .jpeg, .png, .webp
- Content-Type: `image/*`

---

**Ready to upload!** 🚀 Your video sharing platform now supports full file upload functionality with Azure Blob Storage integration, secure URLs, and comprehensive metadata tracking.
