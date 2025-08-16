# Video Sharing Platform API - Updated Documentation

## 🎯 **API Structure Overview**

This document describes the updated API structure for the video sharing platform that now correctly matches the actual Cosmos DB video record format.

## 📊 **Video Data Model**

### **VideoResponse (API Response)**

```json
{
  "id": "d1e3a6ac-81d1-48fd-b50d-a5f1705db7e6",
  "title": "Birds Core",
  "description": "Minding their own business",
  "genre": "Wild Life",
  "ageRating": "PG",
  "uploadDate": "2025-08-10T19:04:08.698975",
  "creatorId": "20253ebb-a620-4cff-ae97-0d4dd6877c8c",
  "viewCount": 0,
  "fileUrl": "https://projutik.blob.core.windows.net/videos/1eae7b7b-470f-4f2b-93d1-b38ce0c01264.mp4",
  "thumbnailUrl": "https://projutik.blob.core.windows.net/thumbnails/dea1ba42-f146-475f-ad72-98f7e22f5642.jpg",
  "status": "ready",
  "sizeMb": 5.54,
  "contentType": "video/mp4",
  "originalFilename": "12634389-hd_1280_720_30fps.mp4",
  "average_rating": null
}
```

### **VideoUpload (API Request)**

```json
{
  "title": "Epic Dance Challenge #viral",
  "description": "Amazing dance moves that will blow your mind!",
  "genre": "Dance",
  "ageRating": "PG",
  "fileUrl": "https://projutik.blob.core.windows.net/videos/dance-challenge.mp4",
  "thumbnailUrl": "https://projutik.blob.core.windows.net/thumbnails/dance-thumb.jpg",
  "sizeMb": 15.7,
  "contentType": "video/mp4",
  "originalFilename": "epic_dance_challenge.mp4"
}
```

## 🔄 **Field Mapping Changes**

| **Old Field Names** | **New Field Names** | **Description**                   |
| ------------------- | ------------------- | --------------------------------- |
| `publisher`         | **Removed**         | No longer used                    |
| `producer`          | **Removed**         | No longer used                    |
| `age_rating`        | `ageRating`         | Age rating (G, PG, PG-13, R, 18+) |
| `upload_date`       | `uploadDate`        | ISO date string                   |
| `uploader_id`       | `creatorId`         | User ID who uploaded              |
| `views`             | `viewCount`         | Number of views                   |
| `blob_url`          | `fileUrl`           | Video file URL                    |
| `tags`              | **Removed**         | No longer used                    |
| **New:**            | `thumbnailUrl`      | Thumbnail image URL               |
| **New:**            | `status`            | Video processing status           |
| **New:**            | `sizeMb`            | File size in MB                   |
| **New:**            | `contentType`       | MIME type                         |
| **New:**            | `originalFilename`  | Original filename                 |

## 🎬 **API Endpoints**

### **1. List Videos**

```http
GET /api/videos?skip=0&limit=10
```

**Response:** Array of `VideoResponse` objects

### **2. Upload Video**

```http
POST /api/videos
Authorization: Bearer {token}
Content-Type: application/json

{
  "title": "My Video",
  "description": "Description here",
  "genre": "Entertainment",
  "ageRating": "PG",
  "fileUrl": "https://...",
  "thumbnailUrl": "https://...",
  "sizeMb": 10.5,
  "contentType": "video/mp4",
  "originalFilename": "video.mp4"
}
```

### **3. Search Videos**

```http
GET /api/videos/search?q=dance&genre=Entertainment
```

### **4. Get Single Video**

```http
GET /api/videos/{video_id}
```

_Automatically increments view count_

## 📝 **Updated Postman Collections**

### **Local Development Collection**

- **File:** `video_sharing_postman_collection.json`
- **Base URL:** `http://localhost:7071`
- **Updated:** All upload requests now use new field structure

### **Azure Production Collection**

- **File:** `video_sharing_azure_collection.json`
- **Base URL:** `https://proj-backend-svc.azurewebsites.net`
- **Updated:** Realistic examples with proper blob URLs
- **Enhanced:** Better test scripts showing new response fields

## 🎯 **Example Usage**

### **Upload a Dance Video**

```json
{
  "title": "Epic Dance Challenge #viral",
  "description": "Amazing dance moves that will blow your mind! 🕺💃",
  "genre": "Dance",
  "ageRating": "PG",
  "fileUrl": "https://projutik.blob.core.windows.net/videos/dance-challenge-viral.mp4",
  "thumbnailUrl": "https://projutik.blob.core.windows.net/thumbnails/dance-challenge-thumb.jpg",
  "sizeMb": 15.7,
  "contentType": "video/mp4",
  "originalFilename": "epic_dance_challenge.mp4"
}
```

### **Upload a Comedy Skit**

```json
{
  "title": "When your code finally works 😂",
  "description": "Every programmer can relate to this! The struggles are real 😭💻",
  "genre": "Comedy",
  "ageRating": "PG",
  "fileUrl": "https://projutik.blob.core.windows.net/videos/code-works-comedy.mp4",
  "thumbnailUrl": "https://projutik.blob.core.windows.net/thumbnails/code-works-thumb.jpg",
  "sizeMb": 8.3,
  "contentType": "video/mp4",
  "originalFilename": "code_finally_works.mp4"
}
```

## ✅ **What's Fixed**

1. **Field Mapping Errors** - All `'publisher'` errors resolved
2. **Database Queries** - Updated to use `uploadDate` instead of `upload_date`
3. **Response Models** - Match actual Cosmos DB structure
4. **Postman Collections** - Updated with correct field names and realistic examples
5. **Test Scripts** - Show correct response fields like `viewCount`, `creatorId`, `fileUrl`

## 🚀 **Ready to Test**

Both Postman collections are now fully compatible with your updated API and actual video data structure. Import either collection and start testing with the new field structure!

---

**Last Updated:** August 14, 2025  
**API Version:** v2.0 (Field Structure Update)
