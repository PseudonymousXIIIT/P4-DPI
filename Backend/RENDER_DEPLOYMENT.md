# Render Deployment Guide - Two Service Architecture

## Overview

This deployment uses **two separate Render web services**:

1. **p4-dpi-backend** - Runs your full P4 DPI system (Docker Hub image)
   - Generates packet data continuously
   - Exposes logs and packet data
   - URL: `https://p4-dpi-backend.onrender.com`

2. **p4-dpi** - Serves React frontend + proxies to backend
   - Shows React dashboard
   - Provides REST API endpoints
   - Connects to backend service
   - URL: `https://p4-dpi.onrender.com`

## Deployment Steps

### Step 1: Ensure Docker Image is Pushed to Docker Hub

Your image should already be pushed as `adityasinghrautan/p4-dpi:latest`

Verify:
```bash
docker images | grep p4-dpi
# Should show: adityasinghrautan/p4-dpi:latest
```

### Step 2: Create Service 1 - P4 DPI Backend on Render

1. Go to **Render Dashboard** → **New** → **Web Service**
2. Select **"Deploy an image from a Docker registry"**
3. Fill in:
   - **Image URL**: `adityasinghrautan/p4-dpi:latest`
   - **Name**: `p4-dpi-backend`
   - **Region**: Choose closest to you
   - **Plan**: Free
4. Add **Environment Variables**:
   - `DPI_TRAFFIC_TARGET_PACKETS` = `600`
   - `PYTHONUNBUFFERED` = `1`
5. Click **Deploy**

⏳ This will take **10-15 minutes** to build and start (compiling P4C, BMv2, etc.)

### Step 3: Create Service 2 - Frontend API on Render

1. Go to **Render Dashboard** → **New** → **Web Service**
2. Select **"Build and deploy from Git"**
3. Connect your GitHub repo: `https://github.com/PseudonymousXIIIT/P4-DPI`
4. Fill in:
   - **Name**: `p4-dpi`
   - **Region**: Same as backend
   - **Branch**: `main`
   - **Build Command**: (leave empty)
   - **Start Command**: `gunicorn --bind 0.0.0.0:$PORT --workers 2 --timeout 120 --worker-class sync scripts.flask_api:app`
   - **Plan**: Free
   - **Docker**: Yes
   - **Dockerfile Path**: `./Dockerfile.render`
5. Add **Environment Variables**:
   - `PYTHONUNBUFFERED` = `1`
   - `BACKEND_SERVICE_URL` = `https://p4-dpi-backend.onrender.com` (use the exact URL from Service 1)
6. Click **Deploy**

### Step 4: Verify Deployment

Once both services are deployed:

1. **Check Frontend**: Visit `https://p4-dpi.onrender.com/`
   - Should show React dashboard with streaming packets
   - May show "reconnecting" initially while backend starts generating data

2. **Check Health**: Visit `https://p4-dpi.onrender.com/api/health`
   - Should show both frontend and backend status
   ```json
   {
     "status": "healthy",
     "frontend": {"status": "healthy", "packet_count": 1234},
     "backend": {"status": "healthy", "url": "https://p4-dpi-backend.onrender.com"}
   }
   ```

3. **Check Stream**: Visit `https://p4-dpi.onrender.com/stream`
   - Should show real-time SSE data with packets from P4 DPI backend

## How It Works

```
User Browser
    ↓
https://p4-dpi.onrender.com (Frontend service)
    ↓
    ├─→ Serves React frontend
    ├─→ /api/* endpoints
    └─→ Proxies /stream to backend
         ↓
         https://p4-dpi-backend.onrender.com (P4 DPI service)
            ↓
            Runs: python3 scripts/start_dpi.py
            Generates packet data
            Logs to: /p4-dpi/logs/packets.db
```

## Important Notes

### Free Tier Limitations

- **Memory**: 512 MB per service
- **Sleep**: Services auto-sleep after 15 minutes of inactivity (first request takes ~30s)
- **Ephemeral Storage**: Database/logs reset on redeploy
- **Build Time**: P4 compilation takes 10-15 minutes

### Monitoring

Check logs for each service in Render dashboard:
- Backend logs: Check for `Starting P4 DPI system` message
- Frontend logs: Check for `Backend P4 DPI Service URL` message

### Troubleshooting

**Frontend shows "reconnecting":**
- Backend service may still be starting (takes 10-15 min)
- Check backend service logs in Render dashboard

**Health check shows backend as "unknown":**
- Backend might not have exposed `/api/health` endpoint
- Check if backend service has a Flask/API running on port 5000

**No packet data on frontend:**
- Check if `DPI_TRAFFIC_TARGET_PACKETS` is set on backend
- Wait for P4 DPI to generate data (5-10 minutes after startup)

## Environment Variables Reference

**p4-dpi-backend service:**
- `DPI_TRAFFIC_TARGET_PACKETS`: Number of packets to generate (default: 600)
- `PYTHONUNBUFFERED`: Set to 1 for real-time logs

**p4-dpi service:**
- `BACKEND_SERVICE_URL`: Full HTTPS URL of p4-dpi-backend service
- `PYTHONUNBUFFERED`: Set to 1 for real-time logs

## Next Steps

Once deployed:
1. Monitor the `/api/health` endpoint to ensure both services are healthy
2. Check `/stream` endpoint for real-time packet data
3. View full packet list at `/api/packets`
4. View statistics at `/api/stats`

## Updating Code

When you push to GitHub:
1. **Frontend service** (p4-dpi) automatically redeploys
2. **Backend service** (p4-dpi-backend) stays unchanged (uses Docker Hub image)

To update the backend:
1. Rebuild locally: `docker build -f Dockerfile -t adityasinghrautan/p4-dpi:latest .`
2. Push: `docker push adityasinghrautan/p4-dpi:latest`
3. Redeploy on Render (manual restart needed)
