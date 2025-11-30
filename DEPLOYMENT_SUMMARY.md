# 🚀 Render Deployment - Ready to Deploy!

## ✅ What's Been Prepared

Your P4 DPI project is now ready for Render deployment with the following new files:

### Core Deployment Files
1. **`render.yaml`** - Render Blueprint (auto-deployment config)
2. **`Dockerfile.render`** - Lightweight API-only Docker image
3. **`api_server.py`** - Standalone Flask API with no P4/Mininet dependencies

### Helper Scripts
4. **`sync_to_render.py`** - Sync local DPI packets to cloud
5. **`test_render_api.py`** - Test API before/after deployment

### Documentation
6. **`RENDER_DEPLOYMENT.md`** - Complete step-by-step guide
7. **`RENDER_QUICKSTART.md`** - Quick reference and checklists
8. **`DEPLOYMENT_SUMMARY.md`** - This file

## 🎯 Deployment Options

### Option A: Cloud-Only (Simplest)
Deploy API to Render with mock/static data for testing.
```bash
# Just push to GitHub and connect to Render
git add .
git commit -m "Add Render deployment"
git push origin main
```

### Option B: Local DPI + Cloud API (Recommended)
Keep P4 DPI running locally, sync packets to Render periodically.
```bash
# 1. Deploy to Render (see below)
# 2. Run sync script locally
python sync_to_render.py \
  --url https://your-app.onrender.com \
  --continuous \
  --interval 60
```

### Option C: Hybrid Real-Time
Continuous sync from local DPI to cloud with webhook notifications.

## 📋 Step-by-Step Deployment

### 1. Test Locally (Optional but Recommended)

```bash
# Build the Render Docker image
docker build -f Dockerfile.render -t p4-dpi-render .

# Run locally on port 10000
docker run -p 10000:10000 p4-dpi-render

# In another terminal, test it
python test_render_api.py http://localhost:10000
```

### 2. Push to GitHub

```bash
git add .
git commit -m "Add Render deployment configuration"
git push origin main
```

### 3. Deploy on Render

**Using Blueprint (Easiest):**
1. Go to https://dashboard.render.com
2. Click "New +" → "Blueprint"
3. Connect your GitHub repository
4. Render auto-detects `render.yaml`
5. Click "Apply"
6. Wait 5-10 minutes for build

**Manual Setup:**
1. Go to https://dashboard.render.com
2. Click "New +" → "Web Service"
3. Connect GitHub repo
4. Settings:
   - **Name**: `p4-dpi-api`
   - **Environment**: `Docker`
   - **Dockerfile Path**: `./Dockerfile.render`
   - **Instance Type**: `Free`
5. Add Disk:
   - **Name**: `p4-dpi-data`
   - **Mount Path**: `/data`
   - **Size**: `1 GB`
6. Click "Create Web Service"

### 4. Get Your API URL

After deployment completes, you'll get a URL like:
```
https://p4-dpi-api.onrender.com
```

### 5. Test the Deployed API

```bash
# Test from your local machine
python test_render_api.py https://your-app.onrender.com

# Or use curl
curl https://your-app.onrender.com/api/health
```

### 6. Populate with Data (Choose One)

**Option A: Upload from Local DPI**
```bash
python sync_to_render.py --url https://your-app.onrender.com
```

**Option B: Use Test Script (Seeds Mock Data)**
```bash
# Add seed endpoint temporarily to api_server.py
curl https://your-app.onrender.com/api/upload -X POST \
  -H "Content-Type: application/json" \
  -d @sample_packets.json
```

**Option C: Continuous Sync**
```bash
# Run in background
python sync_to_render.py \
  --url https://your-app.onrender.com \
  --continuous \
  --interval 60 \
  > sync.log 2>&1 &
```

### 7. Connect Your Frontend

Update your frontend to use the Render URL:

```javascript
// config.js or .env
const API_BASE_URL = 'https://your-app.onrender.com';

// Fetch packets
fetch(`${API_BASE_URL}/api/packets/recent?limit=100`)
  .then(res => res.json())
  .then(data => {
    console.log('Packets:', data.data);
  });

// Real-time streaming
const eventSource = new EventSource(`${API_BASE_URL}/stream`);
eventSource.onmessage = (event) => {
  const data = JSON.parse(event.data);
  updateDashboard(data.packets);
};
```

## 🔍 Available API Endpoints

Once deployed, your API provides:

```
GET  /                           - API info and available endpoints
GET  /api/health                 - Health check with packet count
GET  /api/packets                - Get packets with time offset
GET  /api/packets/recent         - Get most recent packets
GET  /api/stats                  - Get statistics (protocols, top IPs, etc.)
GET  /stream                     - Server-Sent Events stream (real-time)
POST /api/upload                 - Bulk upload packets (for sync script)
```

## 📊 What You Get with Free Tier

✅ **Included:**
- 750 hours/month (enough for one always-on service)
- 512 MB RAM
- 1 GB persistent disk
- HTTPS with automatic SSL
- Auto-deploy from GitHub
- Health checks and monitoring
- Custom Render subdomain

⚠️ **Limitations:**
- Service sleeps after 15 min inactivity
- First request after sleep ~30s
- Shared CPU
- No custom domain (need paid plan)

💰 **Upgrade Options:**
- **Starter ($7/month)**: 24/7 uptime, no sleep, more resources
- **Standard ($25/month)**: Better performance, custom domain

## 🔧 Monitoring & Maintenance

### View Logs
```bash
# In Render dashboard: Your Service → Logs
# Or use Render CLI (if installed)
render logs
```

### Check Health
```bash
curl https://your-app.onrender.com/api/health
```

### Update/Redeploy
```bash
# Just push changes to GitHub
git add .
git commit -m "Update API"
git push origin main
# Render auto-deploys
```

### Database Maintenance
```bash
# Access shell in Render dashboard
cd /data
sqlite3 packets.db

# Clean old packets
DELETE FROM packets WHERE id < 1000;
VACUUM;
```

## 🐛 Troubleshooting

### Build Fails
- Check Render logs for errors
- Ensure all files committed: `git status`
- Verify Dockerfile.render syntax

### API Returns 503
- Free tier is sleeping (first request takes ~30s)
- Or build failed (check logs)

### Database Empty
- Upload packets: `python sync_to_render.py --url YOUR_URL`
- Or check disk mount: Shell → `ls -la /data`

### CORS Errors
- API already has CORS enabled for all origins
- Check frontend uses HTTPS (not mixed HTTP/HTTPS)

### Sync Script Fails
- Verify local `logs/packets.db` exists
- Check Render URL is correct
- Test upload endpoint: `curl -X POST YOUR_URL/api/upload -d '{"packets":[]}'`

## 📈 Performance Tips

1. **Optimize Queries**: Add indexes in database for common queries
2. **Batch Uploads**: Sync in batches of 1000-5000 packets
3. **Clean Old Data**: Periodically delete old packets to save space
4. **Upgrade Plan**: For production, consider paid plan ($7/month)
5. **Use CDN**: For static assets, use Cloudflare/CloudFront

## 🎉 Next Steps

- [ ] Deploy to Render (follow steps above)
- [ ] Test all API endpoints
- [ ] Set up data sync (if using local DPI)
- [ ] Connect frontend to Render URL
- [ ] Monitor logs and performance
- [ ] Consider upgrading to paid plan for production

## 📚 Additional Resources

- **Full Guide**: See `RENDER_DEPLOYMENT.md`
- **Quick Reference**: See `RENDER_QUICKSTART.md`
- **Render Docs**: https://render.com/docs
- **Render Community**: https://community.render.com
- **API Code**: See `api_server.py`
- **Sync Script**: See `sync_to_render.py`

## 🆘 Need Help?

1. Check logs in Render dashboard
2. Review `RENDER_DEPLOYMENT.md`
3. Test locally first: `docker build -f Dockerfile.render -t test .`
4. Use test script: `python test_render_api.py`
5. Open GitHub issue if needed

---

**Ready to deploy?** Start with Step 1 above! 🚀
