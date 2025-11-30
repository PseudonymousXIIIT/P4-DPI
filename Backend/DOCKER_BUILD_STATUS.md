# Docker Build Status

## Current Status: BUILDING

The Docker image is being rebuilt to include `simple_switch_grpc` support.

### What's Happening:
1. **Build Started**: `docker build -t p4-dpi:latest -f Dockerfile .`
2. **Expected Duration**: 30-60 minutes
3. **Log File**: `docker_build.log` (in project root)

### Changes in Dockerfile:
- Added explicit build and installation of `simple_switch_grpc` in BMv2 build step
- This ensures the binary is available at `/usr/local/bin/simple_switch_grpc`

### To Check Build Progress:

```powershell
# Check the build log
Get-Content docker_build.log -Tail 30

# Check if build is still running
docker ps -a

# Check Docker images
docker images | grep p4-dpi
```

### After Build Completes:

1. **Stop and remove old container**:
   ```powershell
   docker stop p4-dpi-container
   docker rm p4-dpi-container
   ```

2. **Start new container**:
   ```powershell
   docker run --name p4-dpi-container --cap-add NET_ADMIN --cap-add SYS_ADMIN -v "${PWD}:/p4-dpi" -w /p4-dpi -d p4-dpi:latest sleep infinity
   ```

3. **Verify simple_switch_grpc is installed**:
   ```powershell
   docker exec p4-dpi-container which simple_switch_grpc
   ```

4. **Start the DPI system**:
   ```powershell
   docker exec -d p4-dpi-container python3 /p4-dpi/scripts/start_dpi.py
   ```

### Expected Results After Build:
- ✅ `simple_switch_grpc` available at `/usr/local/bin/simple_switch_grpc`
- ✅ P4 switches can start with P4Runtime gRPC support
- ✅ P4Runtime connections work properly
- ✅ ICMP ping traffic generation works (already fixed)

### Notes:
- The build process compiles BMv2 from source, which takes significant time
- Do not interrupt the build process
- If the build fails, check `docker_build.log` for errors

