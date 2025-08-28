import httpx

async def external_api_check() -> bool:
    """Check external service connectivity"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get("https://httpbin.org/status/200", timeout=5.0)
            return response.status_code == 200
    except Exception:
        return False

async def memory_check() -> bool:
    """Check memory usage"""
    try:
        import psutil
        memory = psutil.virtual_memory()
        # Fail if memory usage is above 90%
        return memory.percent < 90
    except Exception:
        return False
