from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from datetime import datetime
from starlette.responses import JSONResponse
from ...credential_service.credservice import health_check



# Initialize scheduler
scheduler = AsyncIOScheduler()

async def run_credential_service_check():
    """
    Run health check for credential service and log the result
    """
    try:
        print(f"Running scheduled credential service health check at {datetime.now()}")
        result: JSONResponse = await health_check()
        print(f"Credential service health check result: {result.body}")
    except Exception as e:
        print(f"Credential service health check failed: {str(e)}")

def start_health_check_scheduler():
    """
    Start the scheduler for periodic credential service health checks
    """
    if not scheduler.running:
        # Add job to run every 10 minutes
        scheduler.add_job(
            run_credential_service_check,
            trigger=IntervalTrigger(minutes=10),
            id="credential_service_health_check",
            replace_existing=True
        )
        scheduler.start()
        print("Credential service health check scheduler started")

def shutdown_scheduler():
    """
    Shutdown the scheduler
    """
    if scheduler.running:
        scheduler.shutdown()
        print("Credential service health check scheduler stopped")