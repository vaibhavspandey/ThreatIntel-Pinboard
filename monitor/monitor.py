print("--- MONITOR SCRIPT STARTED ---", flush=True)
import os
import time
import requests
from apscheduler.schedulers.blocking import BlockingScheduler
from connectors import get_enrichment_data
from delta_engine import find_deltas

# API Configuration
API_BASE_URL = os.getenv("API_BASE_URL", "http://backend:8000")

# Create a session for connection pooling
session = requests.Session()


def run_monitoring_cycle():
    """
    Main monitoring cycle function.
    This is called periodically by the scheduler.
    """
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Starting monitoring cycle...", flush=True)

    # Retry logic for connecting to the backend
    for i in range(5):
        try:
            # Step 1: Get all pins to check
            response = session.get(f"{API_BASE_URL}/api/internal/pins-to-check", timeout=30)
            response.raise_for_status()
            break  # Break the loop if the request is successful
        except requests.exceptions.RequestException as e:
            print(f"Error connecting to backend: {e}", flush=True)
            if i < 4:
                print("Retrying in 5 seconds...", flush=True)
                time.sleep(5)
            else:
                print("Could not connect to backend after 5 attempts. Aborting cycle.", flush=True)
                return

    try:
        pins = response.json()
        print(f"Found {len(pins)} active pins to check", flush=True)
        
        # Step 2: Loop through each pin
        for pin in pins:
            pin_id = pin['id']
            ioc_value = pin['ioc_value']
            ioc_type = pin['ioc_type']
            
            print(f"Processing pin {pin_id}: {ioc_value} ({ioc_type})", flush=True)
            
            try:
                # Step 2a: Get new report from enrichment
                print(f"  Fetching enrichment data...", flush=True)
                new_report = get_enrichment_data(ioc_value, ioc_type)
                
                if not new_report:
                    print(f"  Warning: No enrichment data returned for {ioc_value}", flush=True)
                    continue
                
                # Step 2b: Get baseline snapshot
                print(f"  Fetching baseline snapshot...", flush=True)
                try:
                    baseline_response = session.get(f"{API_BASE_URL}/api/internal/baseline/{pin_id}", timeout=30)
                except requests.exceptions.Timeout:
                    print(f"  Warning: Timeout while fetching baseline for pin {pin_id}", flush=True)
                    baseline_snapshot = {}
                except requests.exceptions.RequestException as e:
                    print(f"  Warning: Request failed while fetching baseline for pin {pin_id}: {str(e)}", flush=True)
                    baseline_snapshot = {}
                else:
                    if baseline_response.status_code != 200:
                        print(f"  Warning: Could not fetch baseline for pin {pin_id}", flush=True)
                        baseline_snapshot = {}
                    else:
                        baseline_data = baseline_response.json()
                        baseline_snapshot = baseline_data.get('full_report_json', {})
                
                # Step 2c: Find deltas
                print(f"  Comparing with baseline...", flush=True)
                deltas = find_deltas(baseline_snapshot, new_report, ioc_type)
                
                # Step 2d: Save new snapshot (ALWAYS)
                print(f"  Saving new snapshot...", flush=True)
                try:
                    snapshot_response = session.post(
                        f"{API_BASE_URL}/api/internal/snapshot",
                        json={
                            "pin_id": pin_id,
                            "full_report_json": new_report
                        },
                        timeout=30
                    )
                except requests.exceptions.Timeout:
                    print(f"  Error: Timeout while saving snapshot for pin {pin_id}", flush=True)
                except requests.exceptions.RequestException as e:
                    print(f"  Error: Request failed while saving snapshot for pin {pin_id}: {str(e)}", flush=True)
                else:
                    if snapshot_response.status_code != 200:
                        print(f"  Error: Failed to save snapshot for pin {pin_id}", flush=True)
                    else:
                        print(f"  Snapshot saved successfully", flush=True)
                
                # Step 2e: Save alerts (IF deltas exist)
                if deltas:
                    print(f"  Found {len(deltas)} changes! Creating alerts...", flush=True)
                    for delta in deltas:
                        try:
                            alert_response = session.post(
                                f"{API_BASE_URL}/api/internal/alert",
                                json={
                                    "pin_id": pin_id,
                                    "delta_data": delta
                                },
                                timeout=30
                            )
                        except requests.exceptions.Timeout:
                            print(f"    Error: Timeout while creating alert for {delta.get('field', 'unknown')}", flush=True)
                            continue
                        except requests.exceptions.RequestException as e:
                            print(f"    Error: Request failed while creating alert: {str(e)}", flush=True)
                            continue
                        else:
                            if alert_response.status_code == 200:
                                print(f"    Alert created: {delta.get('field', 'unknown')}", flush=True)
                            else:
                                print(f"    Error creating alert: {alert_response.status_code}", flush=True)
                else:
                    print(f"  No changes detected", flush=True)
                
                # Small delay between pins to avoid rate limiting
                time.sleep(1)
            
            except Exception as e:
                print(f"  Error processing pin {pin_id}: {str(e)}", flush=True)
                continue
        
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Monitoring cycle completed", flush=True)
    
    except Exception as e:
        print(f"Fatal error in monitoring cycle: {str(e)}", flush=True)


def main():
    """Main entry point for the monitor service"""
    print("TI Analyst's Watchlist - Monitor Service", flush=True)
    print("=" * 50, flush=True)
    print(f"API Base URL: {API_BASE_URL}", flush=True)
    print(f"Starting scheduler (interval: 1 hour)...", flush=True)
    print("=" * 50, flush=True)
    
    # Create scheduler
    scheduler = BlockingScheduler()
    
    # Add job to run every 1 hour
    scheduler.add_job(
        run_monitoring_cycle,
        'interval',
        hours=1,
        id='monitoring_cycle',
        name='Run monitoring cycle',
        replace_existing=True
    )
    
    # Run an initial cycle immediately
    print("Running initial monitoring cycle...", flush=True)
    run_monitoring_cycle()
    
    # Start the scheduler
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        print("\nShutting down monitor service...", flush=True)
        scheduler.shutdown()


if __name__ == "__main__":
    main()
