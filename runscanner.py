import asyncio
from scan3 import Scanner

if __name__ == "__main__":
    try:
        # Initialize the scanner with default or custom parameters
        scanner = Scanner(
            target_url="www.dupe.com",  # Replace with the actual target URL
            verbose=True,
            output_dir="reports"
        )

        # Run the scanner asynchronously
        asyncio.run(scanner.start_scan())

    except Exception as e:
        import logging
        logging.basicConfig(level=logging.ERROR)
        logger = logging.getLogger("WebSecScanner Runner")
        logger.exception(f"Unhandled error during scan execution: {e}")
