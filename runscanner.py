import asyncio
from scan3 import Scanner

if __name__ == "__main__":
    try:
        
        scanner = Scanner(
            target_url="https://www.mdx.ac.uk/",  
            verbose=True,
            output_dir="reports",
            depth=50
        )

        
        asyncio.run(scanner.start_scan())

    except Exception as e:
        import logging
        logging.basicConfig(level=logging.ERROR)
        logger = logging.getLogger("WebSecScanner Runner")
        logger.exception(f"Unhandled error during scan execution: {e}")
