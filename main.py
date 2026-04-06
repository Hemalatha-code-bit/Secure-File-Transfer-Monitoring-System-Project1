from monitor import start_monitoring
from report import generate_report

if __name__ == "__main__":
    try:
        start_monitoring()
    finally:
        generate_report()   # ✅ This generates report when you stop
