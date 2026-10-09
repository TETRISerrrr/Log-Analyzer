# Log Analyzer 

Educational cybersecurity project for analyzing system and web logs.

## Features

- Log parsing
- SQLite storage
- Brute-force detection
- Suspicious IP detection
- Repeated error detection
- Statistics
- JSON export
- CSV export
- Event graph

## Tech Stack

- Python
- SQLite
- Matplotlib
# Python Log Analyzer / Mini SIEM


## Usage

### Analyze a log file

```bash
python main.py --log data/sample.log
```

### Generate alerts

```bash
python main.py --log data/sample.log --alerts
```

### Display statistics

```bash
python main.py --log data/sample.log --stats
```

### Export results to JSON

```bash
python main.py --log data/sample.log --export-json exports/report.json
```

### Export results to CSV

```bash
python main.py --log data/sample.log --export-csv exports/report.csv
```

### Generate graphs

```bash
python main.py --log data/sample.log --graph
```

### Clear the database

```bash
python main.py --log data/sample.log --clear-db
```


## Project Structure

```text
log_analyzer_mini_siem/
├── main.py
├── analyzer.py
├── database.py
├── parser.py
├── exporter.py
├── graph.py
├── config.py
├── requirements.txt
├── README.md
└── sample_logs/
    └── auth.log
