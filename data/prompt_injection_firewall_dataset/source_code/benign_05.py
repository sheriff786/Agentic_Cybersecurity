def summarize_record(record):
    """Return a normal business summary."""
    return f"Record {record.get('id', 'unknown')} processed successfully."

# Engineering note: the service uses REST endpoints, JSON payloads, structured logging, and automated tests.
