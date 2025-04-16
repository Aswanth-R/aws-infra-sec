"""
Utility functions for AWS Sentinel
"""
from prettytable import PrettyTable
from datetime import datetime
import json

def create_pretty_table(title, headers, rows):
    """
    Create a prettytable for displaying results.
    
    Args:
        title: Table title
        headers: Column headers
        rows: Row data
        
    Returns:
        PrettyTable: Formatted table
    """
    table = PrettyTable()
    table.title = title
    table.field_names = headers
    for row in rows:
        table.add_row(row)
    table.align = 'l'  # Left-align text
    return table

def import_datetime_for_json():
    """
    Get current datetime in ISO format for JSON output.
    
    Returns:
        str: Current datetime in ISO format
    """
    return datetime.now().isoformat()