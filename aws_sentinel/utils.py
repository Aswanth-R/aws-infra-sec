"""
Utility functions for AWS Sentinel
"""
from prettytable import PrettyTable

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