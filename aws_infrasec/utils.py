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

def create_html_report(profile, region, results):
    """
    Create an HTML report for security scan results.
    
    Args:
        profile: AWS profile used
        region: AWS region scanned
        results: List of security issues [service, resource, issue, severity]
        
    Returns:
        str: HTML formatted report
    """
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Severity color mapping
    severity_colors = {
        'HIGH': '#dc3545',    # Red
        'MEDIUM': '#fd7e14',  # Orange
        'LOW': '#ffc107'      # Yellow
    }
    
    html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS InfraSec Security Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f8f9fa;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
            font-size: 1.1em;
        }}
        .summary {{
            padding: 30px;
            background-color: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }}
        .summary-item {{
            background: white;
            padding: 20px;
            border-radius: 6px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .summary-item h3 {{
            margin: 0 0 10px 0;
            color: #6c757d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .summary-item .value {{
            font-size: 2em;
            font-weight: bold;
            color: #495057;
        }}
        .results {{
            padding: 30px;
        }}
        .results h2 {{
            margin: 0 0 20px 0;
            color: #495057;
            border-bottom: 2px solid #dee2e6;
            padding-bottom: 10px;
        }}
        .table-container {{
            overflow-x: auto;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }}
        th {{
            background-color: #f8f9fa;
            font-weight: 600;
            color: #495057;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }}
        tr:hover {{
            background-color: #f8f9fa;
        }}
        .severity-badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
            color: white;
        }}
        .no-issues {{
            text-align: center;
            padding: 60px 30px;
            color: #28a745;
        }}
        .no-issues h3 {{
            margin: 0 0 10px 0;
            font-size: 1.5em;
        }}
        .footer {{
            padding: 20px 30px;
            background-color: #f8f9fa;
            border-top: 1px solid #dee2e6;
            text-align: center;
            color: #6c757d;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>AWS InfraSec Security Report</h1>
            <p>Comprehensive AWS Security Scan Results</p>
        </div>
        
        <div class="summary">
            <div class="summary-grid">
                <div class="summary-item">
                    <h3>AWS Profile</h3>
                    <div class="value">{profile}</div>
                </div>
                <div class="summary-item">
                    <h3>Region</h3>
                    <div class="value">{region}</div>
                </div>
                <div class="summary-item">
                    <h3>Scan Time</h3>
                    <div class="value">{scan_time}</div>
                </div>
                <div class="summary-item">
                    <h3>Issues Found</h3>
                    <div class="value">{len(results)}</div>
                </div>
            </div>
        </div>
        
        <div class="results">
"""
    
    if results:
        html_template += """
            <h2>Security Issues Detected</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Service</th>
                            <th>Resource</th>
                            <th>Issue</th>
                            <th>Severity</th>
                        </tr>
                    </thead>
                    <tbody>
"""
        
        for result in results:
            service, resource, issue, severity = result
            severity_color = severity_colors.get(severity, '#6c757d')
            html_template += f"""
                        <tr>
                            <td><strong>{service}</strong></td>
                            <td><code>{resource}</code></td>
                            <td>{issue}</td>
                            <td><span class="severity-badge" style="background-color: {severity_color};">{severity}</span></td>
                        </tr>
"""
        
        html_template += """
                    </tbody>
                </table>
            </div>
"""
    else:
        html_template += """
            <div class="no-issues">
                <h3>No Security Issues Found!</h3>
                <p>Your AWS environment appears to be secure based on the configured checks.</p>
            </div>
"""
    
    html_template += f"""
        </div>
        
        <div class="footer">
            <p>Generated by AWS InfraSec v0.1.1 | Report generated on {scan_time}</p>
        </div>
    </div>
</body>
</html>
"""
    
    return html_template.strip()