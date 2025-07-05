from flask import session
from datetime import datetime, timedelta
from google.cloud import firestore
from google.oauth2 import service_account
import pdfplumber
from io import BytesIO
import io
import os
import json
import csv



if os.getenv('ENVIRONMENT') == 'development':
    db = firestore.Client.from_service_account_json('./serviceAccountKey.json')
else:
    service_account_info = {
        "type": os.getenv('type'),
        "project_id": os.getenv('project_id'),
        "private_key_id": os.getenv('private_key_id'),
        "private_key": os.getenv('private_key').replace('\\n', '\n'),
        "client_email": os.getenv('client_email'),
        "client_id": os.getenv('client_id'),
        "auth_uri": os.getenv('auth_uri'),
        "token_uri": os.getenv('token_uri'),
        "auth_provider_x509_cert_url": os.getenv('auth_provider_x509_cert_url'),
        "client_x509_cert_url": os.getenv('client_x509_cert_url'),
        "universe_domain": os.getenv('universe_domain')
    }

    credentials = service_account.Credentials.from_service_account_info(service_account_info)

    db = firestore.Client(credentials=credentials)


def add_days_to_timestamp(timestamp=None, days=30):
    """Fixed version that returns string instead of timestamp float"""
    dt = datetime.fromtimestamp(timestamp) if timestamp is not None else datetime.now()
    future_dt = dt + timedelta(days=days)
    # Return as ISO string instead of timestamp to avoid Firestore issues
    return future_dt.isoformat()


def get_user_conversions():
    """Retrieve user's conversion data from database."""
    if 'user_id' in session:
        user_ref = db.collection('users').document(session['user_id'])
        user_doc = user_ref.get()
        if user_doc.exists:
            user_data = user_doc.to_dict()
            plan = user_data.get('subscription', {}).get('plan')
            
            if 'conversions' not in user_data:
                # Use ISO string for reset time instead of timestamp
                reset_time = (datetime.now() + timedelta(days=30)).isoformat()
                user_data['conversions'] = {
                    'remaining_conversions': 1,  
                    'conversions_reset_time': reset_time,
                    'conversions_count': 2
                }
                user_ref.set(user_data, merge=True)
                
            return user_data.get('conversions', {
                'remaining_conversions': 50 if plan == "premium" else 1,
                'conversions_reset_time': (datetime.now() + timedelta(days=30)).isoformat(),
                'conversions_count': 0
            })
    
    return {
        'remaining_conversions': 1,
        'conversions_reset_time': (datetime.now() + timedelta(days=30)).isoformat(),
        'conversions_count': 0
    }


def update_user_conversions(conversions):
    """Update user's conversion data in database and session."""
    if 'user_id' in session:
        user_ref = db.collection('users').document(session['user_id'])
        user_ref.set({
            'conversions': {
                'remaining_conversions': conversions['remaining_conversions'],
                'conversions_reset_time': conversions['conversions_reset_time'],
                'conversions_count': conversions['conversions_count']
            }
        }, merge=True)
    session['conversions'] = conversions


def get_conversion_context():
    """Prepare conversion data for template rendering."""
    try:
        user_conversions = get_user_conversions()
        remaining_conversions = user_conversions['remaining_conversions']
        reset_time = user_conversions['conversions_reset_time']
        conversions_count = user_conversions['conversions_count']
        
        return {
            'remaining_conversions': remaining_conversions,
            'conversions_reset_time': reset_time,
            'conversions_count': conversions_count
        }
    except Exception as e:
        reset_time = (datetime.now() + timedelta(days=30)).isoformat()
        return {
            'remaining_conversions': 1,
            'conversions_reset_time': reset_time,
            'conversions_count': 0
        }
    


def validate_and_process_pdf(file):
    if not file or not hasattr(file, 'filename'):
        return False, "No file provided", None
    
    if not file.filename.lower().endswith('.pdf'):
        return False, "Please upload a valid PDF file", None
    
    try:
        # Read the file content and create a fresh BytesIO object
        file_content = BytesIO(file.read())
        file_content.seek(0)
        
        # Process the PDF using pdfplumber with optimization
        with pdfplumber.open(file_content) as pdf:
            # Check page count restrictions
            page_count = len(pdf.pages)
            
            # Get user's subscription status
            subscription_status = 'free'  # Default value
            if 'user_id' in session:
                try:
                    user_ref = db.collection('users').document(session['user_id'])
                    user_doc = user_ref.get()
                    if user_doc.exists:
                        user_data = user_doc.to_dict()
                        subscription_status = user_data.get('subscription', {}).get('status', 'free')
                except Exception as e:
                    print(f"Error getting user subscription: {e}")
                    subscription_status = 'free'
            
            # Check page count limits
            if subscription_status == 'free' and page_count > 15:
                return False, "Free users are limited to 15 pages per PDF", None
            elif subscription_status == 'premium' and page_count > 50:
                return False, "Premium users are limited to 50 pages per PDF", None
            
            # Check daily limits for premium users
            if subscription_status == 'premium' and 'user_id' in session:
                try:
                    # Get today's date as STRING (not date object)
                    today = datetime.now().strftime('%Y-%m-%d')
                    
                    # Check daily usage
                    daily_usage_ref = db.collection('daily_usage').document(f"{session['user_id']}-{today}")
                    daily_usage_doc = daily_usage_ref.get()
                    
                    # Safely get existing usage
                    current_pages_used = 0
                    if daily_usage_doc.exists:
                        daily_usage_data = daily_usage_doc.to_dict()
                        if daily_usage_data:
                            pages_used_value = daily_usage_data.get('pages_used', 0)
                            # Ensure it's an integer
                            current_pages_used = int(pages_used_value) if isinstance(pages_used_value, (int, float)) else 0
                    
                    if current_pages_used + page_count > 50:
                        return False, f"Daily page limit exceeded. You have used {current_pages_used}/50 pages today.", None
                    
                    # Update daily usage - Store only simple data types
                    update_data = {
                        'user_id': str(session['user_id']),  # Ensure it's a string
                        'date': today,  # Already a string
                        'pages_used': int(current_pages_used + page_count)  # Ensure it's an integer
                    }
                    
                    daily_usage_ref.set(update_data, merge=True)
                    
                except Exception as e:
                    print(f"Error in daily usage tracking: {e}")
                    import traceback
                    print(f"Full traceback: {traceback.format_exc()}")
                    pass
            
            # Process tables with optimization and timeout protection
            tables = []
            max_pages_to_process = min(page_count, 20)  # Limit processing to avoid timeouts
            
            for i, page in enumerate(pdf.pages[:max_pages_to_process]):
                try:
                    # Use simplified table extraction settings for better performance
                    table_settings = {
                        "vertical_strategy": "lines",
                        "horizontal_strategy": "lines",
                        "intersection_tolerance": 3,
                        "text_tolerance": 3,
                        "min_words_vertical": 1,
                        "min_words_horizontal": 1,
                        "snap_tolerance": 3,
                        "snap_x_tolerance": 3,
                        "snap_y_tolerance": 3,
                        "join_tolerance": 3,
                        "edge_min_length": 3,
                        "intersection_x_tolerance": 3,
                        "intersection_y_tolerance": 3
                    }
                    
                    # Extract tables with timeout protection
                    page_tables = page.extract_tables(table_settings)
                    
                    if page_tables:
                        tables.extend(page_tables)
                        
                    # If we found tables and have processed at least 5 pages, consider stopping
                    # to prevent timeout on large documents
                    if tables and i >= 4:  # 0-indexed, so this means 5 pages
                        break
                        
                except Exception as e:
                    print(f"Error processing page {i+1}: {e}")
                    continue
            
            if not tables:
                return False, "No tables found in the PDF", None
            
            # Clean and merge tables with optimization
            headers = []
            all_rows = []
            
            for table_idx, table in enumerate(tables):
                if not table:
                    continue
                
                # Limit table processing to prevent timeouts
                if table_idx > 10:  # Don't process more than 10 tables
                    break
                    
                cleaned_table = []
                for row in table:
                    cleaned_row = [str(cell).strip() if cell is not None else "" for cell in row]
                    cleaned_table.append(cleaned_row)
                
                if not headers and cleaned_table:
                    headers = cleaned_table[0]
                    all_rows.extend(cleaned_table[1:])
                else:
                    for row in cleaned_table:
                        if len(headers) > 0:
                            # Skip empty rows
                            if all(cell == "" for cell in row):
                                continue
                            # Skip header-like rows
                            if any(h.lower() in cell.lower() for h, cell in zip(headers, row) if h and cell):
                                continue
                            # Normalize row length
                            if len(row) < len(headers):
                                row.extend([""] * (len(headers) - len(row)))
                            elif len(row) > len(headers):
                                row = row[:len(headers)]
                            all_rows.append(row)
            
            # Create a StringIO object for the CSV output, not BytesIO
            csv_output = io.StringIO()
            writer = csv.writer(csv_output)
            
            # Write the merged data to CSV
            if headers:
                writer.writerow(headers)
            writer.writerows(all_rows)
            
            # Convert to BytesIO for returning as a file
            csv_bytes = BytesIO()
            csv_bytes.write(csv_output.getvalue().encode('utf-8'))
            csv_bytes.seek(0)
            return True, "PDF processed successfully", csv_bytes
    
    except Exception as e:
        print(f"Error processing PDF: {e}")
        import traceback
        print(f"Full traceback: {traceback.format_exc()}")
        return False, f"Error processing PDF: {str(e)}", None
    


def validate_and_process_json(file):
    if not file or not hasattr(file, 'filename'):
        return False, "No file provided", None
    
    if not file.filename.lower().endswith('.pdf'):
        return False, "Please upload a valid PDF file", None
    
    try:
        # Read the file content and create a fresh BytesIO object
        file_content = BytesIO(file.read())
        file_content.seek(0)
        
        # Process the PDF using pdfplumber
        with pdfplumber.open(file_content) as pdf:
            tables = []
            for page in pdf.pages:
                page_tables = page.extract_tables()
                if page_tables:
                    tables.extend(page_tables)
            
            if not tables:
                return False, "No tables found in the PDF", None
            
            # Clean and merge tables
            headers = []
            all_rows = []
            
            for table in tables:
                if not table:
                    continue
                
                # Clean the table data
                cleaned_table = []
                for row in table:
                    cleaned_row = [str(cell).strip() if cell is not None else "" for cell in row]
                    cleaned_table.append(cleaned_row)
                
                # For the first non-empty table, use its headers
                if not headers and cleaned_table:
                    headers = cleaned_table[0]
                    all_rows.extend(cleaned_table[1:])
                else:
                    # For subsequent tables, add all rows if they match the header count
                    for row in cleaned_table:
                        if len(headers) > 0:
                            if all(cell == "" for cell in row):
                                continue
                            
                            if any(h.lower() in cell.lower() for h, cell in zip(headers, row) if h and cell):
                                continue
                            
                            if len(row) < len(headers):
                                row.extend([""] * (len(headers) - len(row)))
                            elif len(row) > len(headers):
                                row = row[:len(headers)]
                            
                            all_rows.append(row)
            
            # Convert to JSON format
            json_data = {
                'headers': headers,
                'rows': all_rows
            }
            json_bytes = BytesIO()
            json_bytes.write(json.dumps(json_data, indent=2).encode('utf-8'))
            json_bytes.seek(0)
            
            return True, "PDF processed successfully", json_bytes
    
    except Exception as e:
        return False, f"Error processing PDF: {str(e)}", None
