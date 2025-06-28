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
    dt = datetime.fromtimestamp(timestamp) if timestamp is not None else datetime.now()
    future_dt = dt + timedelta(days=days)
    return future_dt.timestamp()


def get_user_conversions():
    """Retrieve user's conversion data from database."""
    if 'user_id' in session:
        user_ref = db.collection('users').document(session['user_id'])
        user_data = user_ref.get().to_dict()
        plan = user_data.get('subscription', {}).get('plan') #plan == "premium"
        if 'conversions' not in user_data:
            user_data['conversions'] = {
                'remaining_conversions': 1,  
                'conversions_reset_time': add_days_to_timestamp(datetime.now().timestamp(), 30),
                'conversions_count': 0
            }
            user_ref.set(user_data, merge=True)
            
        return user_data.get('conversions', {
            'remaining_conversions': 50 if plan == "premium" else 1,
            'conversions_reset_time': add_days_to_timestamp(datetime.now().timestamp(), 30),
            'conversions_count': 0
        })
    
    return {
        'remaining_conversions': 1,
        'conversions_reset_time': add_days_to_timestamp(datetime.now().timestamp(), 30),
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
        return {
            'remaining_conversions': 1,
            'conversions_reset_time': add_days_to_timestamp(datetime.now().timestamp(), 30),
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
        
        # Process the PDF using pdfplumber
        with pdfplumber.open(file_content) as pdf:
            # Check page count restrictions
            page_count = len(pdf.pages)
            
            # Get user's subscription status
            subscription_status = 'free'  # Default
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
            if subscription_status == 'free' and page_count > 10:
                return False, "Free users are limited to 10 pages per PDF", None
            elif subscription_status == 'premium' and page_count > 50:
                return False, "Premium users are limited to 50 pages per PDF", None
            
            # Check daily limits for premium users - ONLY if user is logged in
            if subscription_status == 'premium' and 'user_id' in session:
                try:
                    # Get today's date as string in YYYY-MM-DD format
                    today = datetime.now().strftime('%Y-%m-%d')
                    
                    # Check daily usage
                    daily_usage_ref = db.collection('daily_usage').document(f"{session['user_id']}-{today}")
                    daily_usage_doc = daily_usage_ref.get()
                    
                    current_pages_used = 0
                    if daily_usage_doc.exists:
                        daily_usage_data = daily_usage_doc.to_dict()
                        # Safely get pages_used and ensure it's an integer
                        pages_used_value = daily_usage_data.get('pages_used', 0)
                        if isinstance(pages_used_value, (int, float)):
                            current_pages_used = int(pages_used_value)
                        else:
                            current_pages_used = 0
                    
                    if current_pages_used + page_count > 50:
                        return False, f"Daily page limit exceeded. You have used {current_pages_used}/50 pages today.", None
                    
                    # Update daily usage - Multiple fallback approaches for timestamp
                    update_data = {
                        'user_id': session['user_id'],
                        'date': today,
                        'pages_used': current_pages_used + page_count
                    }
                    
                    # Try different timestamp approaches
                    try:
                        # Approach 1: Try SERVER_TIMESTAMP
                        from firebase_admin import firestore
                        update_data['updated_at'] = firestore.SERVER_TIMESTAMP
                    except (ImportError, AttributeError):
                        try:
                            # Approach 2: Try google.cloud.firestore SERVER_TIMESTAMP
                            from google.cloud.firestore import SERVER_TIMESTAMP
                            update_data['updated_at'] = SERVER_TIMESTAMP
                        except (ImportError, AttributeError):
                            try:
                                # Approach 3: Try Timestamp.now()
                                from google.cloud.firestore import Timestamp
                                update_data['updated_at'] = Timestamp.now()
                            except (ImportError, AttributeError):
                                # Approach 4: Use ISO string as fallback
                                update_data['updated_at'] = datetime.now().isoformat()
                    
                    # Perform the database update
                    daily_usage_ref.set(update_data, merge=True)
                    
                except Exception as e:
                    print(f"Error updating daily usage: {e}")
                    # For debugging - log the full error details
                    import traceback
                    print(f"Full traceback: {traceback.format_exc()}")
                    # Continue processing even if usage tracking fails - don't block the user
                    pass
            
            # Process tables
            tables = []
            for page_num, page in enumerate(pdf.pages):
                try:
                    page_tables = page.extract_tables()
                    if page_tables:
                        tables.extend(page_tables)
                except Exception as e:
                    print(f"Error extracting tables from page {page_num + 1}: {e}")
                    continue
            
            if not tables:
                return False, "No tables found in the PDF", None
            
            # Clean and merge tables
            headers = []
            all_rows = []
            
            for table_num, table in enumerate(tables):
                if not table:
                    continue
                
                try:
                    cleaned_table = []
                    for row in table:
                        # Handle None values and convert to string
                        cleaned_row = []
                        for cell in row:
                            if cell is None:
                                cleaned_row.append("")
                            else:
                                # Strip whitespace and convert to string
                                cell_str = str(cell).strip()
                                cleaned_row.append(cell_str)
                        cleaned_table.append(cleaned_row)
                    
                    # Set headers from first table's first row
                    if not headers and cleaned_table:
                        headers = cleaned_table[0]
                        # Add remaining rows from first table
                        if len(cleaned_table) > 1:
                            all_rows.extend(cleaned_table[1:])
                    else:
                        # Process subsequent tables
                        for row in cleaned_table:
                            # Skip empty rows
                            if all(cell == "" for cell in row):
                                continue
                            
                            # Skip header-like rows (contain header text)
                            if len(headers) > 0:
                                is_header_row = False
                                for i, (header, cell) in enumerate(zip(headers, row)):
                                    if header and cell and header.lower() in cell.lower():
                                        is_header_row = True
                                        break
                                
                                if is_header_row:
                                    continue
                            
                            # Normalize row length to match headers
                            if len(headers) > 0:
                                if len(row) < len(headers):
                                    row.extend([""] * (len(headers) - len(row)))
                                elif len(row) > len(headers):
                                    row = row[:len(headers)]
                            
                            all_rows.append(row)
                            
                except Exception as e:
                    print(f"Error processing table {table_num + 1}: {e}")
                    continue
            
            # Create CSV output
            try:
                csv_output = io.StringIO()
                writer = csv.writer(csv_output)
                
                # Write headers if available
                if headers:
                    writer.writerow(headers)
                
                # Write data rows
                writer.writerows(all_rows)
                
                # Convert to BytesIO for file download
                csv_bytes = BytesIO()
                csv_bytes.write(csv_output.getvalue().encode('utf-8'))
                csv_bytes.seek(0)
                
                return True, "PDF processed successfully", csv_bytes
                
            except Exception as e:
                return False, f"Error creating CSV: {str(e)}", None
    
    except Exception as e:
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
