from flask import session
from datetime import datetime, timedelta
from google.cloud import firestore
from google.oauth2 import service_account
import pdfplumber
from io import BytesIO
import os
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
        
        # Initialize conversions data if it doesn't exist
        if user_data is None:
            user_data = {
                'firstName': '',
                'lastName': '',
                'email': '',
                'createdAt': firestore.SERVER_TIMESTAMP,
                'emailVerified': False,
                'active': False,
                'subscription': {
                    'type': '',
                    'startDate': datetime.now().timestamp(),
                    'endDate': add_days_to_timestamp(datetime.now().timestamp(), 30),
                    'isActive': True
                },
                'conversions': {
                    'remaining_conversions': 1,
                    'conversions_reset_time': add_days_to_timestamp(datetime.now().timestamp(), 30),
                    'conversions_count': 0
                }
            }
            user_ref.set(user_data)
        elif 'conversions' not in user_data:
            user_data['conversions'] = {
                'remaining_conversions': 1,
                'conversions_reset_time': add_days_to_timestamp(datetime.now().timestamp(), 30),
                'conversions_count': 0
            }
            user_ref.set(user_data, merge=True)
            
        return user_data.get('conversions', {
            'remaining_conversions': 1,
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
        # Fallback values matching database structure
        return {
            'remaining_conversions': 1,
            'conversions_reset_time': add_days_to_timestamp(datetime.now().timestamp(), 30),
            'conversions_count': 0
        }
    


def validate_and_process_pdf(file):
    if not file or not file.filename:
        return False, "No file provided", None
    
    if not file.filename.lower().endswith('.pdf'):
        return False, "Please upload a valid PDF file", None
    
    try:
        # Debug: Check initial file type
        print(f"Initial file type: {type(file)}")
        
        # Ensure we're working with bytes
        if hasattr(file, 'read'):
            # Debug: Check if file is seekable
            print(f"File is seekable: {file.seekable()}")
            print(f"Current file position: {file.tell()}")
            
            # Reset file position if needed
            file.seek(0)
            file_bytes = file.read()
            print(f"After read, file_bytes type: {type(file_bytes)}")
        elif isinstance(file, str):
            print(f"File is a path: {file}")
            with open(file, 'rb') as f:
                file_bytes = f.read()
                print(f"After reading from path, file_bytes type: {type(file_bytes)}")
        else:
            print(f"File is neither file-like nor path: {type(file)}")
            file_bytes = file
        
        # Debug: Verify bytes content
        if not isinstance(file_bytes, bytes):
            print(f"Content is not bytes: {type(file_bytes)}")
            print(f"First 100 characters: {str(file_bytes[:100])}")
            return False, "Unable to read file content", None
        
        # Process the PDF using pdfplumber
        with pdfplumber.open(BytesIO(file_bytes)) as pdf:
            tables = []
            for page in pdf.pages:
                page_tables = page.extract_tables()
                if page_tables:
                    tables.extend(page_tables)
            
            if not tables:
                return False, "No tables found in the PDF", None
            
            # Rest of your table processing code...
            
            return True, "PDF processed successfully", csv_output
    
    except Exception as e:
        print(f"Error details: {str(e)}")
        print(f"Error type: {type(e)}")
        return False, f"Error processing PDF: {str(e)}", None
