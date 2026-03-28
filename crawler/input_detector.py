from bs4 import BeautifulSoup
import json
from datetime import datetime
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crawler.utils import FileUtils
from config import INPUT_FIELDS_DIR

class InputDetector:
    """Detect and store input fields from HTML pages"""
    
    def __init__(self):
        self.input_fields_data = {}
        self.auth_pages_data = []
        self.file_utils = FileUtils()
        
    def detect_inputs(self, soup, url):
        """Detect all input fields on a page"""
        inputs = []
        forms = []
        
        # Find all input tags
        for input_tag in soup.find_all('input'):
            input_info = self._extract_input_info(input_tag, url)
            if input_info:
                inputs.append(input_info)
        
        # Find all forms
        for form in soup.find_all('form'):
            form_info = self._extract_form_info(form, url)
            if form_info:
                forms.append(form_info)
        
        # Check if this is an authentication page
        is_auth_page = self._is_authentication_page(inputs, forms)
        
        page_data = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'inputs': inputs,
            'forms': forms,
            'is_authentication_page': is_auth_page,
            'total_inputs': len(inputs),
            'total_forms': len(forms)
        }
        
        # Store page data
        self.input_fields_data[url] = page_data
        
        # If authentication page, store separately
        if is_auth_page:
            self.auth_pages_data.append(page_data)
            
        return page_data
    
    def _extract_input_info(self, input_tag, url):
        """Extract information from an input tag"""
        input_type = input_tag.get('type', 'text').lower()
        input_name = input_tag.get('name', '')
        input_id = input_tag.get('id', '')
        input_class = input_tag.get('class', [])
        input_placeholder = input_tag.get('placeholder', '')
        input_value = input_tag.get('value', '')
        input_required = input_tag.get('required') is not None
        input_readonly = input_tag.get('readonly') is not None
        
        # Categorize input type
        category = self._categorize_input(input_type, input_name, input_placeholder)
        
        return {
            'type': input_type,
            'category': category,
            'name': input_name,
            'id': input_id,
            'class': input_class,
            'placeholder': input_placeholder,
            'value': input_value,
            'required': input_required,
            'readonly': input_readonly,
            'url': url
        }
    
    def _extract_form_info(self, form, url):
        """Extract information from a form tag"""
        form_method = form.get('method', 'get').lower()
        form_action = form.get('action', '')
        form_id = form.get('id', '')
        form_class = form.get('class', [])
        
        # Get all inputs in the form
        form_inputs = []
        for input_tag in form.find_all('input'):
            input_info = self._extract_input_info(input_tag, url)
            if input_info:
                form_inputs.append(input_info)
        
        # Check if form is for login/registration
        is_login_form = self._is_login_form(form_inputs)
        is_register_form = self._is_register_form(form_inputs)
        
        return {
            'method': form_method,
            'action': form_action,
            'id': form_id,
            'class': form_class,
            'inputs': form_inputs,
            'total_inputs': len(form_inputs),
            'is_login_form': is_login_form,
            'is_register_form': is_register_form,
            'url': url
        }
    
    def _categorize_input(self, input_type, input_name, placeholder):
        """Categorize input field based on its attributes"""
        type_map = {
            'text': 'text',
            'email': 'email',
            'password': 'password',
            'search': 'search',
            'tel': 'phone',
            'number': 'number',
            'date': 'date',
            'checkbox': 'checkbox',
            'radio': 'radio',
            'file': 'file',
            'submit': 'submit',
            'button': 'button',
            'hidden': 'hidden'
        }
        
        if input_type in type_map:
            return type_map[input_type]
        
        # Check by name and placeholder
        name_lower = input_name.lower()
        placeholder_lower = placeholder.lower()
        
        if 'email' in name_lower or 'email' in placeholder_lower:
            return 'email'
        elif 'pass' in name_lower or 'pass' in placeholder_lower:
            return 'password'
        elif 'search' in name_lower or 'search' in placeholder_lower:
            return 'search'
        elif 'user' in name_lower or 'name' in name_lower:
            return 'username'
        
        return 'other'
    
    def _is_authentication_page(self, inputs, forms):
        """Check if page contains authentication elements"""
        has_password = any(inp.get('type') == 'password' for inp in inputs)
        has_login_form = any(form.get('is_login_form', False) for form in forms)
        return has_password or has_login_form
    
    def _is_login_form(self, form_inputs):
        """Check if form is a login form"""
        has_password = any(inp.get('type') == 'password' for inp in form_inputs)
        has_username = any(
            inp.get('category') == 'username' or 
            inp.get('type') == 'email' or
            'user' in inp.get('name', '').lower()
            for inp in form_inputs
        )
        return has_password and has_username
    
    def _is_register_form(self, form_inputs):
        """Check if form is a registration form"""
        has_password = any(inp.get('type') == 'password' for inp in form_inputs)
        has_email = any(inp.get('type') == 'email' for inp in form_inputs)
        has_username = any(inp.get('category') == 'username' for inp in form_inputs)
        input_count = len(form_inputs)
        
        # Registration forms typically have 3+ inputs
        return (has_password and (has_email or has_username) and input_count >= 3)
    
    def save_input_fields(self, domain):
        """Save detected input fields to JSON files"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Save all input fields
        all_fields_file = INPUT_FIELDS_DIR / f'{domain}_all_inputs_{timestamp}.json'
        self.file_utils.save_json(self.input_fields_data, all_fields_file)
        
        # Save authentication pages separately
        if self.auth_pages_data:
            auth_file = INPUT_FIELDS_DIR / f'{domain}_auth_pages_{timestamp}.json'
            self.file_utils.save_json(self.auth_pages_data, auth_file)
        
        # Create summary
        summary = {
            'domain': domain,
            'timestamp': timestamp,
            'total_pages_scanned': len(self.input_fields_data),
            'total_auth_pages': len(self.auth_pages_data),
            'total_inputs_found': sum(page['total_inputs'] for page in self.input_fields_data.values()),
            'total_forms_found': sum(page['total_forms'] for page in self.input_fields_data.values())
        }
        
        summary_file = INPUT_FIELDS_DIR / f'{domain}_summary_{timestamp}.json'
        self.file_utils.save_json(summary, summary_file)
        
        return summary