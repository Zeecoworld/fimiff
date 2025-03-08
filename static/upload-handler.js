class UploadHandler {
    constructor() {
        // Initialize all DOM elements in constructor
        this.dropZone = document.getElementById('dropZone');
        this.fileInput = document.getElementById('pdf_file');
        this.fileNameSpan = document.getElementById('fileName');
        this.progressContainer = document.getElementById('progressContainer');
        this.progress = document.getElementById('uploadProgress');
        this.uploadForm = document.getElementById('uploadForm');
        this.statusMessage = document.getElementById('status-message');
        
        // Verify all elements exist
        this.validateElements();
        
        this.initializeEventListeners();
    }

    validateElements() {
        const requiredElements = [
            'dropZone', 'fileInput', 'fileNameSpan', 'progressContainer',
            'progress', 'uploadForm', 'statusMessage'
        ];
        
        requiredElements.forEach(element => {
            if (!this[element]) {
                console.error(`Required element ${element} not found`);
            }
        });
    }

    initializeEventListeners() {
        // Add change event listener to file input
        this.fileInput.addEventListener('change', this.handleFileSelect.bind(this));
        
        // Enable drag and drop
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            this.dropZone.addEventListener(eventName, this.preventDefaults.bind(this));
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            this.dropZone.addEventListener(eventName, this.highlight.bind(this));
        });

        ['dragleave', 'drop'].forEach(eventName => {
            this.dropZone.addEventListener(eventName, this.unhighlight.bind(this));
        });

        this.dropZone.addEventListener('drop', this.handleDrop.bind(this));
    }

    async handleFileSelect(e) {
        const file = this.fileInput.files[0];
        if (!file) return;

        // Clear previous status
        this.statusMessage.textContent = '';
        this.statusMessage.classList.remove('error', 'success');

        // Validate file type
        if (!file.name.toLowerCase().endsWith('.pdf')) {
            this.statusMessage.textContent = 'Please upload a PDF file.';
            this.statusMessage.classList.add('error');
            return;
        }

        // Update UI
        this.fileNameSpan.textContent = file.name;
        this.progress.style.width = '0%';
        this.progressContainer.style.display = 'block';
        this.statusMessage.textContent = 'Processing file...';

        try {
            // Create FormData for the file
            const formData = new FormData();
            formData.append('pdf_file', file);
            
            // Get CSRF token from a hidden input field in the form
            const csrfToken = document.querySelector('input[name="csrf_token"]').value;
            
            // Send the file to the conversion endpoint
            const response = await fetch('/convert', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-CSRFToken': csrfToken
                }
            });
            // Debug the response
            console.log('Response status:', response.status);
            console.log('Response headers:', response.headers);

            // Try to get the response as text first
            const responseText = await response.text();
            console.log('Response text:', responseText);

            // Now we need to handle this differently since we've already consumed the response
            if (!response.ok) {
                throw new Error(`Conversion failed (${response.status}): ${responseText.substring(0, 100)}...`);
            }

            // For success case, we need to create a new blob from the text
            const blob = new Blob([responseText], {type: 'text/csv'});
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = 'bankstatementconverter.csv';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);

            // Update progress bar and status
            this.progress.style.width = '100%';
            this.statusMessage.textContent = 'File processed successfully!';
            this.statusMessage.classList.add('success');

            // Reset form after success
            setTimeout(() => {
                this.uploadForm.reset();
                this.fileNameSpan.textContent = 'No file selected';
                this.progressContainer.style.display = 'none';
            }, 2000);

        } catch(error) {
            console.error('Error:', error);
            this.progress.style.width = '0%';
            
            // Reset form after error
            setTimeout(() => {
                this.uploadForm.reset();
                this.fileNameSpan.textContent = 'No file selected';
                this.progressContainer.style.display = 'none';
            }, 3000);
        
            // Display error message
            this.statusMessage.textContent = error.message || 'An unexpected error occurred';
            this.statusMessage.classList.add('error');
        }
    }

    preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    highlight(e) {
        this.dropZone.classList.add('dragover');
    }

    unhighlight(e) {
        this.dropZone.classList.remove('dragover');
    }

    handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0) {
            const file = files[0];
            if (!file.name.toLowerCase().endsWith('.pdf')) {
                this.statusMessage.textContent = 'Please upload a PDF file.';
                this.statusMessage.classList.add('error');
                return;
            }
            this.fileInput.files = dt.files;
            this.handleFileSelect(e);
        }
    }
}

// Initialize the upload handler when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new UploadHandler();
});
