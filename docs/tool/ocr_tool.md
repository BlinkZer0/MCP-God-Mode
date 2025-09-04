# OCR Tool

## Overview
Optical Character Recognition (OCR) tool for extracting text from images, documents, and video frames. Supports multiple languages, handwriting recognition, and various image formats across all platforms.

## Description
Optical Character Recognition (OCR) tool for extracting text from images, documents, and video frames. Supports multiple languages, handwriting recognition, and various image formats across all platforms.

## Input Schema
- **action** (required): OCR action to perform. 'extract_text' for basic text extraction, 'recognize_handwriting' for handwritten text, 'extract_from_pdf' for PDF documents, 'extract_from_video' for video frame text, 'batch_process' for multiple files, 'language_detection' for language identification, 'table_extraction' for tabular data, 'form_processing' for form field extraction.
- **input_file** (required): Path to the input file (image, PDF, video). Examples: './document.jpg', '/home/user/images/receipt.png', 'C:\\Users\\User\\Documents\\form.pdf'.
- **output_file** (optional): Path for the output text file. Examples: './extracted_text.txt', '/home/user/output/ocr_result.txt'. If not specified, auto-generates based on input file.
- **language** (optional): Language for OCR processing. Examples: 'en' for English, 'es' for Spanish, 'fr' for French, 'auto' for automatic detection. Defaults to 'auto'.
- **confidence_threshold** (optional): Minimum confidence threshold for text recognition (0-100). Higher values ensure better accuracy but may miss some text.
- **output_format** (optional): Output format for extracted text. 'text' for plain text, 'json' for structured data, 'xml' for XML format, 'csv' for comma-separated values, 'hocr' for HTML OCR format.
- **preprocess_image** (optional): Whether to preprocess the image for better OCR results. Includes noise reduction, contrast enhancement, and deskewing.
- **extract_tables** (optional): Whether to extract tabular data from the document. Useful for spreadsheets and forms.
- **preserve_layout** (optional): Whether to preserve the original document layout in the output. Useful for maintaining formatting and structure.

## Output Schema
- **success**: Whether the OCR operation was successful.
- **action_performed**: The OCR action that was executed.
- **input_file**: Path to the input file.
- **output_file**: Path to the output text file.
- **extracted_text**: The extracted text content.
- **confidence_score**: Average confidence score of the OCR recognition (0-100).
- **processing_time**: Time taken to process the document in seconds.
- **text_statistics**: Statistics about the extracted text content including total characters, words, lines, detected language, and table count.
- **ocr_metadata**: Metadata about the OCR processing including engine used, image quality, preprocessing steps, and recognition areas.
- **message**: Summary message of the OCR operation.
- **error**: Error message if the operation failed.
- **platform**: Platform where the OCR tool was executed.
- **timestamp**: Timestamp when the operation was performed.

## Natural Language Access
Users can request OCR operations using natural language:
- "Extract text from this image"
- "Read the text from my PDF document"
- "Recognize handwriting in this image"
- "Extract text from video frames"
- "Process multiple documents with OCR"
- "Detect the language in this document"
- "Extract table data from this image"
- "Process form fields from this document"
- "Convert image text to editable text"
- "Extract text while preserving layout"

## Usage Examples

### Basic Text Extraction
```javascript
// Extract text from an image
const result = await ocr_tool({
  action: "extract_text",
  input_file: "./document.jpg",
  language: "en",
  confidence_threshold: 85
});
```

### PDF Text Extraction
```javascript
// Extract text from PDF document
const result = await ocr_tool({
  action: "extract_from_pdf",
  input_file: "./report.pdf",
  output_format: "json",
  preserve_layout: true
});
```

### Handwriting Recognition
```javascript
// Recognize handwritten text
const result = await ocr_tool({
  action: "recognize_handwriting",
  input_file: "./handwritten_notes.jpg",
  language: "en",
  preprocess_image: true
});
```

### Table Extraction
```javascript
// Extract tabular data
const result = await ocr_tool({
  action: "table_extraction",
  input_file: "./spreadsheet.jpg",
  extract_tables: true,
  output_format: "csv"
});
```

### Batch Processing
```javascript
// Process multiple documents
const result = await ocr_tool({
  action: "batch_process",
  input_file: "./documents/",
  language: "auto",
  output_format: "text"
});
```

## Platform Support
- **Windows**: Full support with Tesseract, Windows OCR APIs, and cloud services
- **Linux**: Full support with Tesseract, OpenCV, and cloud OCR APIs
- **macOS**: Full support with Tesseract, Vision framework, and cloud services
- **Android**: Limited support through system APIs and cloud services
- **iOS**: Limited support through Vision framework and cloud services

## OCR Capabilities

### Text Recognition
- Printed text recognition in multiple languages
- Handwritten text recognition
- Mixed content (printed + handwritten)
- Special characters and symbols
- Mathematical notation recognition

### Document Processing
- Image files (JPG, PNG, BMP, TIFF)
- PDF documents
- Multi-page documents
- Scanned documents
- Camera-captured images

### Language Support
- English and major European languages
- Asian languages (Chinese, Japanese, Korean)
- Middle Eastern languages (Arabic, Hebrew)
- Right-to-left language support
- Automatic language detection

### Advanced Features
- Table structure recognition
- Form field extraction
- Layout preservation
- Font recognition
- Confidence scoring

### Output Formats
- Plain text output
- Structured JSON data
- XML format with metadata
- CSV for tabular data
- HOCR for HTML output

## Performance Features
- Multi-threaded processing
- GPU acceleration support
- Batch processing capabilities
- Progress monitoring
- Memory optimization

## Security Features
- File validation and sanitization
- Safe file path handling
- Input file verification
- Output file security checks
- Privacy protection for sensitive documents

## Error Handling
- File format validation
- Image quality assessment
- Language detection errors
- Processing timeout handling
- Detailed error messages

## Related Tools
- `file_ops` - File system operations
- `fs_read_text` - Read text files
- `fs_write_text` - Write text files
- `download_file` - Download documents
- `mobile_hardware` - Mobile camera access
- `video_editing` - Video frame extraction

## Use Cases
- **Document Digitization**: Convert paper documents to digital text
- **Data Entry**: Extract data from forms and receipts
- **Content Accessibility**: Make image text readable for screen readers
- **Research**: Extract text from historical documents
- **Business Process**: Automate invoice and receipt processing
- **Language Learning**: Extract text from foreign language materials
- **Academic Research**: Process research papers and documents
- **Legal Documents**: Extract text from contracts and legal papers
- **Medical Records**: Process medical forms and documents
- **Archival Work**: Digitize historical archives and manuscripts
