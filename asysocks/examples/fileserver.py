#!/usr/bin/env python3
"""
File Download Server Example

This example demonstrates how to create a secure file download server using the 
HTTPServerHandler class. The server allows:
- Listing files in a specified directory
- Downloading individual files
- Protection against directory traversal attacks

Usage:
    python fileserver.py [directory_path] [host] [port]

Example:
    python fileserver.py ./downloads 127.0.0.1 8080
"""

import asyncio
import os
import urllib.parse
import mimetypes
import html
import h11
import tempfile
import re
from pathlib import Path
from asysocks.unicomm.common.target import UniTarget, UniProto
from asysocks.unicomm.protocol.server.http.httpserver import HTTPServerHandler, HTTPServer


class MultipartStreamProcessor:
    """
    Memory-efficient multipart form data processor that handles boundary detection
    across chunk boundaries and streams file data directly to disk.
    """
    
    def __init__(self, boundary_bytes, target_path, max_buffer_size=1024*1024, 
                 max_file_size=500*1024*1024, allowed_extensions=None, max_files_per_request=100, print_cb = None):
        self.boundary_bytes = boundary_bytes
        self.target_path = target_path
        self.max_buffer_size = max_buffer_size
        self.max_file_size = max_file_size
        self.allowed_extensions = allowed_extensions
        self.max_files_per_request = max_files_per_request
        
        # State tracking
        self.buffer = b''
        self.state = 'looking_for_boundary'  # 'looking_for_boundary', 'reading_headers', 'reading_file_data'
        self.current_file_info = None
        self.current_file_handle = None
        self.temp_files = []  # Track for cleanup
        self.completed_files = []
        self.file_count = 0  # Track number of files processed
        
        # Boundary patterns
        self.boundary_with_crlf = b'\r\n' + self.boundary_bytes
        self.end_boundary = self.boundary_bytes + b'--'
        self.print_cb = print_cb

    async def print(self, msg=''):
        if self.print_cb is None:
            return
        await self.print_cb(msg)
        
    async def process_chunk(self, chunk):
        """
        Process a chunk of data, returning any completed file info.
        
        Args:
            chunk (bytes): Raw chunk data
            
        Returns:
            list: List of completed file info dictionaries
        """
        self.buffer += chunk
        completed_files = []
        
        # Prevent buffer from growing too large
        if len(self.buffer) > self.max_buffer_size:
            if self.state == 'reading_file_data':
                # Flush file data to reduce buffer size
                await self._flush_file_data()
            elif len(self.buffer) > self.max_buffer_size * 2:  # Emergency limit
                raise ValueError(f"Buffer size exceeded: {len(self.buffer)} bytes")
        
        while True:
            if self.state == 'looking_for_boundary':
                completed_files.extend(await self._process_boundary_search())
                if self.state == 'looking_for_boundary':
                    break  # No more boundaries found
                    
            elif self.state == 'reading_headers':
                if not await self._process_headers():
                    break  # Need more data
                    
            elif self.state == 'reading_file_data':
                file_info = await self._process_file_data()
                if file_info:
                    completed_files.append(file_info)
                if self.state == 'reading_file_data':
                    break  # Need more data
        
        return completed_files
    
    async def _process_boundary_search(self):
        """Search for boundary markers in the buffer."""
        completed_files = []
        
        # Look for boundary (either at start or with CRLF prefix)
        boundary_pos = self.buffer.find(self.boundary_bytes)
        if boundary_pos == -1:
            # No boundary found, keep reasonable amount of data in buffer
            # Keep the last len(boundary) bytes in case boundary is split
            if len(self.buffer) > len(self.boundary_bytes) * 2:
                # Remove old data but keep potential partial boundary
                keep_size = len(self.boundary_bytes) + 10
                self.buffer = self.buffer[-keep_size:]
            return completed_files
            
        # Found boundary - check if it's an end boundary
        if self.buffer[boundary_pos:boundary_pos + len(self.end_boundary)] == self.end_boundary:
            # End of multipart data
            await self._finalize_current_file()
            if self.current_file_info:
                completed_files.append(self.current_file_info)
                self.current_file_info = None
            return completed_files
            
        # Skip to after the boundary
        boundary_end = boundary_pos + len(self.boundary_bytes)
        self.buffer = self.buffer[boundary_end:]
        
        # Look for CRLF after boundary
        if self.buffer.startswith(b'\r\n'):
            self.buffer = self.buffer[2:]
        elif self.buffer.startswith(b'\n'):
            self.buffer = self.buffer[1:]
            
        self.state = 'reading_headers'
        return completed_files
    
    async def _process_headers(self):
        """Process multipart headers."""
        # Look for double CRLF marking end of headers
        header_end = self.buffer.find(b'\r\n\r\n')
        if header_end == -1:
            # Try just LF (some clients use this)
            header_end = self.buffer.find(b'\n\n')
            if header_end == -1:
                # Check if we have too much header data without end marker
                if len(self.buffer) > 8192:  # 8KB header limit
                    raise ValueError("Multipart headers too long or malformed (missing header terminator)")
                return False  # Need more data
            header_section = self.buffer[:header_end]
            self.buffer = self.buffer[header_end + 2:]
        else:
            header_section = self.buffer[:header_end]
            self.buffer = self.buffer[header_end + 4:]
        
        # Validate header size
        if len(header_section) > 4096:  # 4KB individual header limit
            raise ValueError("Multipart part headers too long")
        
        try:
            # Parse headers
            headers_text = header_section.decode('utf-8', errors='strict')
        except UnicodeDecodeError as e:
            raise ValueError(f"Invalid header encoding: {e}")
            
        filename = self._extract_filename_from_headers(headers_text)
        
        if filename:
            # Finalize previous file if any
            if self.current_file_info:
                await self._finalize_current_file()
                
            # Start new file
            safe_filename = self._sanitize_upload_filename(filename)
            if not safe_filename:
                raise ValueError(f"Invalid or unsafe filename: {filename}")
            await self._start_new_file(safe_filename)
                
        self.state = 'reading_file_data'
        return True
    
    async def _process_file_data(self):
        """Process file data, looking for the next boundary."""
        if not self.current_file_handle:
            # No file to write to, just consume data until boundary
            self.state = 'looking_for_boundary'
            return None
            
        # Look for next boundary in buffer
        next_boundary_pos = self.buffer.find(self.boundary_with_crlf)
        if next_boundary_pos == -1:
            # No boundary found, write most of buffer to file
            # Keep enough data to detect boundary split across chunks
            if len(self.buffer) > len(self.boundary_with_crlf) + 10:
                write_size = len(self.buffer) - len(self.boundary_with_crlf) - 10
                data_to_write = self.buffer[:write_size]
                self.buffer = self.buffer[write_size:]
                
                await self._write_file_data(data_to_write)
            return None
        else:
            # Found boundary - write data before it and finalize file
            data_to_write = self.buffer[:next_boundary_pos]
            self.buffer = self.buffer[next_boundary_pos:]
            
            await self._write_file_data(data_to_write)
            file_info = await self._finalize_current_file()
            
            self.state = 'looking_for_boundary'
            return file_info
    
    def _extract_filename_from_headers(self, headers_text):
        """Extract filename from Content-Disposition header."""
        for line in headers_text.split('\n'):
            line = line.strip()
            if line.lower().startswith('content-disposition:'):
                # Look for filename parameter
                filename_match = re.search(r'filename="([^"]*)"', line, re.IGNORECASE)
                if filename_match:
                    return filename_match.group(1)
                # Also try without quotes
                filename_match = re.search(r'filename=([^;\s]+)', line, re.IGNORECASE)
                if filename_match:
                    return filename_match.group(1)
        return None
    
    def _sanitize_upload_filename(self, filename):
        """
        Sanitize uploaded filename to prevent directory traversal and other attacks.
        """
        if not filename:
            return None
        
        # Remove any path components - only allow base filename
        safe_name = os.path.basename(filename)
        
        # Remove dangerous characters and patterns
        safe_name = re.sub(r'[<>:"|?*]', '_', safe_name)  # Windows dangerous chars
        safe_name = re.sub(r'[^\w\-_\.]', '_', safe_name)  # Only allow word chars, dash, underscore, dot
        safe_name = re.sub(r'\.\.+', '.', safe_name)  # Replace multiple dots with single dot
        safe_name = safe_name.strip('._')  # Remove leading/trailing dots and underscores
        
        # Check for dangerous patterns
        if not safe_name or safe_name in ['.', '..']:
            return None
        
        # Ensure reasonable length
        if len(safe_name) > 255:
            name_part, ext_part = os.path.splitext(safe_name)
            safe_name = name_part[:250] + ext_part[:5]
        
        return safe_name
    
    async def _start_new_file(self, filename):
        """Start writing a new file."""
        # Check file count limit
        if self.file_count >= self.max_files_per_request:
            raise ValueError(f"Too many files in upload (max: {self.max_files_per_request})")
            
        # Check file extension if restrictions are set
        if self.allowed_extensions:
            file_ext = os.path.splitext(filename)[1].lower()
            if file_ext not in self.allowed_extensions:
                raise ValueError(f"File extension '{file_ext}' not allowed. Allowed: {', '.join(self.allowed_extensions)}")
        
        file_path = os.path.join(self.target_path, filename)
        
        # Create temporary file first
        temp_file_path = file_path + '.uploading'
        try:
            self.current_file_handle = open(temp_file_path, 'wb')
            self.temp_files.append(temp_file_path)
        except OSError as e:
            raise OSError(f"Cannot create upload file '{temp_file_path}': {e}")
        except PermissionError as e:
            raise OSError(f"Permission denied creating upload file '{temp_file_path}': {e}")
        
        self.current_file_info = {
            'filename': filename,
            'temp_path': temp_file_path,
            'final_path': file_path,
            'size': 0
        }
        self.file_count += 1
    
    async def _write_file_data(self, data):
        """Write data to current file."""
        if self.current_file_handle and data:
            # Check file size limit before writing
            new_size = self.current_file_info['size'] + len(data)
            if new_size > self.max_file_size:
                raise ValueError(f"File '{self.current_file_info['filename']}' exceeds size limit: {new_size} bytes (max: {self.max_file_size})")
                
            try:
                self.current_file_handle.write(data)
                self.current_file_info['size'] += len(data)
            except OSError as e:
                raise OSError(f"Error writing to file '{self.current_file_info['filename']}': {e}")
            except Exception as e:
                raise OSError(f"Unexpected error writing file '{self.current_file_info['filename']}': {e}")
    
    async def _flush_file_data(self):
        """Flush file data to reduce memory usage."""
        if self.current_file_handle:
            self.current_file_handle.flush()
    
    async def _finalize_current_file(self):
        """Finalize the current file and return its info."""
        if not self.current_file_info:
            return None
            
        if self.current_file_handle:
            self.current_file_handle.close()
            self.current_file_handle = None
            
            # Move from temp location to final location
            temp_path = self.current_file_info['temp_path']
            final_path = self.current_file_info['final_path']
            
            try:
                os.rename(temp_path, final_path)
                if temp_path in self.temp_files:
                    self.temp_files.remove(temp_path)
                    
                file_info = {
                    'filename': self.current_file_info['filename'],
                    'size': self.current_file_info['size'],
                    'path': final_path
                }
                
                await self.print(f"[UPLOAD-SUCCESS] Uploaded: {file_info['filename']} ({file_info['size']:,} bytes)")
                self.completed_files.append(file_info)
                self.current_file_info = None
                
                return file_info
                
            except Exception as e:
                await self.print(f"[UPLOAD-ERROR] Error finalizing file {final_path}: {e}")
                # Clean up temp file
                try:
                    os.unlink(temp_path)
                    if temp_path in self.temp_files:
                        self.temp_files.remove(temp_path)
                except:
                    pass
                    
        self.current_file_info = None
        return None
    
    async def finalize(self):
        """Finalize any remaining data."""
        completed_files = []
        
        # Process any remaining buffer data
        while self.buffer and self.state != 'looking_for_boundary':
            if self.state == 'reading_headers':
                if not await self._process_headers():
                    break
            elif self.state == 'reading_file_data':
                # Treat remaining data as end of file
                if self.current_file_handle and self.buffer:
                    await self._write_file_data(self.buffer)
                    self.buffer = b''
                file_info = await self._finalize_current_file()
                if file_info:
                    completed_files.append(file_info)
                break
        
        return completed_files
    
    async def cleanup(self):
        """Clean up any temporary files."""
        if self.current_file_handle:
            try:
                self.current_file_handle.close()
            except:
                pass
            self.current_file_handle = None
            
        for temp_path in self.temp_files:
            try:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
                    await self.print(f"[UPLOAD-CLEANUP] Removed temp file: {temp_path}")
            except Exception as e:
                await self.print(f"[UPLOAD-CLEANUP] Error removing temp file {temp_path}: {e}")
        
        self.temp_files.clear()


class FileDownloadHandler(HTTPServerHandler):
    """
    HTTP server handler that provides secure file download functionality.
    
    Features:
    - File listing for GET requests without parameters
    - File download for GET requests with 'file' parameter
    - Directory traversal protection
    - MIME type detection
    - HTML directory listing
    """
    
    def __init__(self, download_directory=None, max_upload_size=2*1024*1024*1024, max_file_size=500*1024*1024, 
                 allowed_extensions=None, max_files_per_request=100, print_cb = None):
        """
        Initialize the file download handler.
        
        Args:
            download_directory (str): Directory to serve files from
            max_upload_size (int): Maximum total upload size per request in bytes (default: 2GB)
            max_file_size (int): Maximum individual file size in bytes (default: 500MB)
            allowed_extensions (set): Set of allowed file extensions (None = allow all)
            max_files_per_request (int): Maximum number of files per upload request (default: 100)
        """
        super().__init__()
        self.download_directory = download_directory
        self.max_upload_size = max_upload_size
        self.max_file_size = max_file_size
        self.allowed_extensions = allowed_extensions
        self.max_files_per_request = max_files_per_request
        self.print_cb = print_cb
        
        if self.download_directory:
            # Resolve to absolute path and ensure it exists
            self.download_directory = os.path.abspath(self.download_directory)
            if not os.path.exists(self.download_directory):
                raise ValueError(f"Download directory does not exist: {self.download_directory}")
            if not os.path.isdir(self.download_directory):
                raise ValueError(f"Download path is not a directory: {self.download_directory}")
    
    async def print(self, msg = ''):
        if self.print_cb is None:
            return
        await self.print_cb(msg)
    
    def _sanitize_path(self, path_request):
        """
        Sanitize the requested path to prevent directory traversal attacks while allowing
        safe navigation within the allowed directory tree.
        
        Args:
            path_request (str): The requested file or directory path
            
        Returns:
            str or None: Safe absolute path or None if invalid
        """
        if not self.download_directory:
            return None
            
        if not path_request:
            return self.download_directory  # Return root directory for empty path
            
        # Normalize the path request
        # Replace backslashes with forward slashes for consistency
        normalized_path = path_request.replace('\\', '/')
        
        # Remove any attempts to escape the directory with .. patterns
        # Split into components and filter out dangerous ones
        path_components = []
        for component in normalized_path.split('/'):
            component = component.strip()
            if not component or component == '.':
                continue  # Skip empty and current directory references
            if component == '..':
                continue  # Skip parent directory references entirely
            if any(char in component for char in [':', '*', '?', '"', '<', '>', '|']):
                return None  # Reject dangerous characters
            path_components.append(component)
        
        # Build the safe path
        if not path_components:
            return self.download_directory  # Return root if no valid components
            
        safe_path = self.download_directory
        for component in path_components:
            safe_path = os.path.join(safe_path, component)
        
        safe_path = os.path.abspath(safe_path)
        
        # Ensure the path is within the download directory tree
        try:
            common_path = os.path.commonpath([safe_path, self.download_directory])
            if common_path != self.download_directory:
                return None
        except ValueError:
            # Paths are on different drives (Windows) or other error
            return None
            
        return safe_path
    
    def _generate_directory_list_html(self, current_path=None):
        """
        Generate an HTML page listing files and directories.
        
        Args:
            current_path (str): The current directory path to list
            
        Returns:
            str: HTML content
        """
        if not self.download_directory:
            return "<html><body><h1>File Server</h1><p>No download directory configured.</p></body></html>"
        
        # Use the provided path or default to root
        if current_path is None:
            current_path = self.download_directory
        
        try:
            # Get relative path for display
            if current_path == self.download_directory:
                relative_path = "/"
                display_path = "Root Directory"
            else:
                relative_path = "/" + os.path.relpath(current_path, self.download_directory).replace(os.sep, '/')
                display_path = relative_path
            
            # Collect files and directories
            files = []
            directories = []
            
            for item in os.listdir(current_path):
                item_path = os.path.join(current_path, item)
                if os.path.isfile(item_path):
                    size = os.path.getsize(item_path)
                    files.append((item, size))
                elif os.path.isdir(item_path):
                    directories.append(item)
            
            # Sort alphabetically
            files.sort()
            directories.sort()
            
            escaped_directory = html.escape(current_path)
            escaped_display_path = html.escape(display_path)
            
            # Generate breadcrumb navigation
            breadcrumbs = self._generate_breadcrumbs(relative_path)
            
            # Build enhanced HTML content with modern styling and JavaScript
            html_content = '''<!DOCTYPE html>
<html>
<head>
    <title>📁 File Server - Directory Browser</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        :root {
            --primary: #2563eb;
            --primary-dark: #1d4ed8;
            --primary-light: #3b82f6;
            --secondary: #64748b;
            --secondary-light: #94a3b8;
            --success: #059669;
            --success-light: #10b981;
            --warning: #d97706;
            --warning-light: #f59e0b;
            --background: #f8fafc;
            --surface: #ffffff;
            --surface-2: #f1f5f9;
            --text: #1e293b;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
            background: var(--background);
            color: var(--text);
            min-height: 100vh;
            padding: 20px;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: var(--surface);
            border-radius: 12px;
            box-shadow: var(--shadow);
            overflow: hidden;
            animation: slideIn 0.5s ease-out;
        }
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .header {
            background: var(--primary);
            color: white;
            padding: 32px;
            text-align: center;
        }
        .header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 8px;
        }
        .header p {
            opacity: 0.9;
            font-size: 1.1rem;
        }
        .breadcrumb {
            background: var(--surface-2);
            padding: 16px 32px;
            border-bottom: 1px solid var(--border);
            font-size: 1rem;
            font-weight: 500;
        }
        .content {
            padding: 32px;
        }
        .section {
            margin-bottom: 32px;
            padding: 24px;
            border-radius: 8px;
            border: 1px solid var(--border);
            background: var(--surface);
        }
        .upload-section {
            background: #f0fdf4;
            border: 2px dashed var(--success);
            transition: all 0.3s ease;
        }
        .upload-section:hover {
            background: #ecfdf5;
            border-color: var(--success-light);
        }
        .commands-section {
            background: #fefce8;
            border: 1px solid var(--warning);
        }
        .section h3 {
            color: var(--text);
            margin-bottom: 16px;
            font-weight: 600;
            font-size: 1.25rem;
        }
        .btn {
            background: var(--primary);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.2s ease;
            text-decoration: none;
            display: inline-block;
        }
        .btn:hover {
            background: var(--primary-dark);
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(37, 99, 235, 0.3);
        }
        .btn-upload {
            background: var(--success);
            font-size: 16px;
            padding: 16px 32px;
            border-radius: 8px;
        }
        .btn-upload:hover {
            background: var(--success-light);
            box-shadow: 0 4px 12px rgba(5, 150, 105, 0.3);
        }
        .file-input {
            padding: 12px;
            border: 2px solid var(--border);
            border-radius: 6px;
            width: 100%;
            margin-bottom: 16px;
            transition: border-color 0.2s ease;
            font-size: 14px;
        }
        .file-input:focus {
            border-color: var(--primary);
            outline: none;
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }
        .progress-container {
            display: none;
            margin-top: 16px;
            background: var(--surface-2);
            border-radius: 8px;
            padding: 16px;
        }
        .progress-bar {
            width: 100%;
            height: 8px;
            background: var(--border);
            border-radius: 4px;
            overflow: hidden;
            margin-bottom: 8px;
        }
        .progress-fill {
            height: 100%;
            background: var(--primary);
            width: 0%;
            transition: width 0.3s ease;
            border-radius: 4px;
        }
        .command-box {
            background: #0f172a;
            color: #e2e8f0;
            padding: 16px;
            border-radius: 6px;
            font-family: 'Monaco', 'Menlo', 'Consolas', monospace;
            font-size: 13px;
            margin: 12px 0;
            position: relative;
            overflow-x: auto;
            border: 1px solid #334155;
        }
        .command-box pre {
            margin: 0;
            padding: 0;
            background: transparent;
            color: inherit;
            font-family: inherit;
            font-size: inherit;
            line-height: 1.5;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .copy-btn {
            position: absolute;
            top: 12px;
            right: 12px;
            background: var(--secondary);
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 11px;
            transition: background 0.2s;
        }
        .copy-btn:hover { 
            background: var(--secondary-light); 
        }
        .table-container {
            overflow-x: auto;
            border-radius: 8px;
            border: 1px solid var(--border);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background: var(--surface);
        }
        th {
            background: var(--surface-2);
            color: var(--text);
            padding: 16px;
            text-align: left;
            font-weight: 600;
            font-size: 14px;
            border-bottom: 1px solid var(--border);
        }
        td {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
            transition: background-color 0.2s ease;
        }
        tr:hover td {
            background-color: var(--surface-2);
        }
        .file-link {
            color: var(--primary);
            text-decoration: none;
            font-weight: 500;
            transition: color 0.2s ease;
        }
        .file-link:hover {
            color: var(--primary-dark);
        }
        .stats {
            background: var(--surface-2);
            padding: 24px;
            border-radius: 8px;
            text-align: center;
            margin-top: 24px;
            border: 1px solid var(--border);
        }
        .stats h3 {
            color: var(--text);
            margin-bottom: 20px;
        }
        .stat-item {
            text-align: center;
            margin: 12px;
        }
        .stat-number {
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 4px;
        }
        .stat-label {
            font-size: 14px;
            color: var(--text-muted);
            font-weight: 500;
        }
        .tab-container {
            margin-bottom: 20px;
        }
        .tab-buttons {
            display: flex;
            background: var(--surface-2);
            border-radius: 6px;
            padding: 4px;
            margin-bottom: 16px;
        }
        .tab-btn {
            flex: 1;
            padding: 10px 16px;
            border: none;
            background: transparent;
            cursor: pointer;
            border-radius: 4px;
            transition: all 0.2s ease;
            font-weight: 500;
            font-size: 14px;
            color: var(--text-muted);
        }
        .tab-btn.active {
            background: var(--surface);
            color: var(--text);
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .badge {
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 500;
        }
        .badge-directory {
            background: #dbeafe;
            color: #1e40af;
        }
        .badge-file {
            background: #f3e8ff;
            color: #7c3aed;
        }
        @media (max-width: 768px) {
            .container { margin: 10px; }
            .content { padding: 20px; }
            .header { padding: 24px; }
            .header h1 { font-size: 2rem; }
            .stats > div { flex-direction: column; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="breadcrumb">
            <strong>📍 Current Location:</strong> ''' + breadcrumbs + '''
        </div>
        <div class="content">
'''
            
            # Add parent directory link if not at root
            if current_path != self.download_directory:
                parent_relative = os.path.dirname(relative_path.rstrip('/'))
                if parent_relative == '/':
                    parent_relative = ''
                encoded_parent = urllib.parse.quote(parent_relative)
                html_content += '''            <div class="section">
                <a href="?dir=''' + encoded_parent + '''" class="btn" style="text-decoration: none; display: inline-block;">
                    ⬆️ Back to Parent Directory
                </a>
            </div>
'''
            
            # Add upload form with progress and command examples
            current_dir_encoded = urllib.parse.quote(relative_path.lstrip('/')) if relative_path != '/' else ''
            current_dir_param = f'?dir={current_dir_encoded}' if current_dir_encoded else ''
            server_url = 'http://YOUR_SERVER_IP:8080'  # This would be dynamically set in real deployment
            
            html_content += f'''
            <div class="section upload-section">
                <h3>📤 Upload Files</h3>
                <form id="uploadForm" method="post" enctype="multipart/form-data" action="{current_dir_param}">
                    <input type="file" name="files" multiple accept="*/*" class="file-input" id="fileInput">
                    <button type="submit" class="btn btn-upload">🚀 Upload Files</button>
                    <div class="progress-container" id="progressContainer">
                        <div class="progress-bar">
                            <div class="progress-fill" id="progressFill"></div>
                        </div>
                        <div id="progressText">Uploading... 0%</div>
                    </div>
                </form>
                <div style="margin-top: 15px; font-size: 14px; color: #2d5a27;">
                    💡 Drag and drop files or click to browse. Multiple files supported. Large files streamed efficiently.
                </div>
            </div>

            <div class="section">
                <h3>📂 Directory Contents</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>📋 Name</th>
                                <th>📁 Type</th>
                                <th>📏 Size</th>
                                <th>🕒 Actions</th>
                            </tr>
                        </thead>
                        <tbody>
'''
            
            # Add directories first
            for dirname in directories:
                escaped_dirname = html.escape(dirname)
                # Build the path for the directory
                if relative_path == '/':
                    dir_path = dirname
                else:
                    dir_path = relative_path.lstrip('/') + '/' + dirname
                encoded_dirname = urllib.parse.quote(dir_path)
                html_content += f'''                            <tr>
                                <td><a href="?dir={encoded_dirname}" class="file-link">📁 {escaped_dirname}</a></td>
                                <td><span class="badge badge-directory">Directory</span></td>
                                <td style="text-align: right;">-</td>
                                <td><a href="?dir={encoded_dirname}" class="btn" style="padding: 6px 12px; font-size: 12px; text-decoration: none;">Browse</a></td>
                            </tr>
'''
            
            # Add files
            for filename, size in files:
                escaped_filename = html.escape(filename)
                # Build the path for the file
                if relative_path == '/':
                    file_path = filename
                else:
                    file_path = relative_path.lstrip('/') + '/' + filename
                encoded_filename = urllib.parse.quote(file_path)
                
                # Format file size and get appropriate icon
                size_str = self._format_file_size(size)
                
                # Get file extension for icon
                file_ext = os.path.splitext(filename)[1].lower()
                if file_ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
                    icon = '🖼️'
                elif file_ext in ['.mp4', '.avi', '.mkv', '.mov']:
                    icon = '🎬'
                elif file_ext in ['.mp3', '.wav', '.flac', '.ogg']:
                    icon = '🎵'
                elif file_ext in ['.pdf']:
                    icon = '📕'
                elif file_ext in ['.txt', '.md']:
                    icon = '📄'
                elif file_ext in ['.zip', '.rar', '.7z', '.tar', '.gz']:
                    icon = '📦'
                else:
                    icon = '📄'
                
                html_content += f'''                            <tr>
                                <td><a href="?file={encoded_filename}" class="file-link">{icon} {escaped_filename}</a></td>
                                <td><span class="badge badge-file">File</span></td>
                                <td style="text-align: right;">{size_str}</td>
                                <td><a href="?file={encoded_filename}" class="btn" style="padding: 6px 12px; font-size: 12px; text-decoration: none;">Download</a></td>
                            </tr>
'''
            
            total_items = len(directories) + len(files)
            html_content += f'''                        </tbody>
                    </table>
                </div>
            </div>
            
            <div class="stats">
                <h3>📊 Directory Statistics</h3>
                <div style="display: flex; justify-content: space-around; flex-wrap: wrap; margin-top: 16px;">
                    <div class="stat-item">
                        <div class="stat-number" style="color: var(--success);">{len(directories)}</div>
                        <div class="stat-label">📁 Directories</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number" style="color: var(--primary);">{len(files)}</div>
                        <div class="stat-label">📄 Files</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number" style="color: var(--secondary);">{total_items}</div>
                        <div class="stat-label">📋 Total Items</div>
                    </div>
                </div>
                <div style="margin-top: 16px; font-size: 14px; color: var(--text-muted);">
                    💾 Current path: <code style="background: var(--surface-2); padding: 2px 6px; border-radius: 4px; font-size: 13px;">{escaped_display_path}</code>
                </div>
            </div>

            <div class="section commands-section">
                <h3>💻 Command Line Upload Examples</h3>
                <p style="margin-bottom: 20px; color: var(--text-muted);">Use these commands to upload files from your terminal or scripts.</p>
                <div class="tab-container">
                    <div class="tab-buttons">
                        <button class="tab-btn active" onclick="showTab('curl')">🌐 cURL</button>
                        <button class="tab-btn" onclick="showTab('wget')">📥 wget</button>
                        <button class="tab-btn" onclick="showTab('powershell')">⚡ PowerShell</button>
                        <button class="tab-btn" onclick="showTab('python')">🐍 Python</button>
                    </div>
                    
                    <div id="curl" class="tab-content active">
                        <div class="command-box">
                            <button class="copy-btn" onclick="copyToClipboard('curlCmd')">📋 Copy</button>
                            <pre id="curlCmd"># Upload a single file
curl -X POST -F "files=@/path/to/your/file.txt" "{server_url}/{current_dir_param}"

# Upload multiple files
curl -X POST \\
  -F "files=@file1.txt" \\
  -F "files=@file2.jpg" \\
  -F "files=@file3.pdf" \\
  "{server_url}/{current_dir_param}"</pre>
                        </div>
                        <p><strong>Usage:</strong> Replace <code>/path/to/your/file.txt</code> with your actual file path. Use <code>-F "files=@filename"</code> for each file.</p>
                    </div>
                    
                    <div id="wget" class="tab-content">
                        <div class="command-box">
                            <button class="copy-btn" onclick="copyToClipboard('wgetCmd')">📋 Copy</button>
                            <pre id="wgetCmd"># Create multipart form data (limited support)
echo -e "--boundary123\\r\\nContent-Disposition: form-data; name=\\"files\\"; filename=\\"test.txt\\"\\r\\nContent-Type: text/plain\\r\\n\\r\\nfile content here\\r\\n--boundary123--\\r\\n" | \\
wget --post-data=@- \\
     --header="Content-Type: multipart/form-data; boundary=boundary123" \\
     "{server_url}/{current_dir_param}" -O -</pre>
                        </div>
                        <p><strong>Note:</strong> wget has limited multipart support. <strong>Recommended:</strong> Use cURL for better compatibility and easier syntax.</p>
                    </div>
                    
                    <div id="powershell" class="tab-content">
                        <div class="command-box">
                            <button class="copy-btn" onclick="copyToClipboard('psCmd')">📋 Copy</button>
                            <pre id="psCmd"># Upload a single file
$file = Get-Item "C:\\path\\to\\your\\file.txt"
$form = @{{'files' = $file}}
$response = Invoke-RestMethod -Uri "{server_url}/{current_dir_param}" -Method Post -Form $form
Write-Output $response

# Upload multiple files
$files = Get-ChildItem "C:\\path\\to\\files\\*" -Include *.txt,*.jpg,*.pdf
$form = @{{}}
foreach ($file in $files) {{
    $form.Add("files", $file)
}}
$response = Invoke-RestMethod -Uri "{server_url}/{current_dir_param}" -Method Post -Form $form
Write-Output $response</pre>
                        </div>
                        <p><strong>Usage:</strong> Replace the file paths with your actual Windows file paths. Works with PowerShell 3.0+.</p>
                    </div>
                    
                    <div id="python" class="tab-content">
                        <div class="command-box">
                            <button class="copy-btn" onclick="copyToClipboard('pythonCmd')">📋 Copy</button>
                            <pre id="pythonCmd">#!/usr/bin/env python3
import requests
import os

# Upload a single file
def upload_single_file(file_path):
    url = "{server_url}/{current_dir_param}"
    with open(file_path, 'rb') as f:
        files = {{'files': f}}
        response = requests.post(url, files=files)
        print(f"Status: {{response.status_code}}")
        print(f"Response: {{response.text}}")
        return response

# Upload multiple files
def upload_multiple_files(file_paths):
    url = "{server_url}/{current_dir_param}"
    files = []
    try:
        for file_path in file_paths:
            files.append(('files', open(file_path, 'rb')))
        
        response = requests.post(url, files=files)
        print(f"Status: {{response.status_code}}")
        print(f"Response: {{response.text}}")
        return response
    finally:
        # Close all file handles
        for _, file_handle in files:
            file_handle.close()

# Example usage
if __name__ == "__main__":
    # Single file upload
    upload_single_file("/path/to/your/file.txt")
    
    # Multiple files upload
    file_list = [
        "/path/to/file1.txt",
        "/path/to/file2.jpg",
        "/path/to/file3.pdf"
    ]
    upload_multiple_files(file_list)</pre>
                        </div>
                        <p><strong>Installation:</strong> <code>pip install requests</code><br>
                        <strong>Usage:</strong> Replace file paths with your actual file paths. The script includes proper error handling and file cleanup.</p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Tab switching functionality
        function showTab(tabName) {{
            const contents = document.querySelectorAll('.tab-content');
            contents.forEach(content => content.classList.remove('active'));
            
            const buttons = document.querySelectorAll('.tab-btn');
            buttons.forEach(btn => btn.classList.remove('active'));
            
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
        }}
        
        // Copy to clipboard functionality
        function copyToClipboard(elementId) {{
            const element = document.getElementById(elementId);
            const text = element.textContent;
            
            if (navigator.clipboard) {{
                navigator.clipboard.writeText(text).then(() => {{
                    showCopyFeedback(event.target);
                }});
            }} else {{
                const textArea = document.createElement('textarea');
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                showCopyFeedback(event.target);
            }}
        }}
        
        function showCopyFeedback(button) {{
            const originalText = button.textContent;
            button.textContent = '✅ Copied!';
            button.style.background = '#28a745';
            setTimeout(() => {{
                button.textContent = originalText;
                button.style.background = '#4a5568';
            }}, 2000);
        }}
        
        // Upload progress functionality
        document.getElementById('uploadForm').addEventListener('submit', function(e) {{
            e.preventDefault();
            
            const fileInput = document.getElementById('fileInput');
            const files = fileInput.files;
            
            if (files.length === 0) {{
                alert('Please select files to upload');
                return;
            }}
            
            const formData = new FormData();
            for (let i = 0; i < files.length; i++) {{
                formData.append('files', files[i]);
            }}
            
            const progressContainer = document.getElementById('progressContainer');
            const progressFill = document.getElementById('progressFill');
            const progressText = document.getElementById('progressText');
            
            progressContainer.style.display = 'block';
            
            const xhr = new XMLHttpRequest();
            
            xhr.upload.addEventListener('progress', function(e) {{
                if (e.lengthComputable) {{
                    const percentComplete = (e.loaded / e.total) * 100;
                    progressFill.style.width = percentComplete + '%';
                    progressText.textContent = `Uploading... ${{Math.round(percentComplete)}}% (${{formatBytes(e.loaded)}} / ${{formatBytes(e.total)}})`;
                }}
            }});
            
            xhr.addEventListener('load', function() {{
                if (xhr.status === 200) {{
                    progressText.textContent = 'Upload complete! Redirecting...';
                    setTimeout(() => {{
                        location.reload();
                    }}, 1500);
                }} else {{
                    progressText.textContent = 'Upload failed!';
                    progressFill.style.background = '#ef4444';
                }}
            }});
            
            xhr.addEventListener('error', function() {{
                progressText.textContent = 'Upload error!';
                progressFill.style.background = '#ef4444';
            }});
            
            xhr.open('POST', this.action);
            xhr.send(formData);
        }});
        
        function formatBytes(bytes) {{
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }}
        
        // Drag and drop functionality
        const fileInput = document.getElementById('fileInput');
        const uploadSection = document.querySelector('.upload-section');
        
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {{
            uploadSection.addEventListener(eventName, preventDefaults, false);
        }});
        
        function preventDefaults(e) {{
            e.preventDefault();
            e.stopPropagation();
        }}
        
        ['dragenter', 'dragover'].forEach(eventName => {{
            uploadSection.addEventListener(eventName, highlight, false);
        }});
        
        ['dragleave', 'drop'].forEach(eventName => {{
            uploadSection.addEventListener(eventName, unhighlight, false);
        }});
        
        function highlight(e) {{
            uploadSection.style.background = '#ecfdf5';
            uploadSection.style.borderColor = 'var(--success-light)';
            uploadSection.style.transform = 'scale(1.02)';
        }}
        
        function unhighlight(e) {{
            uploadSection.style.background = '#f0fdf4';
            uploadSection.style.borderColor = 'var(--success)';
            uploadSection.style.transform = 'scale(1)';
        }}
        
        uploadSection.addEventListener('drop', handleDrop, false);
        
        function handleDrop(e) {{
            const dt = e.dataTransfer;
            const files = dt.files;
            fileInput.files = files;
            
            if (files.length > 0) {{
                const fileCount = files.length;
                const totalSize = Array.from(files).reduce((sum, file) => sum + file.size, 0);
                alert(`Ready to upload ${{fileCount}} file(s) (${{formatBytes(totalSize)}} total)`);
            }}
        }}
    </script>
</body>
</html>'''
            
            return html_content
            
        except Exception as e:
            error_msg = str(e)
            return f"<html><body><h1>Error</h1><p>Failed to list directory: {html.escape(error_msg)}</p></body></html>"
    
    def _generate_breadcrumbs(self, relative_path):
        """
        Generate breadcrumb navigation HTML.
        
        Args:
            relative_path (str): The current relative path
            
        Returns:
            str: HTML breadcrumb navigation
        """
        if relative_path == '/':
            return '<a href="?" style="text-decoration: none; color: #0066cc;">🏠 Root</a>'
        
        breadcrumbs = ['<a href="?" style="text-decoration: none; color: #0066cc;">🏠 Root</a>']
        
        # Split path into components
        parts = relative_path.strip('/').split('/')
        current_path = ''
        
        for i, part in enumerate(parts):
            if not part:
                continue
                
            current_path += '/' + part if current_path else part
            encoded_path = urllib.parse.quote(current_path)
            escaped_part = html.escape(part)
            
            if i == len(parts) - 1:
                # Current directory (not a link)
                breadcrumbs.append(f'<span style="color: #333;">📁 {escaped_part}</span>')
            else:
                # Intermediate directory (link)
                breadcrumbs.append(f'<a href="?dir={encoded_path}" style="text-decoration: none; color: #0066cc;">📁 {escaped_part}</a>')
        
        return ' <span style="color: #999;">→</span> '.join(breadcrumbs)
    
    def _get_mime_type(self, filepath):
        """
        Get the MIME type for a file.
        
        Args:
            filepath (str): Path to the file
            
        Returns:
            str: MIME type
        """
        mime_type, _ = mimetypes.guess_type(filepath)
        return mime_type or 'application/octet-stream'
    
    async def do_GET(self, event):
        """
        Handle GET requests for file listing, directory browsing, and downloads.
        
        Args:
            event: The HTTP request event
        """
        try:
            # Parse the URL to get query parameters
            url_parts = urllib.parse.urlparse(event.target.decode('ascii'))
            query_params = urllib.parse.parse_qs(url_parts.query)
            
            # Check what type of request this is
            if 'file' in query_params and query_params['file']:
                # File download request
                file_path = query_params['file'][0]
                await self._serve_file(file_path, event.headers)
            elif 'dir' in query_params:
                # Directory listing request
                dir_path = query_params['dir'][0] if query_params['dir'][0] else ''
                await self._serve_directory_list(dir_path)
            else:
                # Root directory listing (no parameters)
                await self._serve_directory_list('')
                
        except Exception as e:
            await self._serve_error(500, f"Internal Server Error: {str(e)}")
    
    async def do_POST(self, event):
        """
        Handle POST requests for file uploads.
        
        Args:
            event: The HTTP request event
        """
        try:
            # Parse the URL to get query parameters (for target directory)
            url_parts = urllib.parse.urlparse(event.target.decode('ascii'))
            query_params = urllib.parse.parse_qs(url_parts.query)
            
            # Get target directory from query params or default to root
            target_dir = query_params.get('dir', [''])[0]
            
            await self._handle_file_upload(event, target_dir)
                
        except Exception as e:
            await self._serve_error(500, f"Upload Error: {str(e)}")
    
    async def _handle_file_upload(self, event, target_dir=''):
        """
        Handle multipart file upload with memory-efficient streaming.
        
        Args:
            event: The HTTP request event
            target_dir (str): Target directory for upload (relative to download_directory)
        """
        try:
            # Validate and sanitize target directory
            safe_target_path = self._sanitize_path(target_dir)
            if not safe_target_path or not os.path.isdir(safe_target_path):
                await self._serve_error(400, "Invalid target directory")
                return
            
            # Get Content-Type header
            content_type = None
            content_length = None
            for name, value in event.headers:
                if name.lower() == b'content-type':
                    content_type = value.decode('ascii')
                elif name.lower() == b'content-length':
                    content_length = int(value.decode('ascii'))
            
            if not content_type or not content_type.startswith('multipart/form-data'):
                await self._serve_error(400, "Only multipart/form-data uploads are supported")
                return
            
            if not content_length:
                await self._serve_error(400, "Content-Length header required")
                return
            
            # Extract boundary from Content-Type
            boundary_match = re.search(r'boundary=([^;]+)', content_type)
            if not boundary_match:
                await self._serve_error(400, "Missing boundary in Content-Type")
                return
            
            boundary = boundary_match.group(1).strip('"')
            boundary_bytes = f'--{boundary}'.encode('ascii')
            end_boundary_bytes = f'--{boundary}--'.encode('ascii')
            
            # Process the upload with streaming
            await self._process_multipart_upload(safe_target_path, boundary_bytes, end_boundary_bytes, content_length)
            
        except Exception as e:
            await self.print(f"[UPLOAD-ERROR] {e}")
            await self._serve_error(500, f"Upload processing error: {str(e)}")
    
    async def _process_multipart_upload(self, target_path, boundary_bytes, end_boundary_bytes, content_length):
        """
        Process multipart upload data with streaming to avoid memory issues.
        
        Args:
            target_path (str): Safe target directory path
            boundary_bytes (bytes): Multipart boundary
            end_boundary_bytes (bytes): End boundary
            content_length (int): Total content length
        """
        uploaded_files = []
        bytes_processed = 0
        chunk_size = 64 * 1024  # 64KB chunks for better performance
        max_buffer_size = 1024 * 1024  # 1MB max buffer to prevent memory issues
        
        # Validate upload size
        if content_length > self.max_upload_size:
            raise ValueError(f"Upload too large: {content_length} bytes (max: {self.max_upload_size})")
        
        # Initialize the multipart stream processor
        processor = MultipartStreamProcessor(
            boundary_bytes, 
            target_path, 
            max_buffer_size,
            max_file_size=self.max_file_size,
            allowed_extensions=self.allowed_extensions,
            max_files_per_request=self.max_files_per_request,
            print_cb = self.print_cb
        )
        
        try:
            # Read request body in chunks
            while bytes_processed < content_length:
                remaining = content_length - bytes_processed
                read_size = min(chunk_size, remaining)
                
                # Read chunk from wrapper
                chunk = await self._read_upload_chunk(read_size)
                if not chunk:
                    break
                
                bytes_processed += len(chunk)
                
                # Process chunk through streaming processor
                file_infos = await processor.process_chunk(chunk)
                uploaded_files.extend(file_infos)
                
                # Progress logging for large uploads
                if content_length > 10 * 1024 * 1024:  # > 10MB
                    progress = (bytes_processed / content_length) * 100
                    if bytes_processed % (1024 * 1024) == 0:  # Log every MB
                        await self.print(f"[UPLOAD-PROGRESS] {progress:.1f}% ({bytes_processed:,}/{content_length:,} bytes)")
            
            # Finalize any remaining data
            final_files = await processor.finalize()
            uploaded_files.extend(final_files)
            
            # Send success response
            await self._send_upload_success_response(uploaded_files, target_path)
            
        except ValueError as e:
            # Validation errors (file too large, too many files, etc.)
            await self.print(f"[UPLOAD-VALIDATION] {e}")
            await processor.cleanup()
            await self._serve_error(400, f"Upload validation failed: {str(e)}")
        except MemoryError as e:
            await self.print(f"[UPLOAD-MEMORY] Out of memory: {e}")
            await processor.cleanup()
            await self._serve_error(413, "Upload too large - insufficient memory")
        except OSError as e:
            # Disk space, permission issues, etc.
            await self.print(f"[UPLOAD-DISK] Disk error: {e}")
            await processor.cleanup()
            await self._serve_error(507, f"Server storage error: {str(e)}")
        except Exception as e:
            await self.print(f"[UPLOAD-ERROR] Unexpected error: {e}")
            await processor.cleanup()
            await self._serve_error(500, f"Upload processing failed: {str(e)}")
    
    async def _read_upload_chunk(self, size):
        """
        Read a chunk of upload data from the HTTP request with timeout.
        """
        try:
            # Add timeout to prevent hanging on slow/broken connections
            event = await asyncio.wait_for(self._wrapper.next_event(), timeout=30.0)
            
            if isinstance(event, h11.Data):
                return event.data[:size] if event.data else b''
            elif isinstance(event, h11.EndOfMessage):
                return b''  # End of request body
            else:
                await self.print(f"[UPLOAD-ERROR] Unexpected event type: {type(event)}")
                return b''
                
        except asyncio.TimeoutError:
            await self.print("[UPLOAD-ERROR] Timeout reading upload data")
            raise OSError("Upload timeout - connection too slow")
        except ConnectionError as e:
            await self.print(f"[UPLOAD-ERROR] Connection error: {e}")
            raise OSError(f"Upload connection lost: {e}")
        except Exception as e:
            await self.print(f"[UPLOAD-ERROR] Error reading chunk: {e}")
            raise OSError(f"Error reading upload data: {e}")
    
    
    async def _send_upload_success_response(self, uploaded_files, target_path):
        """
        Send a success response after file upload.
        
        Args:
            uploaded_files (list): List of uploaded file info
            target_path (str): Target directory path
        """
        try:
            # Get relative path for redirect
            if target_path == self.download_directory:
                redirect_path = ""
            else:
                redirect_path = os.path.relpath(target_path, self.download_directory).replace(os.sep, '/')
            
            # Create success HTML
            html_content = f'''<!DOCTYPE html>
<html>
<head>
    <title>Upload Successful</title>
    <meta http-equiv="refresh" content="3;url=?dir={urllib.parse.quote(redirect_path)}">
</head>
<body style="font-family: Arial, sans-serif; margin: 40px;">
    <h1>✅ Upload Successful!</h1>
    <p>Successfully uploaded {len(uploaded_files)} file(s):</p>
    <ul>
'''
            
            for file_info in uploaded_files:
                size_str = self._format_file_size(file_info['size'])
                html_content += f'        <li>📄 <strong>{html.escape(file_info["filename"])}</strong> ({size_str})</li>\n'
            
            html_content += '''    </ul>
    <p>Redirecting back to directory listing in 3 seconds...</p>
    <p><a href="?dir=''' + urllib.parse.quote(redirect_path) + '''">Click here if not redirected automatically</a></p>
</body>
</html>'''
            
            body = html_content.encode('utf-8')
            
            headers = self.basic_headers()
            headers.extend([
                ("Content-Type", "text/html; charset=utf-8".encode("ascii")),
                ("Content-Length", str(len(body)).encode("ascii"))
            ])
            
            response = h11.Response(status_code=200, headers=headers)
            await self._wrapper.send(response)
            await self._wrapper.send(h11.Data(data=body))
            await self._wrapper.send(h11.EndOfMessage())
            
        except Exception as e:
            await self.print(f"[UPLOAD-ERROR] Error sending success response: {e}")
            raise
    
    def _format_file_size(self, size):
        """Format file size in human-readable format."""
        if size > 1024 * 1024 * 1024:
            return f"{size / (1024*1024*1024):.1f} GB"
        elif size > 1024 * 1024:
            return f"{size / (1024*1024):.1f} MB"
        elif size > 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size} bytes"
    
    async def _serve_directory_list(self, dir_path=''):
        """
        Serve the HTML directory listing page.
        
        Args:
            dir_path (str): The directory path to list (relative to download_directory)
        """
        try:
            # Sanitize the directory path
            safe_path = self._sanitize_path(dir_path)
            
            if not safe_path:
                await self._serve_error(400, "Invalid directory path")
                return
                
            if not os.path.exists(safe_path):
                await self._serve_error(404, "Directory not found")
                return
                
            if not os.path.isdir(safe_path):
                await self._serve_error(400, "Not a directory")
                return
            
            html_content = self._generate_directory_list_html(safe_path)
            body = html_content.encode('utf-8')
            
            headers = self.basic_headers()
            headers.extend([
                ("Content-Type", "text/html; charset=utf-8".encode("ascii")),
                ("Content-Length", str(len(body)).encode("ascii"))
            ])
            
            response = h11.Response(status_code=200, headers=headers)
            await self._wrapper.send(response)
            await self._wrapper.send(h11.Data(data=body))
            await self._wrapper.send(h11.EndOfMessage())
            
        except Exception as e:
            await self._serve_error(500, f"Error generating directory list: {str(e)}")
    
    async def _serve_file(self, file_path, request_headers=None):
        """
        Serve a specific file for download with support for large files.
        
        Args:
            file_path (str): The requested file path (can include directories)
            request_headers (dict): HTTP request headers for range support
        """
        # Sanitize the path
        safe_path = self._sanitize_path(file_path)
        
        if not safe_path:
            await self._serve_error(400, "Invalid filename")
            return
            
        if not os.path.exists(safe_path):
            await self._serve_error(404, "File not found")
            return
            
        if not os.path.isfile(safe_path):
            await self._serve_error(400, "Not a file")
            return
        
        try:
            # Get file info
            file_size = os.path.getsize(safe_path)
            mime_type = self._get_mime_type(safe_path)
            
            # Check for Range header (for partial content/resumable downloads)
            range_header = None
            if request_headers:
                for name, value in request_headers:
                    if name.lower() == b'range':
                        range_header = value.decode('ascii')
                        break
            
            start_byte = 0
            end_byte = file_size - 1
            status_code = 200
            
            # Parse range request if present
            if range_header and range_header.startswith('bytes='):
                try:
                    range_spec = range_header[6:]  # Remove 'bytes='
                    if '-' in range_spec:
                        start, end = range_spec.split('-', 1)
                        if start:
                            start_byte = int(start)
                        if end:
                            end_byte = int(end)
                        status_code = 206  # Partial Content
                except (ValueError, IndexError):
                    # Invalid range, serve full file
                    pass
            
            content_length = end_byte - start_byte + 1
            
            # Prepare headers
            headers = self.basic_headers()
            headers.extend([
                ("Content-Type", mime_type.encode("ascii")),
                ("Content-Length", str(content_length).encode("ascii")),
                ("Accept-Ranges", b"bytes"),
                ("Content-Disposition", f'attachment; filename="{os.path.basename(safe_path)}"'.encode("ascii"))
            ])
            
            if status_code == 206:
                headers.append(("Content-Range", f"bytes {start_byte}-{end_byte}/{file_size}".encode("ascii")))
            
            # Send response headers
            response = h11.Response(status_code=status_code, headers=headers)
            await self._wrapper.send(response)
            
            # Send file content in chunks (optimized for large files)
            chunk_size = 512 * 1024  # 512KB chunks for better performance on large files
            bytes_sent = 0
            bytes_remaining = content_length
            
            with open(safe_path, 'rb') as f:
                # Seek to start position for range requests
                if start_byte > 0:
                    f.seek(start_byte)
                
                while bytes_remaining > 0:
                    # Read chunk (but not more than remaining bytes)
                    read_size = min(chunk_size, bytes_remaining)
                    chunk = f.read(read_size)
                    
                    if not chunk:
                        break
                    
                    try:
                        await self._wrapper.send(h11.Data(data=chunk))
                        bytes_sent += len(chunk)
                        bytes_remaining -= len(chunk)
                        
                        # Optional: Log progress for very large files (>100MB)
                        if content_length > 100 * 1024 * 1024 and bytes_sent % (10 * 1024 * 1024) == 0:
                            progress = (bytes_sent / content_length) * 100
                            await self.print(f"[FILE-SERVER] Download progress: {progress:.1f}% ({bytes_sent:,}/{content_length:,} bytes)")
                            
                    except Exception as e:
                        await self.print(f"[FILE-SERVER] Error sending chunk at {bytes_sent:,} bytes: {e}")
                        raise
            
            await self._wrapper.send(h11.EndOfMessage())
            
        except Exception as e:
            await self._serve_error(500, f"Error serving file: {str(e)}")
    
    async def _serve_error(self, status_code, message):
        """
        Serve an error response.
        
        Args:
            status_code (int): HTTP status code
            message (str): Error message
        """
        try:
            body = f"<html><body><h1>Error {status_code}</h1><p>{html.escape(message)}</p></body></html>".encode('utf-8')
            
            headers = self.basic_headers()
            headers.extend([
                ("Content-Type", "text/html; charset=utf-8".encode("ascii")),
                ("Content-Length", str(len(body)).encode("ascii"))
            ])
            
            response = h11.Response(status_code=status_code, headers=headers)
            await self._wrapper.send(response)
            await self._wrapper.send(h11.Data(data=body))
            await self._wrapper.send(h11.EndOfMessage())
            
        except Exception as e:
            await self.print(f"Error serving error response: {e}")

async def run_file_server_from_target(target, download_directory=None, log_callback=None, 
                                      max_upload_size=2*1024*1024*1024, max_file_size=500*1024*1024, 
                                      allowed_extensions=None, max_files_per_request=100):
    """
    Run the file download server from a target.
    
    Args:
        target: Server target configuration
        download_directory (str): Directory to serve files from
        log_callback: Logging callback function
        max_upload_size (int): Maximum total upload size per request in bytes (default: 2GB)
        max_file_size (int): Maximum individual file size in bytes (default: 500MB)
        allowed_extensions (set): Set of allowed file extensions (None = allow all)
        max_files_per_request (int): Maximum number of files per upload request (default: 100)
    """
    try:
        handler_factory = lambda: FileDownloadHandler(
            download_directory, 
            max_upload_size=max_upload_size,
            max_file_size=max_file_size,
            allowed_extensions=allowed_extensions,
            max_files_per_request=max_files_per_request
        )
        server = HTTPServer(handler_factory, target, log_callback=log_callback)
        return await server.serve() 
    except Exception as e:
        return None, e

async def run_file_server(download_directory=None, host='127.0.0.1', port=8080, debug=False,
                          max_upload_size=2*1024*1024*1024, max_file_size=500*1024*1024, 
                          allowed_extensions=None, max_files_per_request=100):
    """
    Run the file download server.
    
    Args:
        download_directory (str): Directory to serve files from
        host (str): Host to bind to
        port (int): Port to bind to
        debug (bool): Enable debug logging
        max_upload_size (int): Maximum total upload size per request in bytes (default: 2GB)
        max_file_size (int): Maximum individual file size in bytes (default: 500MB)
        allowed_extensions (set): Set of allowed file extensions (None = allow all)
        max_files_per_request (int): Maximum number of files per upload request (default: 100)
    """
    try:
        log_callback = None
        if debug:
            async def log_callback(msg):
                print(f"[FILE-SERVER] {msg}")

        if download_directory:
            print(f"Starting file server on {host}:{port}")
            print(f"Serving files from: {os.path.abspath(download_directory)}")
        else:
            print(f"Starting file server on {host}:{port} (no download directory)")
        
        if debug:
            print("Debug mode enabled - verbose logging active")
        
        target = UniTarget(host, port, UniProto.SERVER_TCP)
        server_task, err = await run_file_server_from_target(
            target, 
            download_directory=download_directory, 
            log_callback=log_callback,
            max_upload_size=max_upload_size,
            max_file_size=max_file_size,
            allowed_extensions=allowed_extensions,
            max_files_per_request=max_files_per_request
        )
        if err is not None:
            print(f"Server error: {err}")
        await server_task

    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        if server_task is not None:
            server_task.cancel()
        print("Server stopped")


def main():
    """
    Main entry point for the file server.
    """
    import argparse
    import sys
    
    # Create argument parser
    parser = argparse.ArgumentParser(
        description='Asysocks File Server - Secure file upload/download server with web interface',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s                                    # Start server on 127.0.0.1:8080 (no directory)
  %(prog)s /home/user/files                  # Serve files from directory
  %(prog)s /home/user/files --host 0.0.0.0  # Bind to all interfaces
  %(prog)s /home/user/files --port 9000      # Use custom port
  %(prog)s /home/user/files --debug          # Enable debug logging
  %(prog)s --help                           # Show this help message

Features:
  • Modern web interface with drag-and-drop uploads
  • Directory browsing with breadcrumb navigation
  • Real-time upload progress bars
  • Command-line examples (cURL, wget, PowerShell, Python)
  • Secure file handling with directory traversal protection
  • Large file streaming support
        ''')
    
    # Add arguments
    parser.add_argument(
        'directory',
        nargs='?',
        help='Directory to serve files from (optional)'
    )
    parser.add_argument(
        '--host', '-H',
        default='127.0.0.1',
        help='Host to bind to (default: 127.0.0.1)'
    )
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=8080,
        help='Port to bind to (default: 8080)'
    )
    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help='Enable debug logging (shows detailed server activity)'
    )
    parser.add_argument(
        '--max-upload-size',
        type=int,
        default=2*1024*1024*1024,
        help='Maximum total upload size per request in bytes (default: 2GB)'
    )
    parser.add_argument(
        '--max-file-size',
        type=int,
        default=500*1024*1024,
        help='Maximum individual file size in bytes (default: 500MB)'
    )
    parser.add_argument(
        '--max-files',
        type=int,
        default=100,
        help='Maximum number of files per upload request (default: 100)'
    )
    parser.add_argument(
        '--allowed-extensions',
        type=str,
        help='Comma-separated list of allowed file extensions (e.g., ".txt,.jpg,.pdf")'
    )
    parser.add_argument(
        '--version', '-v',
        action='version',
        version='Asysocks File Server 1.0.0'
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Validate download directory if provided
    if args.directory:
        if not os.path.exists(args.directory):
            print(f"Error: Directory '{args.directory}' does not exist")
            sys.exit(1)
        if not os.path.isdir(args.directory):
            print(f"Error: '{args.directory}' is not a directory")
            sys.exit(1)
    
    # Validate port range
    if args.port < 1 or args.port > 65535:
        print(f"Error: Port must be between 1 and 65535, got {args.port}")
        sys.exit(1)
    
    # Validate and parse upload limits
    if args.max_upload_size < 1024:  # At least 1KB
        print(f"Error: max-upload-size must be at least 1024 bytes, got {args.max_upload_size}")
        sys.exit(1)
    
    if args.max_file_size < 1024:  # At least 1KB
        print(f"Error: max-file-size must be at least 1024 bytes, got {args.max_file_size}")
        sys.exit(1)
        
    if args.max_files < 1:
        print(f"Error: max-files must be at least 1, got {args.max_files}")
        sys.exit(1)
    
    # Parse allowed extensions
    allowed_extensions = None
    if args.allowed_extensions:
        allowed_extensions = set()
        for ext in args.allowed_extensions.split(','):
            ext = ext.strip()
            if not ext.startswith('.'):
                ext = '.' + ext
            allowed_extensions.add(ext.lower())
    
    # Show startup info
    print("Asysocks File Server")
    print("=" * 50)
    if args.directory:
        print(f"Directory: {os.path.abspath(args.directory)}")
    else:
        print("Directory: None (upload-only mode)")
    print(f"Address: http://{args.host}:{args.port}")
    if args.debug:
        print("Debug: Enabled")
    print(f"Max upload size: {args.max_upload_size / (1024*1024):.0f} MB")
    print(f"Max file size: {args.max_file_size / (1024*1024):.0f} MB")
    print(f"Max files per request: {args.max_files}")
    if allowed_extensions:
        print(f"Allowed extensions: {', '.join(sorted(allowed_extensions))}")
    else:
        print("Allowed extensions: All")
    print("=" * 50)
    
    # Run the server
    try:
        asyncio.run(run_file_server(
            args.directory, 
            args.host, 
            args.port, 
            args.debug,
            max_upload_size=args.max_upload_size,
            max_file_size=args.max_file_size,
            allowed_extensions=allowed_extensions,
            max_files_per_request=args.max_files
        ))
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Failed to start server: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
