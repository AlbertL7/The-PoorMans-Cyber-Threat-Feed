import re
import tkinter as tk
import tkinter.filedialog
import tkinter.simpledialog
import tkinter.messagebox
import os
from tkinter import scrolledtext

regexes = {
    'ipv4': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), #catch IPv4 without defang
    'IPv4': re.compile(r'(?:\d{1,3}\[\.\]|\d{1,3}\.)(?:\d{1,3}\[\.\]|\d{1,3}\.)(?:\d{1,3}\[\.\]|\d{1,3}\.)\d{1,3}'), #catch all defanged IPv4
    'url': re.compile(r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'), #catch url without defang
    'Domains': re.compile(r'(?:[a-zA-Z\-]+[0-9]*\[\.\])+[a-zA-Z\-]+[0-9]*'), #catch all defanged domains
    'URLs': re.compile(r'(?i)(hxxps?:\/\/(?:\[[^\]]+\]|\w+|\[\.\])+(?:\.\w+|\[\.\]\w+)*(?:\/[^\s]*)?)|((?:hxxps?://)?(?:[a-zA-Z0-9-]+\[\.\])+[a-zA-Z]+(?:/[^\s]*)?)'),  #catch all defanged URL's
    'defanged ip in url': re.compile(r'hxxps?:\/\/(?:\d{1,3}\.|\[\.\])?(?:\d{1,3}\.|\[\.\])?(?:\d{1,3}\.|\[\.\])?\d{1,3}(?:\[\.\]\d{1,3})?\/\d+\/[a-f0-9]+'), #catch all defanged ip addresses present in URL's
    'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'), # catch all md5 hashes
    'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'), # catch all sha1 hashes
    'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'), #catch all sha256 hashes
    'CVEs': re.compile(r'(?:CVE-\d{4}-\d{4,}|CVE [\[\(]\d{4}-\d{4,}[\]\)])'), #catch all mentioned CVE's
}

class IOCExtractor(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IOC Extractor")
        self.geometry("1600x800")  # Adjusted the geometry to accommodate the new widget
        
        self.article_input = scrolledtext.ScrolledText(self, wrap=tk.WORD, height=10)
        self.article_input.pack(expand=1, fill='both')
        
        # Added a new ScrolledText widget for reviewing the extracted IOCs
        self.review_output = scrolledtext.ScrolledText(self, wrap=tk.WORD, height=10, bg='light yellow')
        self.review_output.pack(expand=1, fill='both')
        self.review_output.insert(tk.END, "Extracted IOCs will be displayed here...")
        self.review_output.configure(state='disabled')  # Make it read-only
        
        self.parse_button = tk.Button(self, text="Parse IOCs", command=self.parse_iocs)
        self.parse_button.pack(side=tk.BOTTOM, fill='x')

        self.defang_button = tk.Button(self, text="Defang IOCs", command=self.defang_iocs)
        self.defang_button.pack(side=tk.RIGHT, fill='x')

        self.save_button = tk.Button(self, text="Save all IOCs", command=self.save_iocs)
        self.save_button.pack(side=tk.RIGHT, fill='x')

        self.save_folder_button = tk.Button(self, text="Save Individually", command=self.save_iocs_to_folder)
        self.save_folder_button.pack(side=tk.RIGHT, fill='x')
        
    def refang(self, value: str) -> str:
        # Refang the defanged IPs and URLs
        value = value.replace('[.]', '.')  # Refang IP
        value = value.replace('hxxp', 'http')
        value = value.replace('hxxps', 'https')  # Refang URL
        return value
    
    def defang(self, value: str) -> str:
        # Defang the IPs and URLs
        value = value.replace('.', '[.]')  # Defang IP
        value = value.replace('http', 'hxxp')
        value = value.replace('https', 'hxxps')  # Defang URL
        return value
        
    def is_filename(self, candidate: str) -> bool:
        return '.' in candidate and not re.match(regexes['domain'], candidate)
        
    def parse_iocs(self):
        self.article_input.tag_remove("highlight", "1.0", tk.END)
        article = self.article_input.get("1.0", tk.END)
        iocs = {key: set() for key in regexes.keys()}

        # Configure a tag for highlighting
        self.article_input.tag_configure("highlight", background="yellow")

        for key, regex in regexes.items():
            matches = regex.finditer(article)  # Use finditer to get match objects with start and end positions
            
            for match in matches:
                start_line = article.count('\n', 0, match.start()) + 1  # Calculate the line number of the start of the match
                start_column = match.start() - article.rfind('\n', 0, match.start()) - 1  # Calculate the column number of the start of the match
                end_line = article.count('\n', 0, match.end()) + 1  # Calculate the line number of the end of the match
                end_column = match.end() - article.rfind('\n', 0, match.end()) - 1  # Calculate the column number of the end of the match
                
                start_pos = f"{start_line}.{start_column}"  # Convert start position to Text widget index
                end_pos = f"{end_line}.{end_column}"  # Convert end position to Text widget index
                self.article_input.tag_add("highlight", start_pos, end_pos)  # Highlight the matched text
                
                iocs[key].add(self.refang(match.group()))  # Add the refanged match to the set of IOCs

        # Clear the review_output widget and update it with the extracted IOCs
        self.review_output.configure(state='normal')
        self.review_output.delete("1.0", tk.END)
        for key, values in iocs.items():
            if values:
                self.review_output.insert(tk.END, f"{key}:\n")
                for value in values:
                    self.review_output.insert(tk.END, f"  {value}\n")
                    
        self.review_output.configure(state='disabled') 

    def defang_iocs(self):
        # Get the content from the review_output widget
        self.review_output.configure(state='normal')
        content = self.review_output.get("1.0", tk.END)
        
        # Defang the content
        defanged_content = self.defang(content)
        
        # Clear the review_output widget and update it with the defanged IOCs
        self.review_output.delete("1.0", tk.END)
        self.review_output.insert(tk.END, defanged_content)
        self.review_output.configure(state='disabled')

    def save_iocs(self):
        # Get the content from the review_output widget
        content = self.review_output.get("1.0", tk.END)
        
        # Ask the user for a file location to save the IOCs
        file_path = tk.filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if not file_path:  # If the user cancels the file dialog
            return
        # Write the content to the file
        with open(file_path, 'w') as file:
            file.write(content.strip())  # strip() is used to remove the trailing newline character
        # Optionally, you can show a message box to inform the user that the file has been saved successfully
        tk.messagebox.showinfo("Success", f"IOCs have been saved to {os.path.basename(file_path)}")

    def save_iocs_to_folder(self):
    # Ask the user for a directory to save the IOCs
        folder_path = tk.filedialog.askdirectory(title="Select Directory to Save IOCs")
        if not folder_path:  # If the user cancels the directory dialog
            return
        
        # Prompt the user to enter a name for the new folder
        folder_name = tk.simpledialog.askstring("Input", "Enter the name for the new folder:")
        if not folder_name:  # If the user cancels the input dialog or enters an empty string
            return
        
        # Create the new folder within the selected directory
        new_folder_path = os.path.join(folder_path, folder_name)
        os.makedirs(new_folder_path, exist_ok=True)  # exist_ok=True will create the folder if it does not exist
        
        # Extract IOCs and save them to separate files within the new folder
        article = self.article_input.get("1.0", tk.END)
        iocs = {key: set() for key in regexes.keys()}
        
        for key, regex in regexes.items():
            matches = regex.finditer(article)
            iocs[key].update(self.refang(match.group()) for match in matches)
            
            # If there are any IOCs of this type, save them to a separate file within the new folder
            if iocs[key]:  # Changed from if matches: to if iocs[key]:
                file_path = os.path.join(new_folder_path, f"{key}.txt")
                with open(file_path, 'w') as file:
                    for value in iocs[key]:
                        file.write(f"{value}\n")
        
        # Optionally, you can show a message box to inform the user that the files have been saved successfully
        tk.messagebox.showinfo("Success", f"IOCs have been saved to {new_folder_path}")
        
        # Optionally, you can show a message box to inform the user that the files have been saved successfully
        tk.messagebox.showinfo("Success", f"IOCs have been saved to {new_folder_path}")

app = IOCExtractor()
app.mainloop()
