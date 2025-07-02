import fitz  # PyMuPDF

# Set paths
input_path = r"C:\Users\i7\Downloads\IELTS Writing Recap 2024.pdf"
output_path = r"C:\Users\i7\Downloads\IELTS_Writing_Recap_CLEANED.pdf"

# Target image size in pixels
target_width = 2481
target_height = 172

# Open the document
doc = fitz.open(input_path)

# Iterate over all pages
for page_num in range(len(doc)):
    page = doc[page_num]
    images = page.get_images(full=True)

    for img in images:
        xref = img[0]
        width = img[2]
        height = img[3]

        if width == target_width and height == target_height:
            print(f"Page {page_num + 1}: Deleting image {xref} with size {width}x{height}")
            # Prepare and delete image by xref
            page._wrap_contents()
            page.delete_image(xref)

# Save the result
doc.save(output_path)
doc.close()

print("✅ Done. Cleaned file saved as:")
print(output_path)
