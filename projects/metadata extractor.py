from PIL import Image
from PIL.ExifTags import TAGS
from pypdf import PdfReader
from docx import Document
import mutagen
import argparse

def ex_image(image_path):
    try:
        image = Image.open(image_path)
        exif_data = image._getexif()

        if exif_data:
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                print(f"{tag}: {value}")
        else:
            print("No EXIF metadata found.")
    except FileNotFoundError:
        print(f"File not found: {image_path}")
    except Exception as e:
        print(f"Error reading image metadata: {e}")

def ex_pdf(pdf_path):
    try:
        reader = PdfReader(pdf_path)
        meta = reader.metadata

        if meta:
            author = meta.author
            title = meta.title
            creation_date = meta.creation_date
            producer = meta.producer

            print(f"Author: {author}")
            print(f"Title: {title}")
            print(f"Creation Date: {creation_date}")
            print(f"Producer: {producer}")
        else:
            print("No metadata found.")
    except FileNotFoundError:
        print(f"File not found: {pdf_path}")
    except Exception as e:
        print(f"Error reading PDF metadata: {e}")

def ex_docx(docx_path):
    try:
        doc = Document(docx_path)
        props = doc.core_properties
        metadata = {
        "author": props.author,
        "last_modified_by": props.last_modified_by,
        "revision": props.revision,
        "created": props.created,
        "modified": props.modified,
        "title": props.title,
        "subject": props.subject,
        "category": props.category,
        "comments": props.comments,
        }

        for key, value in metadata.items():
            print(f"{key}: {value}")
    except FileNotFoundError:
        print(f"File not found: {docx_path}")
    except Exception as e:
        print(f"Error reading DOCX metadata: {e}")

def ex_audio(audio_path):
    try:
        audio = mutagen.File(audio_path)
        if audio:
            for key, value in audio.items():
                print(f"{key}: {value}")
        else:
            print("No metadata found.")
    except FileNotFoundError:
        print(f"File not found: {audio_path}")
    except Exception as e:
        print(f"Error reading audio metadata: {e}")

parser = argparse.ArgumentParser(description="metadata extractor")
parser.add_argument("--file", default="C:/Users/PC/Downloads/malenames-usa-top1000.txt", help="Path to the file")
parser.add_argument("--type", required=True, help="Type of file (image, pdf, docx, audio)")
args = parser.parse_args()

if args.type == "image":
    ex_image(args.file) 
elif args.type == "pdf":
    ex_pdf(args.file)
elif args.type == "docx":
    ex_docx(args.file)
elif args.type == "audio":
    ex_audio(args.file)
else:
    print("Unsupported file type. Please use 'image', 'pdf', 'docx', or 'audio'.")